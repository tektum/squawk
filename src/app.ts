import { Hono } from "hono";
import { z } from "zod";
import { activityResponse, recordActivity } from "./activity";
import { registerAdminRoutes } from "./admin-api";
import { adminClientResponse, adminShellResponse } from "./admin-shell";
import {
  AuthenticationError,
  AuthorizationError,
  authenticate,
  principalForOrg,
  requireCapability,
} from "./auth";
import { SbomIdSchema, vexInputSchema } from "./domain";
import { safeIssues } from "./error-detail";
import { inventoryResponse } from "./inventory";
import { appendVex, listFindings, retireSbom } from "./repository";
import { PredicateError } from "./sbom";
import { runScheduled } from "./scheduled";
import { handleGithubWebhook, WebhookError } from "./webhook";
import type { WorkerEnv } from "./worker-env";

export type { WorkerBindings } from "./worker-env";

export const app = new Hono<WorkerEnv>();

app.get("/health", (context) => {
  if (context.env.BUILD_SHA) context.header("x-squawk-version", context.env.BUILD_SHA);
  return context.json({ status: "ok" });
});

app.get("/admin", (context) =>
  adminShellResponse(context.env.DESCOPE_PROJECT_ID, context.env.DESCOPE_BASE_URL),
);

app.get("/admin/app.js", (context) => adminClientResponse(context.req.raw));

app.get("/", (context) => inventoryResponse(context.req.raw, context.env.DB));

app.get("/activity", (context) => activityResponse(context.env.DB));

app.post("/webhooks/github", async (context) => {
  try {
    const response = await handleGithubWebhook(context.req.raw, context.env);
    const outcome =
      response.status === 204
        ? "ignored"
        : response.status === 200
          ? "accepted"
          : ((await response.clone().json<{ status?: string }>()).status ?? "pending") ===
              "accepted"
            ? "accepted"
            : "pending";
    await recordActivity(context.env.DB, "webhook", outcome);
    return response;
  } catch (error) {
    await recordActivity(context.env.DB, "webhook", "failed");
    throw error;
  }
});

app.use("/v1/*", async (context, next) => {
  const principal = await authenticate(context.req.header("Authorization"), {
    projectId: context.env.DESCOPE_PROJECT_ID,
    ...(context.env.DESCOPE_BASE_URL ? { baseUrl: context.env.DESCOPE_BASE_URL } : {}),
  });
  context.set("principal", principal);
  await next();
});

registerAdminRoutes(app);

app.post("/v1/operations/scheduled", async (context) => {
  const principal = context.get("principal");
  requireCapability(principal, "operations.run");
  if (!principal.userId) throw new AuthorizationError("human identity required");
  await runScheduled(context.env);
  return context.body(null, 204);
});

app.delete("/v1/sboms/:id", async (context) => {
  const principal = context.get("principal");
  requireCapability(principal, "sbom.manage");
  if (!principal.userId) throw new AuthorizationError("human identity required");
  const retired = await retireSbom(
    context.env.DB,
    principal.tenantId,
    SbomIdSchema.parse(context.req.param("id")),
  );
  return retired ? context.body(null, 204) : context.json({ error: "SBOM not found" }, 404);
});

app.post("/v1/orgs/:id/vex", async (context) => {
  const principal = principalForOrg(context.get("principal"), context.req.param("id"));
  requireCapability(principal, "vex.write");
  if (!principal.userId) throw new AuthorizationError("human identity required");
  const input = vexInputSchema.parse(await context.req.json());
  await appendVex(context.env.DB, principal.tenantId, principal.userId, {
    packageName: input.package_name,
    ecosystem: input.ecosystem,
    vulnId: input.vuln_id,
    status: input.status,
    ...(input.justification ? { justification: input.justification } : {}),
  });
  return context.body(null, 204);
});

app.get("/v1/orgs/:id/findings", async (context) => {
  const principal = principalForOrg(context.get("principal"), context.req.param("id"));
  requireCapability(principal, "findings.read");
  const query = z
    .object({
      severity: z.string().min(1).optional(),
      image: z.string().min(1).max(200).optional(),
      include_suppressed: z.enum(["true", "false"]).optional(),
      include_retired: z.enum(["true", "false"]).optional(),
      limit: z.coerce.number().int().min(1).max(1000).catch(1000),
      offset: z.coerce.number().int().min(0).max(100_000).catch(0),
    })
    .parse(context.req.query());
  const findings = await listFindings(context.env.DB, principal.tenantId, {
    severity: query.severity ?? null,
    includeSuppressed: query.include_suppressed === "true",
    includeRetired: query.include_retired === "true",
    ...(query.image ? { image: query.image } : {}),
    limit: query.limit,
    offset: query.offset,
  });
  return context.json({ findings });
});

app.onError((error, context) => {
  if (error instanceof AuthenticationError) return context.json({ error: "unauthorized" }, 401);
  if (error instanceof AuthorizationError) return context.json({ error: "forbidden" }, 403);
  if (error instanceof WebhookError) return context.json({ error: error.message }, error.status);
  if (error instanceof PredicateError) {
    console.warn("Invalid SBOM predicate", { message: error.message });
    return context.json({ error: "invalid request" }, 400);
  }
  if (error instanceof z.ZodError) {
    console.warn("Invalid request", { issues: safeIssues(error.issues) });
    return context.json({ error: "invalid request" }, 400);
  }
  console.error("Unhandled request error", {
    name: error.name,
    message: error.message,
    stack: error.stack,
  });
  return context.json({ error: "internal error" }, 500);
});
