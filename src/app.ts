import { Hono } from "hono";
import { z } from "zod";
import { AuthenticationError, AuthorizationError, authenticate, requireCapability } from "./auth";
import { type Principal, SbomIdSchema, TenantIdSchema, vexInputSchema } from "./domain";
import { inventoryResponse } from "./inventory";
import { appendVex, listFindings, retireSbom } from "./repository";
import { handleGithubWebhook, WebhookError } from "./webhook";
import { runScheduled } from "./scheduled";

export type WorkerBindings = {
  readonly BUILD_SHA?: string;
  readonly DB: D1Database;
  readonly DISPATCH_ENABLED: string;
  readonly DESCOPE_AUDIENCE: string;
  readonly DESCOPE_BASE_URL?: string;
  readonly DESCOPE_PROJECT_ID: string;
  readonly GH_APP_ID: string;
  readonly GH_APP_INSTALLATION_ID: string;
  readonly GH_APP_PRIVATE_KEY: string;
  readonly GH_WEBHOOK_SECRET: string;
  readonly OSV_API_URL: string;
  readonly OSV_ADVISORY_JOBS: Queue;
  readonly OSV_BASE_URL: string;
  readonly EXECUTION_CONTEXT: ExecutionContext;
};

export const app = new Hono<{
  Bindings: WorkerBindings;
  Variables: { readonly principal: Principal };
}>();

app.get("/health", (context) => {
  if (context.env.BUILD_SHA) context.header("x-squawk-version", context.env.BUILD_SHA);
  return context.json({ status: "ok" });
});

app.get("/", (context) => inventoryResponse(context.req.raw, context.env.DB));

app.post("/webhooks/github", (context) => handleGithubWebhook(context.req.raw, context.env));

app.use("/v1/*", async (context, next) => {
  const principal = await authenticate(context.req.header("Authorization"), {
    projectId: context.env.DESCOPE_PROJECT_ID,
    audience: context.env.DESCOPE_AUDIENCE,
    ...(context.env.DESCOPE_BASE_URL ? { baseUrl: context.env.DESCOPE_BASE_URL } : {}),
  });
  context.set("principal", principal);
  await next();
});

function principalForOrg(principal: Principal, orgId: string): Principal {
  if (principal.tenantId !== TenantIdSchema.parse(orgId))
    throw new AuthorizationError("wrong tenant");
  return principal;
}

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
      include_suppressed: z.enum(["true", "false"]).optional(),
      include_retired: z.enum(["true", "false"]).optional(),
    })
    .parse(context.req.query());
  const findings = await listFindings(
    context.env.DB,
    principal.tenantId,
    query.severity ?? null,
    query.include_suppressed === "true",
    query.include_retired === "true",
  );
  return context.json({ findings });
});

app.onError((error, context) => {
  if (error instanceof AuthenticationError) return context.json({ error: "unauthorized" }, 401);
  if (error instanceof AuthorizationError) return context.json({ error: "forbidden" }, 403);
  if (error instanceof WebhookError) return context.json({ error: error.message }, error.status);
  if (error instanceof z.ZodError) {
    console.warn("Invalid request", { issues: error.issues });
    return context.json({ error: "invalid request" }, 400);
  }
  console.error("Unhandled request error", {
    name: error.name,
    message: error.message,
    stack: error.stack,
  });
  return context.json({ error: "internal error" }, 500);
});
