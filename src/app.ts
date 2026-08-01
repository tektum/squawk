import { Hono } from "hono";
import { errors as joseErrors } from "jose";
import { z } from "zod";
import { authenticate, AuthenticationError, AuthorizationError, requireCapability } from "./auth";
import { backfillSbom } from "./backfill";
import { SbomIdSchema, TenantIdSchema, vexInputSchema, type Principal } from "./domain";
import { appendVex, ingestSbom, listFindings, retireSbom } from "./repository";
import { parsePredicate, sbomInputSchema } from "./sbom";

export type WorkerBindings = {
  readonly DB: D1Database;
  readonly DISPATCH_ENABLED: string;
  readonly DESCOPE_AUDIENCE: string;
  readonly DESCOPE_DISCOVERY_URL: string;
  readonly DESCOPE_ISSUER: string;
  readonly OSV_BASE_URL: string;
  readonly EXECUTION_CONTEXT: ExecutionContext;
};

export const app = new Hono<{
  Bindings: WorkerBindings;
  Variables: { readonly principal: Principal };
}>();

app.get("/health", (context) => context.json({ status: "ok" }));

app.use("/v1/*", async (context, next) => {
  const principal = await authenticate(context.req.header("Authorization"), {
    issuer: context.env.DESCOPE_ISSUER,
    audience: context.env.DESCOPE_AUDIENCE,
    discoveryUrl: context.env.DESCOPE_DISCOVERY_URL,
  });
  context.set("principal", principal);
  await next();
});

function principalForOrg(principal: Principal, orgId: string): Principal {
  if (principal.tenantId !== TenantIdSchema.parse(orgId))
    throw new AuthorizationError("wrong tenant");
  return principal;
}

async function predicateHash(predicate: unknown): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(predicate)),
  );
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join(
    "",
  );
}

app.post("/v1/sboms", async (context) => {
  const principal = context.get("principal");
  requireCapability(principal, "sbom.write");
  const input = sbomInputSchema.parse(await context.req.json());
  const components = parsePredicate(input.predicate);
  const hash = await predicateHash(input.predicate);
  if (input.idempotency_key !== hash)
    throw new z.ZodError([
      { code: "custom", path: ["idempotency_key"], message: "must equal predicate SHA-256" },
    ]);
  const result = await ingestSbom(
    context.env.DB,
    principal.tenantId,
    input,
    input.idempotency_key,
    components,
  );
  if (result.kind === "conflict")
    return context.json({ error: "conflicting platform submission" }, 409);
  if (result.kind === "created")
    context.env.EXECUTION_CONTEXT.waitUntil(
      backfillSbom({
        database: context.env.DB,
        sbomId: result.sbomId,
        osvBaseUrl: context.env.OSV_BASE_URL,
      }),
    );
  return context.json(
    { sbom_id: result.sbomId, status: result.kind === "created" ? "pending" : "complete" },
    result.kind === "created" ? 202 : 200,
  );
});

app.delete("/v1/sboms/:id", async (context) => {
  const principal = context.get("principal");
  requireCapability(principal, "sbom.write");
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
  if (error instanceof joseErrors.JOSEError) return context.json({ error: "unauthorized" }, 401);
  if (error instanceof AuthorizationError) return context.json({ error: "forbidden" }, 403);
  if (error instanceof z.ZodError) return context.json({ error: "invalid request" }, 400);
  return context.json({ error: "internal error" }, 500);
});
