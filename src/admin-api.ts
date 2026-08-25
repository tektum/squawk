import type { Hono } from "hono";
import { z } from "zod";
import { jobs, sources } from "./admin-pipeline";
import { imageDetail, images, overview } from "./admin-queries";
import { principalForOrg, requireCapability } from "./auth";
import { capabilityValues, SbomIdSchema } from "./domain";
import type { WorkerEnv } from "./worker-env";

const statusSchema = z
  .string()
  .regex(/^[a-z_]{1,20}$/)
  .optional();
const listQuerySchema = z.object({
  status: statusSchema,
  q: z.string().trim().max(80).optional(),
  include_retired: z.enum(["true", "false"]).optional(),
  limit: z.coerce.number().int().min(1).max(200).catch(50),
  offset: z.coerce.number().int().min(0).max(100_000).catch(0),
});

/* Read surface for the admin panel. Reads carry `pipeline.read` so an operator can be
   granted diagnosis without the write capabilities; every tenant-addressed route runs
   `principalForOrg` first, so a token for one tenant cannot read another's rows. */
export function registerAdminRoutes(app: Hono<WorkerEnv>): void {
  app.get("/v1/me", (context) => {
    const principal = context.get("principal");
    return context.json({
      tenant_id: principal.tenantId,
      user_id: principal.userId ?? null,
      capabilities: capabilityValues.filter((capability) => principal.capabilities.has(capability)),
    });
  });

  app.get("/v1/orgs/:id/overview", async (context) => {
    const principal = principalForOrg(context.get("principal"), context.req.param("id"));
    requireCapability(principal, "pipeline.read");
    return context.json(await overview(context.env.DB, principal.tenantId));
  });

  app.get("/v1/orgs/:id/images", async (context) => {
    const principal = principalForOrg(context.get("principal"), context.req.param("id"));
    requireCapability(principal, "pipeline.read");
    const query = listQuerySchema.parse(context.req.query());
    return context.json({
      images: await images(context.env.DB, principal.tenantId, {
        status: query.status ?? null,
        search: query.q ?? "",
        includeRetired: query.include_retired === "true",
        limit: query.limit,
        offset: query.offset,
      }),
    });
  });

  app.get("/v1/orgs/:id/images/:sbomId", async (context) => {
    const principal = principalForOrg(context.get("principal"), context.req.param("id"));
    requireCapability(principal, "pipeline.read");
    const detail = await imageDetail(
      context.env.DB,
      principal.tenantId,
      SbomIdSchema.parse(context.req.param("sbomId")),
    );
    return detail ? context.json(detail) : context.json({ error: "SBOM not found" }, 404);
  });

  app.get("/v1/orgs/:id/jobs", async (context) => {
    const principal = principalForOrg(context.get("principal"), context.req.param("id"));
    requireCapability(principal, "pipeline.read");
    const query = listQuerySchema.parse(context.req.query());
    return context.json(
      await jobs(context.env.DB, principal.tenantId, {
        status: query.status ?? null,
        limit: query.limit,
      }),
    );
  });

  app.get("/v1/orgs/:id/sources", async (context) => {
    const principal = principalForOrg(context.get("principal"), context.req.param("id"));
    requireCapability(principal, "pipeline.read");
    return context.json({ sources: await sources(context.env.DB, principal.tenantId) });
  });
}
