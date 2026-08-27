import type { Hono } from "hono";
import { z } from "zod";
import { publicImageDetail, publicImages, publicOverview } from "./public-queries";
import type { WorkerEnv } from "./worker-env";

const listQuerySchema = z.object({
  q: z.string().trim().max(80).catch(""),
  limit: z.coerce.number().int().min(1).max(200).catch(50),
  offset: z.coerce.number().int().min(0).max(100_000).catch(0),
});
const refSchema = z.string().regex(/@sha256:[a-f0-9]{64}$/);

function json(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    headers: {
      "cache-control": "public, max-age=30",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

/* Unauthenticated read surface behind the same disclosure rules as the panel's public
   views. Deliberately outside `/v1/*`: that prefix authenticates every request, while
   these responses carry only disclosed data and are safe to cache at the edge. */
export function registerPublicRoutes(app: Hono<WorkerEnv>): void {
  app.get("/public/overview", async (context) => json(await publicOverview(context.env.DB)));

  app.get("/public/images", async (context) => {
    const query = listQuerySchema.parse(context.req.query());
    return json({
      images: await publicImages(context.env.DB, {
        search: query.q,
        limit: query.limit,
        offset: query.offset,
      }),
    });
  });

  app.get("/public/image", async (context) => {
    const reference = refSchema.parse(context.req.query("ref") ?? "");
    const detail = await publicImageDetail(context.env.DB, reference);
    return detail ? json(detail) : context.json({ error: "image not found" }, 404);
  });
}
