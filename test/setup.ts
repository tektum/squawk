import { applyD1Migrations, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, beforeEach } from "vitest";
import { server } from "./server";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

beforeEach(async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM public_activity"),
    env.DB.prepare("DELETE FROM github_ingestion_jobs"),
    env.DB.prepare("DELETE FROM osv_advisory_jobs"),
    env.DB.prepare("DELETE FROM matching_errors"),
    env.DB.prepare("DELETE FROM findings"),
    env.DB.prepare("DELETE FROM vex_statements"),
    env.DB.prepare("DELETE FROM dispatch_deliveries"),
    env.DB.prepare("DELETE FROM github_deliveries"),
    env.DB.prepare("DELETE FROM components"),
    env.DB.prepare("DELETE FROM vulnerabilities"),
    env.DB.prepare("DELETE FROM sboms"),
    env.DB.prepare("DELETE FROM sync_cursors"),
    env.DB.prepare("DELETE FROM osv_ecosystems"),
    env.DB.prepare("DELETE FROM github_sources"),
    env.DB.prepare("DELETE FROM orgs"),
  ]);
});
