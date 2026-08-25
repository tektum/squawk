import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { SbomIdSchema, TenantIdSchema, UserIdSchema } from "../../src/domain";
import { appendVex, listFindings, retireSbom } from "../../src/repository";

describe("retirement and append-only VEX", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('00000000-0000-4000-8000-000000000001','tenant',?,?, 'linux/amd64',?,'complete',0)",
      ).bind(
        `ghcr.io/x@sha256:${"a".repeat(64)}`,
        `ghcr.io/x@sha256:${"b".repeat(64)}`,
        "c".repeat(64),
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'00000000-0000-4000-8000-000000000001','demo','npm','1','pkg:npm/demo@1',1)",
      ),
      env.DB.prepare(
        "INSERT INTO vulnerabilities VALUES ('OSV-1','npm','demo','{}','high','summary','2026-01-01T00:00:00Z')",
      ),
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',1,'OSV-1',0,NULL)"),
    ]);
  });

  it("uses the latest VEX statement and preserves retired history", async () => {
    const tenant = TenantIdSchema.parse("tenant");
    const user = UserIdSchema.parse("user");
    await appendVex(env.DB, tenant, user, {
      packageName: "demo",
      ecosystem: "npm",
      vulnId: "OSV-1",
      status: "not_affected",
    });
    expect(
      await listFindings(env.DB, tenant, {
        severity: null,
        includeSuppressed: false,
        includeRetired: false,
      }),
    ).toHaveLength(0);
    await appendVex(env.DB, tenant, user, {
      packageName: "demo",
      ecosystem: "npm",
      vulnId: "OSV-1",
      status: "affected",
    });
    expect(
      await listFindings(env.DB, tenant, {
        severity: null,
        includeSuppressed: false,
        includeRetired: false,
      }),
    ).toHaveLength(1);
    const id = SbomIdSchema.parse("00000000-0000-4000-8000-000000000001");
    expect(await retireSbom(env.DB, tenant, id)).toBe(true);
    expect(await retireSbom(env.DB, tenant, id)).toBe(true);
    expect(
      await listFindings(env.DB, tenant, {
        severity: null,
        includeSuppressed: false,
        includeRetired: false,
      }),
    ).toHaveLength(0);
    expect(
      await listFindings(env.DB, tenant, {
        severity: null,
        includeSuppressed: false,
        includeRetired: true,
      }),
    ).toHaveLength(1);
    expect(
      await env.DB.prepare("SELECT COUNT(*) AS count FROM vex_statements").first<number>("count"),
    ).toBe(2);
  });
});
