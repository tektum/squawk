import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { TenantIdSchema } from "../../src/domain";
import { listFindings } from "../../src/repository";

describe("indexed findings query", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('active','tenant',? ,?,'linux/amd64',?,'complete',0)",
      ).bind(
        `ghcr.io/x@sha256:${"a".repeat(64)}`,
        `ghcr.io/x@sha256:${"b".repeat(64)}`,
        "c".repeat(64),
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at,retired_at) VALUES ('retired','tenant',? ,?,'linux/arm64',?,'complete',0,1)",
      ).bind(
        `ghcr.io/x@sha256:${"d".repeat(64)}`,
        `ghcr.io/x@sha256:${"b".repeat(64)}`,
        "e".repeat(64),
      ),
    ]);
    const statements: D1PreparedStatement[] = [];
    for (let index = 0; index < 200; index += 1) {
      const packageName = `package-${index}`;
      statements.push(
        env.DB.prepare(
          "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (?,?,?,?,?,?,1)",
        ).bind(
          index + 1,
          index < 100 ? "active" : "retired",
          packageName,
          "npm",
          "1.0.0",
          `pkg:npm/${packageName}@1.0.0`,
        ),
        env.DB.prepare(
          "INSERT INTO vulnerabilities VALUES (?,?,?,'{}','high','summary','2026-01-01T00:00:00Z')",
        ).bind(`OSV-${index}`, "npm", packageName),
        env.DB.prepare("INSERT INTO findings VALUES ('tenant',?,?,0,NULL)").bind(
          index + 1,
          `OSV-${index}`,
        ),
      );
    }
    for (let offset = 0; offset < statements.length; offset += 50)
      await env.DB.batch(statements.slice(offset, offset + 50));
    await env.DB.prepare(
      "INSERT INTO vex_statements (org_id,package_name,ecosystem,vuln_id,status,created_by_descope_user_id,created_at) VALUES ('tenant','package-0','npm','OSV-0','not_affected','user',1)",
    ).run();
  });

  it("applies suppression and retirement switches within the p95 target", async () => {
    const tenant = TenantIdSchema.parse("tenant");
    expect(await listFindings(env.DB, tenant, null, false, false)).toHaveLength(99);
    expect(await listFindings(env.DB, tenant, null, true, true)).toHaveLength(200);
    expect(await listFindings(env.DB, tenant, "critical", true, true)).toHaveLength(0);
    const timings: number[] = [];
    for (let index = 0; index < 30; index += 1) {
      const started = performance.now();
      await listFindings(env.DB, tenant, null, false, false);
      timings.push(performance.now() - started);
    }
    timings.sort((left, right) => left - right);
    expect(timings[Math.floor(timings.length * 0.95)]).toBeLessThan(300);
    const plan = await env.DB.prepare(
      "EXPLAIN QUERY PLAN SELECT * FROM findings WHERE org_id=? AND dispatched_at IS NULL",
    )
      .bind(tenant)
      .all<{ readonly detail: string }>();
    expect(plan.results.some(({ detail }) => detail.includes("idx_findings_org_current"))).toBe(
      true,
    );
  });
});
