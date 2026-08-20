import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { assertSuccessfulExit } from "../../scripts/reconcile-tenant";

describe("D1 migration contract", () => {
  it("enforces relational, identity, and status invariants", async () => {
    const tables = await env.DB.prepare("SELECT name FROM sqlite_schema WHERE type='table'").all<{
      readonly name: string;
    }>();
    for (const name of [
      "orgs",
      "sboms",
      "components",
      "vulnerabilities",
      "findings",
      "vex_statements",
      "sync_cursors",
      "osv_ecosystems",
      "osv_advisory_jobs",
      "matching_errors",
      "dispatch_deliveries",
      "github_sources",
      "github_deliveries",
      "public_activity",
    ]) {
      expect(tables.results.some((table) => table.name === name)).toBe(true);
    }
    const columns = await env.DB.prepare("PRAGMA table_info(orgs)").all<{
      readonly name: string;
    }>();
    expect(
      columns.results
        .map((column) => column.name)
        .some((name) => /name|email|secret|key/i.test(name)),
    ).toBe(false);
    const activityColumns = await env.DB.prepare("PRAGMA table_info(public_activity)").all<{
      readonly name: string;
    }>();
    expect(activityColumns.results.map((column) => column.name)).toEqual([
      "event_sha256",
      "kind",
      "outcome",
      "occurred_at",
    ]);
    expect(
      activityColumns.results
        .map((column) => column.name)
        .some((name) => /name|email|secret|key|payload|request|response|error/i.test(name)),
    ).toBe(false);
    await expect(
      env.DB.prepare(
        "INSERT INTO components (sbom_id,package_name,ecosystem,version,purl,matchable) VALUES ('missing','x','npm','1','pkg:npm/x@1',1)",
      ).run(),
    ).rejects.toThrow();
    await env.DB.prepare(
      "INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)",
    ).run();
    await expect(
      env.DB.prepare(
        "INSERT INTO vex_statements (org_id,package_name,ecosystem,vuln_id,status,created_by_descope_user_id,created_at) VALUES ('tenant','x','npm','OSV','invalid','user',0)",
      ).run(),
    ).rejects.toThrow();
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('sbom','tenant','image','logical','linux/amd64','digest','complete',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'sbom','demo','npm','1','pkg:npm/demo@1',1)",
      ),
      env.DB.prepare(
        "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (1,'OSV-1','first',0)",
      ),
    ]);
    await expect(
      env.DB.prepare(
        "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (1,'OSV-1','second',1)",
      ).run(),
    ).rejects.toThrow();
    const foreignKeys = await env.DB.prepare("PRAGMA foreign_key_list(components)").all();
    expect(foreignKeys.results.length).toBeGreaterThan(0);
  });
});

it("can migrate all tenant-owned rows to the real Descope tenant", async () => {
  await env.DB.batch([
    env.DB.prepare("INSERT INTO orgs VALUES ('stale','app','owner/repo','monitor.yaml',0)"),
    env.DB.prepare("INSERT INTO github_sources VALUES ('1','2','stale','registry_package','',0)"),
    env.DB.prepare(
      "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('sbom','stale','image','logical','linux/amd64','digest','complete',0)",
    ),
  ]);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO orgs SELECT 'real',descope_inbound_app_id,github_dispatch_repo,github_dispatch_workflow,created_at FROM orgs ORDER BY created_at LIMIT 1",
    ),
    env.DB.prepare("UPDATE github_sources SET org_id='real' WHERE org_id!='real'"),
    env.DB.prepare("UPDATE sboms SET org_id='real' WHERE org_id!='real'"),
  ]);
  await env.DB.prepare("DELETE FROM orgs WHERE descope_tenant_id!='real'").run();

  await expect(env.DB.prepare("SELECT org_id FROM github_sources").first("org_id")).resolves.toBe(
    "real",
  );
  await expect(env.DB.prepare("SELECT org_id FROM sboms").first("org_id")).resolves.toBe("real");
});

it("detects collisions between non-target tenant SBOM identities", async () => {
  await env.DB.batch([
    env.DB.prepare("INSERT INTO orgs VALUES ('stale-a','app','owner/repo','monitor.yaml',0)"),
    env.DB.prepare("INSERT INTO orgs VALUES ('stale-b','app','owner/repo','monitor.yaml',0)"),
    env.DB.prepare("INSERT INTO orgs VALUES ('real','app','owner/repo','monitor.yaml',0)"),
    env.DB.prepare(
      "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('stale-a-sbom','stale-a','image','logical','linux/amd64','digest-a','complete',0)",
    ),
    env.DB.prepare(
      "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('stale-b-sbom','stale-b','image','logical','linux/amd64','digest-b','complete',0)",
    ),
  ]);

  await expect(
    env.DB.prepare(
      "SELECT COUNT(*) AS collision_count FROM (SELECT image_ref,platform FROM sboms GROUP BY image_ref,platform HAVING COUNT(*)>1)",
    ).first<number>("collision_count"),
  ).resolves.toBe(1);
});

it("reports a failed Wrangler reconciliation subprocess", () => {
  expect(() => assertSuccessfulExit(1)).toThrow("wrangler exited with status 1");
  expect(() => assertSuccessfulExit(0)).not.toThrow();
});
