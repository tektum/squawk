import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

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
