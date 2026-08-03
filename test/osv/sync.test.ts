import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { SubrequestBudget } from "../../src/budget";
import { syncEcosystem } from "../../src/sync";
import { respond } from "../http";

const relevant = (id: string) => ({
  id,
  modified: "2026-01-02T00:00:00Z",
  affected: [
    {
      package: { ecosystem: "npm", name: "demo" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
      versions: [],
    },
  ],
});

describe("incremental OSV synchronization", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('sbom','tenant',?,?, 'linux/amd64',?,'complete',0)",
      ).bind(
        `ghcr.io/x@sha256:${"a".repeat(64)}`,
        `ghcr.io/x@sha256:${"b".repeat(64)}`,
        "c".repeat(64),
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'sbom','demo','npm','1.5.0','pkg:npm/demo@1.5.0',1)",
      ),
      env.DB.prepare(
        "INSERT INTO sync_cursors (ecosystem,last_synced_at,boundary_ids) VALUES ('npm','2026-01-01T00:00:00Z','')",
      ),
    ]);
  });

  it("resumes equal-timestamp work without skipping records", async () => {
    const csv =
      "modified,id\n2026-01-01T01:00:00Z,OSV-1\n2026-01-02T00:00:00Z,OSV-2\n2026-01-02T00:00:00Z,OSV-3\n";
    respond({ url: "https://osv.test/npm/modified_id.csv", status: 200, text: csv });
    respond({ url: "https://osv.test/npm/OSV-1.json", status: 200, body: relevant("OSV-1") });
    respond({
      url: "https://osv.test/npm/OSV-2.json",
      status: 200,
      body: {
        id: "OSV-2",
        modified: "2026-01-02T00:00:00Z",
        affected: [{ package: { ecosystem: "npm", name: "absent" }, ranges: [], versions: [] }],
      },
    });
    expect(
      await syncEcosystem({
        database: env.DB,
        ecosystem: "npm",
        osvBaseUrl: "https://osv.test",
        budget: new SubrequestBudget(3),
        now: 1,
      }),
    ).toBe(2);
    expect(
      await env.DB.prepare("SELECT COUNT(*) AS count FROM findings").first<number>("count"),
    ).toBe(1);

    respond({ url: "https://osv.test/npm/modified_id.csv", status: 200, text: csv });
    respond({ url: "https://osv.test/npm/OSV-3.json", status: 200, body: relevant("OSV-3") });
    expect(
      await syncEcosystem({
        database: env.DB,
        ecosystem: "npm",
        osvBaseUrl: "https://osv.test",
        budget: new SubrequestBudget(3),
        now: 2,
      }),
    ).toBe(1);
    expect(
      await env.DB.prepare("SELECT COUNT(*) AS count FROM findings").first<number>("count"),
    ).toBe(2);
  });
});
