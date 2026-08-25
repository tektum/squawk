import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import type { AdvisoryMessage } from "../../src/advisory";
import { discoverAdvisories } from "../../src/sync";
import { respond } from "../http";

describe("incremental OSV synchronization", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
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

  it("discovers equal-timestamp work without skipping records", async () => {
    const csv =
      "modified,id\n2026-01-01T01:00:00Z,OSV-1\n2026-01-02T00:00:00Z,OSV-2\n2026-01-02T00:00:00Z,OSV-3\n";
    respond({ url: "https://osv.test/npm/modified_id.csv", status: 200, text: csv });
    const messages: AdvisoryMessage[] = [];

    await expect(
      discoverAdvisories({
        database: env.DB,
        ecosystem: "npm",
        osvBaseUrl: "https://osv.test",
        queue: {
          sendBatch: async (batch) => {
            for (const item of batch) messages.push(item.body);
          },
        },
      }),
    ).resolves.toBe(3);

    expect(messages).toHaveLength(3);
    await expect(
      env.DB.prepare("SELECT boundary_ids FROM sync_cursors WHERE ecosystem='npm'").first(
        "boundary_ids",
      ),
    ).resolves.toBe("OSV-2,OSV-3");
  });
});
