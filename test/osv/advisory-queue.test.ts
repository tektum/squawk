import { createExecutionContext, createMessageBatch, env, getQueueResult } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { SubrequestBudget } from "../../src/budget";
import { type AdvisoryJob, discoverAdvisories } from "../../src/sync";
import { respond } from "../http";

const message = {
  advisoryId: "OSV-1",
  ecosystem: "npm",
  modifiedAt: "2026-01-02T00:00:00Z",
} satisfies AdvisoryJob;

function queueMessage(body: AdvisoryJob) {
  return { attempts: 1, body, id: crypto.randomUUID(), timestamp: new Date() };
}

describe("OSV advisory queue", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('sbom','tenant','image','logical','linux/amd64','digest','complete',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'sbom','demo','npm','1.5.0','pkg:npm/demo@1.5.0',1)",
      ),
      env.DB.prepare(
        "INSERT INTO sync_cursors (ecosystem,last_synced_at,boundary_ids) VALUES ('npm','2026-01-01T00:00:00Z','')",
      ),
    ]);
  });

  it("discovers every unseen advisory and advances after durable enqueue", async () => {
    const rows = Array.from(
      { length: 205 },
      (_, index) => `2026-01-02T00:00:00Z,OSV-${String(index).padStart(3, "0")}`,
    );
    respond({
      url: "https://osv.test/npm/modified_id.csv",
      status: 200,
      text: `modified,id\n${rows.join("\n")}\n`,
    });
    const batches: AdvisoryJob[][] = [];

    await expect(
      discoverAdvisories({
        database: env.DB,
        ecosystem: "npm",
        osvBaseUrl: "https://osv.test",
        budget: new SubrequestBudget(3),
        queue: {
          sendBatch: async (batch) => {
            batches.push(Array.from(batch, (item) => item.body));
          },
        },
      }),
    ).resolves.toBe(205);

    expect(batches.map((batch) => batch.length)).toEqual([100, 100, 5]);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM osv_advisory_jobs").first("COUNT(*)"),
    ).resolves.toBe(205);
    await expect(
      env.DB.prepare("SELECT last_synced_at FROM sync_cursors WHERE ecosystem='npm'").first(
        "last_synced_at",
      ),
    ).resolves.toBe("2026-01-02T00:00:00Z");
  });

  it("acknowledges an idempotent successful advisory", async () => {
    await env.DB.prepare(
      "INSERT INTO osv_advisory_jobs VALUES ('npm','OSV-1','2026-01-02T00:00:00Z','pending',NULL,NULL)",
    ).run();
    respond({
      url: "https://osv.test/npm/OSV-1.json",
      status: 200,
      body: {
        id: "OSV-1",
        modified: message.modifiedAt,
        affected: [
          {
            package: { ecosystem: "npm", name: "demo" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "1" }, { fixed: "2" }] }],
            versions: [],
          },
        ],
      },
    });
    const batch = createMessageBatch("squawk-osv-advisories", [queueMessage(message)]);
    const context = createExecutionContext();

    await worker.queue(batch, { ...env, OSV_BASE_URL: "https://osv.test" } as never);
    const result = await getQueueResult(batch, context);
    expect(result.ackAll).toBe(false);
    expect(result.explicitAcks).toHaveLength(1);
    await expect(
      env.DB.prepare("SELECT status FROM osv_advisory_jobs").first("status"),
    ).resolves.toBe("complete");
    await expect(env.DB.prepare("SELECT COUNT(*) FROM findings").first("COUNT(*)")).resolves.toBe(
      1,
    );
  });

  it("retries a transient advisory failure", async () => {
    await env.DB.prepare(
      "INSERT INTO osv_advisory_jobs VALUES ('npm','OSV-1','2026-01-02T00:00:00Z','pending',NULL,NULL)",
    ).run();
    respond({ url: "https://osv.test/npm/OSV-1.json", status: 503 });
    const batch = createMessageBatch("squawk-osv-advisories", [queueMessage(message)]);
    const context = createExecutionContext();

    await worker.queue(batch, { ...env, OSV_BASE_URL: "https://osv.test" } as never);
    const result = await getQueueResult(batch, context);
    expect(result.retryMessages).toHaveLength(1);
    await expect(
      env.DB.prepare("SELECT status FROM osv_advisory_jobs").first("status"),
    ).resolves.toBe("failed");
  });
});
