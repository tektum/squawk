import { createExecutionContext, createMessageBatch, env, getQueueResult } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { sha256 } from "../../src/digest";
import { discoverAdvisories, requeueAdvisoryJobs } from "../../src/sync";
import { respond } from "../http";

const modifiedAt = "2026-01-02T00:00:00Z";
const jobId = () => sha256(["npm", "OSV-1", modifiedAt].join("\u0000"));
const queueMessage = (id: string) => ({
  attempts: 1,
  body: { jobId: id },
  id: crypto.randomUUID(),
  timestamp: new Date(),
});

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

  it("checkpoints bounded digest batches and normalizes CRLF", async () => {
    const rows = Array.from(
      { length: 205 },
      (_, index) => `${modifiedAt},OSV-${String(index).padStart(3, "0")}\r`,
    );
    respond({
      url: "https://osv.test/npm/modified_id.csv",
      status: 200,
      text: `modified,id\r\n${rows.join("\n")}\n`,
    });
    const batches: { jobId: string }[][] = [];

    await expect(
      discoverAdvisories({
        database: env.DB,
        ecosystem: "npm",
        osvBaseUrl: "https://osv.test",
        maxChunks: 2,
        queue: { sendBatch: async (batch) => batches.push(Array.from(batch, (item) => item.body)) },
      }),
    ).resolves.toBe(200);

    expect(batches.map((batch) => batch.length)).toEqual([100, 100]);
    expect(Object.keys(batches[0]?.[0] ?? {})).toEqual(["jobId"]);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM osv_advisory_jobs").first("COUNT(*)"),
    ).resolves.toBe(200);
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) FROM osv_advisory_jobs WHERE instr(advisory_id, char(13))>0",
      ).first("COUNT(*)"),
    ).resolves.toBe(0);
    await expect(
      env.DB.prepare("SELECT continuation_id FROM sync_cursors WHERE ecosystem='npm'").first(
        "continuation_id",
      ),
    ).resolves.toBe("OSV-199");
  });

  it("leaves the cursor at the last successfully enqueued chunk", async () => {
    const rows = Array.from(
      { length: 205 },
      (_, index) => `${modifiedAt},OSV-${String(index).padStart(3, "0")}`,
    );
    respond({
      url: "https://osv.test/npm/modified_id.csv",
      status: 200,
      text: `modified,id\n${rows.join("\n")}\n`,
    });
    let calls = 0;
    await expect(
      discoverAdvisories({
        database: env.DB,
        ecosystem: "npm",
        osvBaseUrl: "https://osv.test",
        queue: {
          sendBatch: async () => {
            calls += 1;
            if (calls === 2) throw new Error("injected queue failure");
          },
        },
      }),
    ).rejects.toThrow("injected queue failure");
    await expect(
      env.DB.prepare("SELECT continuation_id FROM sync_cursors WHERE ecosystem='npm'").first(
        "continuation_id",
      ),
    ).resolves.toBe("OSV-099");
  });

  it("acknowledges an idempotent successful advisory", async () => {
    const id = await jobId();
    await insertJob(id, "pending", null);
    advisoryResponse(200);
    const batch = createMessageBatch("squawk-osv-advisories", [queueMessage(id)]);
    const context = createExecutionContext();

    await worker.queue(batch, { ...env, OSV_BASE_URL: "https://osv.test" } as never, context);
    const result = await getQueueResult(batch, context);
    expect(result.explicitAcks).toHaveLength(1);
    await expect(
      env.DB.prepare("SELECT status FROM osv_advisory_jobs").first("status"),
    ).resolves.toBe("complete");
    await expect(env.DB.prepare("SELECT COUNT(*) FROM findings").first("COUNT(*)")).resolves.toBe(
      1,
    );
  });

  it("retries a transient failure and requeues stale work", async () => {
    const id = await jobId();
    await insertJob(id, "pending", null);
    advisoryResponse(503);
    const batch = createMessageBatch("squawk-osv-advisories", [queueMessage(id)]);
    const context = createExecutionContext();
    await worker.queue(batch, { ...env, OSV_BASE_URL: "https://osv.test" } as never, context);
    expect((await getQueueResult(batch, context)).retryMessages).toHaveLength(1);
    const sent: { jobId: string }[] = [];
    await requeueAdvisoryJobs({
      database: env.DB,
      now: 2_000_000,
      queue: {
        sendBatch: async (messages) => {
          sent.push(...Array.from(messages, (item) => item.body));
        },
      },
    });
    expect(sent).toEqual([{ jobId: id }]);
  });

  async function insertJob(id: string, status: string, attemptedAt: number | null) {
    await env.DB.prepare("INSERT INTO osv_advisory_jobs VALUES (?,'npm','OSV-1',?,?,?,NULL)")
      .bind(id, modifiedAt, status, attemptedAt)
      .run();
  }

  function advisoryResponse(status: number) {
    respond({
      url: "https://osv.test/npm/OSV-1.json",
      status,
      ...(status === 200
        ? {
            body: {
              id: "OSV-1",
              modified: modifiedAt,
              affected: [
                {
                  package: { ecosystem: "npm", name: "demo" },
                  ranges: [{ type: "SEMVER", events: [{ introduced: "1" }, { fixed: "2" }] }],
                  versions: [],
                },
              ],
            },
          }
        : {}),
    });
  }
});
