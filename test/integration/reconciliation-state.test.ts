import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  currentInventoryGeneration,
  persistRevision,
  refreshReconciliationCheckpoints,
} from "../../src/reconciliation-state";

import {
  reconciliationImage as logical,
  reconciliationNow as now,
  reconciliationSource as source,
  seedCompleteImage,
} from "./reconciliation-fixture";

describe("reconciliation checkpoint state", () => {
  beforeEach(() => seedCompleteImage(env.DB));

  it("allocates concurrent revisions idempotently without unique failures", async () => {
    const generation = await currentInventoryGeneration(env.DB, source);
    const same = {
      state: "blocked" as const,
      reason: "inventory_incomplete" as const,
      fingerprint: "1".repeat(64),
      generation,
    };
    const results = await Promise.all(
      Array.from({ length: 4 }, () => persistRevision(env.DB, source, same, now)),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM reconciliation_checkpoints").first("COUNT(*)"),
    ).resolves.toBe(1);

    await Promise.all([
      persistRevision(env.DB, source, { ...same, fingerprint: "2".repeat(64) }, now + 1),
      persistRevision(env.DB, source, { ...same, fingerprint: "3".repeat(64) }, now + 1),
    ]);
    await expect(
      env.DB.prepare("SELECT MAX(revision) FROM reconciliation_checkpoints").first("MAX(revision)"),
    ).resolves.toBe(3);
  });

  it("does not allow payload fields to override checkpoint identity", async () => {
    const generation = await currentInventoryGeneration(env.DB, source);
    await persistRevision(
      env.DB,
      source,
      {
        state: "ready",
        fingerprint: "4".repeat(64),
        generation,
        payload: { checkpoint_id: "attacker", revision: 999, kind: "inventory_snapshot" },
      },
      now,
    );
    const row = await env.DB.prepare(
      "SELECT checkpoint_id,revision,payload_json FROM reconciliation_checkpoints",
    ).first<{ checkpoint_id: string; revision: number; payload_json: string }>();
    const payload = JSON.parse(row?.payload_json ?? "{}") as {
      checkpoint_id?: string;
      revision?: number;
    };
    expect(payload).toMatchObject({ checkpoint_id: row?.checkpoint_id, revision: row?.revision });
    expect(payload.checkpoint_id).not.toBe("attacker");
    expect(payload.revision).not.toBe(999);
  });

  it("advances past one image whose checkpoint write fails", async () => {
    const next = `ghcr.io/owner/z-demo@sha256:${"9".repeat(64)}`;
    await env.DB.prepare(
      `INSERT INTO sboms
       (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,
        created_at,installation_id,repository_id)
       VALUES ('next','tenant',? ,?,'linux/amd64',?,'complete',1,'123','9')`,
    )
      .bind(next, next, "6".repeat(64))
      .run();
    await env.DB.prepare(
      `CREATE TRIGGER fail_first_checkpoint BEFORE INSERT ON reconciliation_checkpoints
       WHEN NEW.logical_image_ref='${logical}'
       BEGIN SELECT RAISE(FAIL,'injected image failure'); END`,
    ).run();
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await refreshReconciliationCheckpoints(env.DB, now);
      expect(error).toHaveBeenCalledWith("checkpoint refresh failed", logical, expect.any(String));
    } finally {
      await env.DB.prepare("DROP TRIGGER fail_first_checkpoint").run();
      error.mockRestore();
    }
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM image_reconciliation_state WHERE logical_image_ref=?")
        .bind(logical)
        .first("COUNT(*)"),
    ).resolves.toBe(0);

    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM image_reconciliation_state WHERE logical_image_ref=?")
        .bind(next)
        .first("COUNT(*)"),
    ).resolves.toBe(1);
  });
  it("advances a durable cursor across bounded refresh pages", async () => {
    await env.DB.batch(
      Array.from({ length: 25 }, (_, index) => {
        const suffix = index.toString(16).padStart(64, "0");
        return env.DB.prepare(
          `INSERT INTO sboms
           (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,
            created_at,installation_id,repository_id)
           VALUES (?,'tenant',?,?,'linux/amd64',?,'complete',1,'123','9')`,
        ).bind(
          `page-${index}`,
          `ghcr.io/owner/page-${index}@sha256:${suffix}`,
          `ghcr.io/owner/page-${index}@sha256:${suffix}`,
          "6".repeat(64),
        );
      }),
    );

    await refreshReconciliationCheckpoints(env.DB, now);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM image_reconciliation_state").first("COUNT(*)"),
    ).resolves.toBe(25);
    await refreshReconciliationCheckpoints(env.DB, now);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM image_reconciliation_state").first("COUNT(*)"),
    ).resolves.toBe(26);
  });
});
