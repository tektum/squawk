import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { buildInventoryCandidate } from "../../src/inventory-checkpoint";
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

describe("inventory checkpoint state", () => {
  beforeEach(() => seedCompleteImage(env.DB));
  it("cannot publish a clean candidate after a newer ingestion starts", async () => {
    const clean = await buildInventoryCandidate(env.DB, source, now);
    await env.DB.prepare(
      "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,created_at) VALUES (?,'123','9',?,'pending',?)",
    )
      .bind(`sha256:${"a".repeat(64)}`, logical, now + 1)
      .run();

    await expect(persistRevision(env.DB, source, clean, now + 1)).rejects.toThrow();
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM reconciliation_checkpoints").first("COUNT(*)"),
    ).resolves.toBe(0);
    await refreshReconciliationCheckpoints(env.DB, now + 1);
    await expect(
      env.DB.prepare("SELECT state || ':' || reason FROM image_reconciliation_state").first(
        "state || ':' || reason",
      ),
    ).resolves.toBe("blocked:inventory_incomplete");
  });

  it("persists a complete two-platform inventory with fresh feed evidence", async () => {
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO vulnerabilities VALUES ('USN-1','Ubuntu:24.04:LTS','openssl','{}','high','summary','2026-09-06T00:00:00Z')",
      ),
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',1,'USN-1',1,NULL)"),
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',2,'USN-1',1,NULL)"),
    ]);

    await expect(refreshReconciliationCheckpoints(env.DB, now)).resolves.toBe(1);
    const row = await env.DB.prepare(
      "SELECT state,revision,payload_json,payload_sha256 FROM reconciliation_checkpoints",
    ).first<{
      state: string;
      revision: number;
      payload_json: string;
      payload_sha256: string;
    }>();
    expect(row?.state).toBe("ready");
    expect(row?.revision).toBe(1);
    expect(row?.payload_sha256).toMatch(/^[a-f0-9]{64}$/);
    const payload = JSON.parse(row?.payload_json ?? "{}") as {
      coverage: { advisory_feed_checked_at: number };
      platforms: { platform: string; image_ref: string }[];
      findings: { ecosystem: string; platforms: string[] }[];
    };
    expect(payload.coverage.advisory_feed_checked_at).toBe(Math.floor((now - 2_000) / 1000));
    expect(payload.platforms.map(({ platform }) => platform)).toEqual([
      "linux/amd64",
      "linux/arm64",
    ]);
    expect(payload.findings).toMatchObject([
      { ecosystem: "Ubuntu:24.04:LTS", platforms: ["linux/amd64", "linux/arm64"] },
    ]);
  });

  it("blocks pending advisory jobs even when both SBOM backfills are complete", async () => {
    await env.DB.prepare(
      "INSERT INTO osv_advisory_jobs VALUES (?,'Ubuntu','USN-pending','2026-09-05T00:00:00Z','pending',NULL,NULL)",
    )
      .bind("9".repeat(64))
      .run();

    await refreshReconciliationCheckpoints(env.DB, now);
    await expect(
      env.DB.prepare("SELECT reason FROM image_reconciliation_state").first("reason"),
    ).resolves.toBe("feed_incomplete");
  });

  it("invalidates an older complete check when newer discovery is partial", async () => {
    await refreshReconciliationCheckpoints(env.DB, now);
    await env.DB.prepare(
      "INSERT INTO advisory_feed_checks (checkpoint_id,ecosystem,cursor_modified_at,checked_at,discovery_complete,status) VALUES (?,'Ubuntu','2026-09-07T00:00:00Z',?,0,'pending')",
    )
      .bind("7".repeat(64), now + 1)
      .run();

    await refreshReconciliationCheckpoints(env.DB, now + 1);
    await expect(
      env.DB.prepare("SELECT state || ':' || reason FROM image_reconciliation_state").first(
        "state || ':' || reason",
      ),
    ).resolves.toBe("blocked:feed_incomplete");
  });
  it("supersedes a ready checkpoint when a newer ingestion is incomplete", async () => {
    await refreshReconciliationCheckpoints(env.DB, now);
    await env.DB.prepare(
      "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,created_at) VALUES (?,'123','9',?,'pending',?)",
    )
      .bind(`sha256:${"a".repeat(64)}`, logical, now + 1)
      .run();

    await refreshReconciliationCheckpoints(env.DB, now + 1);
    await expect(
      env.DB.prepare(
        "SELECT state || ':' || reason || ':' || revision FROM image_reconciliation_state",
      ).first("state || ':' || reason || ':' || revision"),
    ).resolves.toBe("blocked:inventory_incomplete:2");
  });

  it("blocks a stale feed check even when advisory modification time is unchanged", async () => {
    await env.DB.prepare("UPDATE advisory_feed_checks SET checked_at=?")
      .bind(now - 6 * 60 * 60_000 - 1)
      .run();

    await refreshReconciliationCheckpoints(env.DB, now);
    await expect(
      env.DB.prepare("SELECT reason FROM image_reconciliation_state").first("reason"),
    ).resolves.toBe("feed_stale");
  });

  it("does not revise inventory for an unchanged feed freshness poll or old-row retention", async () => {
    await env.DB.prepare(
      "INSERT INTO advisory_feed_checks (checkpoint_id,ecosystem,cursor_modified_at,checked_at,completed_at,discovery_complete,status) VALUES (?,'Ubuntu','2026-09-05T00:00:00Z',?,?,1,'complete')",
    )
      .bind("8".repeat(64), now - 4_000, now - 3_000)
      .run();
    await refreshReconciliationCheckpoints(env.DB, now);
    const generation = await currentInventoryGeneration(env.DB, source);

    await env.DB.prepare(
      "UPDATE advisory_feed_checks SET checked_at=?,completed_at=? WHERE checkpoint_id=?",
    )
      .bind(now + 1_000, now + 1_000, "f".repeat(64))
      .run();
    await env.DB.prepare("DELETE FROM advisory_feed_checks WHERE checkpoint_id=?")
      .bind("8".repeat(64))
      .run();

    await expect(currentInventoryGeneration(env.DB, source)).resolves.toBe(generation);
    await expect(refreshReconciliationCheckpoints(env.DB, now + 1_000)).resolves.toBe(0);
    await expect(
      env.DB.prepare("SELECT revision FROM image_reconciliation_state").first("revision"),
    ).resolves.toBe(1);
  });

  it("blocks unsupported package coverage", async () => {
    await env.DB.prepare(
      "UPDATE components SET ecosystem='unsupported:deb:ubuntu',matchable=0 WHERE id=1",
    ).run();
    await refreshReconciliationCheckpoints(env.DB, now);
    await expect(
      env.DB.prepare("SELECT reason FROM image_reconciliation_state").first("reason"),
    ).resolves.toBe("unsupported_coverage");
  });
});
