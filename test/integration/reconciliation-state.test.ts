import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { buildInventoryCandidate } from "../../src/inventory-checkpoint";
import {
  currentInventoryGeneration,
  persistRevision,
  refreshReconciliationCheckpoints,
} from "../../src/reconciliation-state";
import { refreshRetirementCheckpoints } from "../../src/retirement-checkpoint";

const now = 20_000_000;
const logical = `ghcr.io/owner/demo@sha256:${"a".repeat(64)}`;
const source = { installation_id: "123", repository_id: "9", logical_image_ref: logical };

async function seedCompleteImage(): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
    env.DB.prepare(
      "INSERT INTO github_sources (installation_id,repository_id,org_id,dispatch_workflow,dispatch_ref,created_at) VALUES ('123','9','tenant','monitor.yaml','main',0)",
    ),
    env.DB.prepare(
      "INSERT INTO github_deliveries (delivery_id,installation_id,repository_id,statement_sha256,status,created_at,completed_at,subject_digest) VALUES ('ingestion','123','9','statement','accepted',1,2,?)",
    ).bind(`sha256:${"a".repeat(64)}`),
    env.DB.prepare(
      "INSERT INTO advisory_feed_checks (checkpoint_id,ecosystem,cursor_modified_at,checked_at,completed_at,discovery_complete,status) VALUES (?,'Ubuntu','2026-09-06T00:00:00Z',?,?,1,'complete')",
    ).bind("f".repeat(64), now - 2_000, now - 1_000),
  ]);
  for (const [index, platform] of ["linux/amd64", "linux/arm64"].entries()) {
    const sbom = `sbom-${index}`;
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at,installation_id,repository_id) VALUES (?,'tenant',?,?,?,?,'complete',1,'123','9')",
      ).bind(
        sbom,
        `ghcr.io/owner/demo@sha256:${String(index + 1).repeat(64)}`,
        logical,
        platform,
        String(index + 3).repeat(64),
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (?,?,?,?,?,?,1)",
      ).bind(
        index + 1,
        sbom,
        "openssl",
        "Ubuntu:24.04:LTS",
        "3.0.13-0ubuntu3.15",
        `pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.15?arch=${index === 0 ? "amd64" : "arm64"}&distro=ubuntu-24.04`,
      ),
    ]);
  }
}

describe("reconciliation checkpoint state", () => {
  beforeEach(seedCompleteImage);

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

  it("blocks unsupported package coverage and manual retirement", async () => {
    await env.DB.prepare(
      "UPDATE components SET ecosystem='unsupported:deb:ubuntu',matchable=0 WHERE id=1",
    ).run();
    await refreshReconciliationCheckpoints(env.DB, now);
    await expect(
      env.DB.prepare("SELECT reason FROM image_reconciliation_state").first("reason"),
    ).resolves.toBe("unsupported_coverage");

    await env.DB.prepare("UPDATE sboms SET retired_at=?")
      .bind(now + 1)
      .run();
    await refreshRetirementCheckpoints(env.DB, now + 1);
    await expect(
      env.DB.prepare("SELECT reason FROM image_reconciliation_state").first("reason"),
    ).resolves.toBe("retirement_unverified");
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
  it("emits retirement only from validated replacement evidence", async () => {
    await refreshReconciliationCheckpoints(env.DB, now);
    await env.DB.prepare("UPDATE sboms SET retired_at=?")
      .bind(now + 1)
      .run();
    await env.DB.prepare(
      `INSERT INTO authoritative_retirements
       (event_id,installation_id,repository_id,logical_image_ref,replacement_logical_image_ref,
        replacement_published_at,replacement_run_url,retired_at,created_at)
       VALUES ('retirement-event','123','9',?,?,?,'https://github.com/owner/repo/actions/runs/42',?,?)`,
    )
      .bind(logical, `ghcr.io/owner/demo@sha256:${"9".repeat(64)}`, now, now + 1, now + 1)
      .run();

    await refreshRetirementCheckpoints(env.DB, now + 1);
    const payload = await env.DB.prepare(
      "SELECT payload_json FROM reconciliation_checkpoints WHERE revision=2",
    ).first<string>("payload_json");
    expect(JSON.parse(payload ?? "{}")).toMatchObject({
      kind: "retirement",
      authoritative_source_event_id: "retirement-event",
      replacement: { logical_image_ref: `ghcr.io/owner/demo@sha256:${"9".repeat(64)}` },
    });
  });
});
