import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  currentInventoryGeneration,
  refreshReconciliationCheckpoints,
} from "../../src/reconciliation-state";
import { refreshRetirementCheckpoints } from "../../src/retirement-checkpoint";
import {
  reconciliationImage as logical,
  reconciliationNow as now,
  reconciliationSource as source,
  seedCompleteImage,
} from "./reconciliation-fixture";

describe("retirement checkpoint state", () => {
  beforeEach(() => seedCompleteImage(env.DB));

  it("blocks retirement without authoritative replacement evidence", async () => {
    await refreshReconciliationCheckpoints(env.DB, now);
    await env.DB.prepare("UPDATE sboms SET retired_at=?")
      .bind(now + 1)
      .run();
    await refreshRetirementCheckpoints(env.DB, now + 1);
    await expect(
      env.DB.prepare("SELECT reason FROM image_reconciliation_state").first("reason"),
    ).resolves.toBe("retirement_unverified");
  });
  it("ignores authoritative retirement evidence while the image is active", async () => {
    await refreshReconciliationCheckpoints(env.DB, now);
    await env.DB.prepare(
      `INSERT INTO authoritative_retirements
       (event_id,installation_id,repository_id,logical_image_ref,replacement_logical_image_ref,
        replacement_published_at,replacement_run_url,retired_at,created_at)
       VALUES ('active-event','123','9',?,?,1,'https://github.com/owner/repo/actions/runs/42',2,2)`,
    )
      .bind(logical, `ghcr.io/owner/demo@sha256:${"9".repeat(64)}`)
      .run();

    await expect(refreshRetirementCheckpoints(env.DB, now + 1)).resolves.toBe(0);
    await expect(
      env.DB.prepare("SELECT state || ':' || revision FROM image_reconciliation_state").first(
        "state || ':' || revision",
      ),
    ).resolves.toBe("ready:1");
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
    const generation = await currentInventoryGeneration(env.DB, source);
    await env.DB.prepare(
      `CREATE TRIGGER inject_retirement_generation_race
       BEFORE INSERT ON reconciliation_checkpoints
       WHEN NEW.state='ready' AND (SELECT generation FROM image_inventory_generations
         WHERE installation_id='123' AND repository_id='9' AND logical_image_ref='${logical}')=${generation}
       BEGIN
         UPDATE image_inventory_generations SET generation=generation+1
         WHERE installation_id='123' AND repository_id='9' AND logical_image_ref='${logical}';
       END`,
    ).run();
    try {
      await refreshRetirementCheckpoints(env.DB, now + 1);
    } finally {
      await env.DB.prepare("DROP TRIGGER inject_retirement_generation_race").run();
    }
    const payload = await env.DB.prepare(
      "SELECT payload_json FROM reconciliation_checkpoints WHERE revision=2",
    ).first<string>("payload_json");
    expect(JSON.parse(payload ?? "{}")).toMatchObject({
      kind: "retirement",
      authoritative_source_event_id: "retirement-event",
      replacement: { logical_image_ref: `ghcr.io/owner/demo@sha256:${"9".repeat(64)}` },
    });
  });

  it("continues retirement refresh after one image fails", async () => {
    const second = `ghcr.io/owner/z-retired@sha256:${"8".repeat(64)}`;
    await refreshReconciliationCheckpoints(env.DB, now);
    await env.DB.prepare("UPDATE sboms SET retired_at=?")
      .bind(now + 1)
      .run();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO authoritative_retirements
         (event_id,installation_id,repository_id,logical_image_ref,replacement_logical_image_ref,
          replacement_published_at,replacement_run_url,retired_at,created_at)
         VALUES ('first','123','9',?,?,1,'https://github.com/owner/repo/actions/runs/41',2,2)`,
      ).bind(logical, `ghcr.io/owner/demo@sha256:${"7".repeat(64)}`),
      env.DB.prepare(
        `INSERT INTO authoritative_retirements
         (event_id,installation_id,repository_id,logical_image_ref,replacement_logical_image_ref,
          replacement_published_at,replacement_run_url,retired_at,created_at)
         VALUES ('second','123','9',?,?,1,'https://github.com/owner/repo/actions/runs/42',2,2)`,
      ).bind(second, `ghcr.io/owner/z-retired@sha256:${"9".repeat(64)}`),
      env.DB.prepare(
        `CREATE TRIGGER fail_first_retirement BEFORE INSERT ON reconciliation_checkpoints
         WHEN NEW.logical_image_ref='${logical}'
         BEGIN SELECT RAISE(FAIL,'injected retirement failure'); END`,
      ),
    ]);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await refreshRetirementCheckpoints(env.DB, now + 1);
      expect(error).toHaveBeenCalledWith(
        "Retirement checkpoint refresh failed",
        expect.objectContaining({ logicalImageRef: logical, error: expect.any(String) }),
      );
    } finally {
      await env.DB.prepare("DROP TRIGGER fail_first_retirement").run();
      error.mockRestore();
    }

    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) FROM image_reconciliation_state WHERE logical_image_ref=? AND state='ready'",
      )
        .bind(second)
        .first("COUNT(*)"),
    ).resolves.toBe(1);
  });

  it("advances a durable cursor across bounded retirement pages", async () => {
    await env.DB.batch(
      Array.from({ length: 26 }, (_, index) => {
        const suffix = index.toString(16).padStart(64, "0");
        const replacement = (index + 100).toString(16).padStart(64, "0");
        return env.DB.prepare(
          `INSERT INTO authoritative_retirements
           (event_id,installation_id,repository_id,logical_image_ref,replacement_logical_image_ref,
            replacement_published_at,replacement_run_url,retired_at,created_at)
           VALUES (?,'123','9',?,?,1,'https://github.com/owner/repo/actions/runs/42',2,2)`,
        ).bind(
          `page-${index}`,
          `ghcr.io/owner/retired-${index}@sha256:${suffix}`,
          `ghcr.io/owner/retired-${index}@sha256:${replacement}`,
        );
      }),
    );

    await refreshRetirementCheckpoints(env.DB, now);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM image_reconciliation_state").first("COUNT(*)"),
    ).resolves.toBe(25);
    await refreshRetirementCheckpoints(env.DB, now);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM image_reconciliation_state").first("COUNT(*)"),
    ).resolves.toBe(26);
  });
});
