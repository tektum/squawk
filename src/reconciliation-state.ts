import { canonicalJson } from "./canonical-json";
import type { RunDeadline } from "./budget";
import { sha256 } from "./digest";
import { describeError } from "./error-detail";
import { buildInventoryCandidate } from "./inventory-checkpoint";
import { currentInventoryGeneration, type InventoryImageKey } from "./inventory-generation";
import type { ReconciliationReason } from "./reconciliation-contract";

export type ReconciliationImageKey = InventoryImageKey;
export { currentInventoryGeneration } from "./inventory-generation";
export type CheckpointCandidate =
  | {
      readonly state: "blocked";
      readonly reason: ReconciliationReason;
      readonly fingerprint: string;
      readonly generation: number;
    }
  | {
      readonly state: "ready";
      readonly fingerprint: string;
      readonly payload: object;
      readonly generation: number;
    };

export class StaleInventoryGeneration extends Error {
  readonly name = "StaleInventoryGeneration";
}

export async function persistRevision(
  database: D1Database,
  image: ReconciliationImageKey,
  candidate: CheckpointCandidate,
  now: number,
): Promise<boolean> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const inventoryGeneration = await currentInventoryGeneration(database, image);
    if (inventoryGeneration !== candidate.generation) throw new StaleInventoryGeneration();
    const current = await database
      .prepare(
        `SELECT revision,state_sha256,applied_revision,inventory_generation
         FROM image_reconciliation_state
         WHERE installation_id=? AND repository_id=? AND logical_image_ref=?`,
      )
      .bind(image.installation_id, image.repository_id, image.logical_image_ref)
      .first<{
        readonly revision: number;
        readonly state_sha256: string;
        readonly applied_revision: number;
        readonly inventory_generation: number;
      }>();
    if (
      current?.state_sha256 === candidate.fingerprint &&
      current.inventory_generation === candidate.generation
    )
      return false;
    const revision = (current?.revision ?? 0) + 1;
    const checkpointId = await sha256(
      [
        "reconciliation-checkpoint-v2",
        image.installation_id,
        image.repository_id,
        image.logical_image_ref,
        revision.toString(),
        candidate.fingerprint,
      ].join("\u0000"),
    );
    let payloadJson: string | null = null;
    let payloadSha256: string | null = null;
    if (candidate.state === "ready") {
      payloadJson = canonicalJson({
        ...candidate.payload,
        checkpoint_id: checkpointId,
        revision,
      });
      payloadSha256 = await sha256(payloadJson);
    }
    const results = await database.batch([
      database
        .prepare(
          `INSERT OR IGNORE INTO reconciliation_checkpoints
           (checkpoint_id,installation_id,repository_id,logical_image_ref,revision,state,reason,payload_json,payload_sha256,created_at)
           SELECT ?,?,?,?,?,?,?,?,?,?
           WHERE (SELECT generation FROM image_inventory_generations
             WHERE installation_id=? AND repository_id=? AND logical_image_ref=?)=?`,
        )
        .bind(
          checkpointId,
          image.installation_id,
          image.repository_id,
          image.logical_image_ref,
          revision,
          candidate.state,
          candidate.state === "blocked" ? candidate.reason : null,
          payloadJson,
          payloadSha256,
          now,
          image.installation_id,
          image.repository_id,
          image.logical_image_ref,
          candidate.generation,
        ),
      database
        .prepare(
          `INSERT INTO image_reconciliation_state
           (installation_id,repository_id,logical_image_ref,revision,state,reason,checkpoint_id,applied_revision,inventory_generation,state_sha256,updated_at)
           SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS (
             SELECT 1 FROM reconciliation_checkpoints WHERE checkpoint_id=?
           ) AND (SELECT generation FROM image_inventory_generations
             WHERE installation_id=? AND repository_id=? AND logical_image_ref=?)=?
           ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET
             revision=excluded.revision,state=excluded.state,reason=excluded.reason,
             checkpoint_id=excluded.checkpoint_id,inventory_generation=excluded.inventory_generation,
             state_sha256=excluded.state_sha256,updated_at=excluded.updated_at
           WHERE image_reconciliation_state.revision=?
             AND image_reconciliation_state.state_sha256=?
             AND (SELECT generation FROM image_inventory_generations
               WHERE installation_id=? AND repository_id=? AND logical_image_ref=?)=?`,
        )
        .bind(
          image.installation_id,
          image.repository_id,
          image.logical_image_ref,
          revision,
          candidate.state,
          candidate.state === "blocked" ? candidate.reason : null,
          checkpointId,
          current?.applied_revision ?? 0,
          candidate.generation,
          candidate.fingerprint,
          now,
          checkpointId,
          image.installation_id,
          image.repository_id,
          image.logical_image_ref,
          candidate.generation,
          current?.revision ?? -1,
          current?.state_sha256 ?? "",
          image.installation_id,
          image.repository_id,
          image.logical_image_ref,
          candidate.generation,
        ),
    ]);
    if ((results[1]?.meta.changes ?? 0) > 0) return true;
    if ((await currentInventoryGeneration(database, image)) !== candidate.generation)
      throw new StaleInventoryGeneration();
  }
  throw new Error("reconciliation revision allocation did not converge");
}

export async function refreshReconciliationImage(
  database: D1Database,
  image: ReconciliationImageKey,
  now = Date.now(),
): Promise<boolean> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      const candidate = await buildInventoryCandidate(database, image, now);
      return await persistRevision(database, image, candidate, now);
    } catch (error) {
      if (error instanceof StaleInventoryGeneration) continue;
      const generation = await currentInventoryGeneration(database, image);
      try {
        await persistRevision(
          database,
          image,
          {
            state: "blocked",
            reason: "checkpoint_invalidated",
            fingerprint: await sha256(
              `${image.installation_id}\u0000${image.repository_id}\u0000${image.logical_image_ref}\u0000${generation}\u0000${now}`,
            ),
            generation,
          },
          now,
        );
      } catch (failure) {
        if (failure instanceof StaleInventoryGeneration) continue;
        throw failure;
      }
      throw error;
    }
  }
  throw new Error("reconciliation inventory did not stabilize");
}

export async function refreshReconciliationCheckpoints(
  database: D1Database,
  now = Date.now(),
  deadline?: RunDeadline,
): Promise<number> {
  const cursor = await database
    .prepare(
      `SELECT installation_id,repository_id,logical_image_ref FROM reconciliation_refresh_cursor
       WHERE singleton=1`,
    )
    .first<Record<keyof ReconciliationImageKey, string | null>>();
  const images = (
    await database
      .prepare(
        `SELECT DISTINCT s.installation_id,s.repository_id,s.logical_image_ref
         FROM sboms s JOIN github_sources g
           ON g.installation_id=s.installation_id AND g.repository_id=s.repository_id
         WHERE s.retired_at IS NULL AND s.installation_id IS NOT NULL AND s.repository_id IS NOT NULL
           AND (? IS NULL OR s.installation_id>? OR
             (s.installation_id=? AND s.repository_id>?) OR
             (s.installation_id=? AND s.repository_id=? AND s.logical_image_ref>?))
         ORDER BY s.installation_id,s.repository_id,s.logical_image_ref LIMIT 25`,
      )
      .bind(
        cursor?.installation_id ?? null,
        cursor?.installation_id ?? "",
        cursor?.installation_id ?? "",
        cursor?.repository_id ?? "",
        cursor?.installation_id ?? "",
        cursor?.repository_id ?? "",
        cursor?.logical_image_ref ?? "",
      )
      .all<ReconciliationImageKey>()
  ).results;
  let changed = 0;
  let last: ReconciliationImageKey | undefined;
  for (const image of images) {
    if (deadline?.expired) break;
    try {
      if (await refreshReconciliationImage(database, image, now)) changed += 1;
    } catch (error) {
      console.error("checkpoint refresh failed", image.logical_image_ref, describeError(error));
    }
    last = image;
  }
  if (last) {
    const completePage = last === images.at(-1) && images.length < 25;
    await database
      .prepare(
        `UPDATE reconciliation_refresh_cursor SET installation_id=?,repository_id=?,logical_image_ref=?
         WHERE singleton=1`,
      )
      .bind(
        completePage ? null : last.installation_id,
        completePage ? null : last.repository_id,
        completePage ? null : last.logical_image_ref,
      )
      .run();
  } else if (images.length === 0 && cursor?.installation_id !== null) {
    await database
      .prepare(
        `UPDATE reconciliation_refresh_cursor SET installation_id=NULL,repository_id=NULL,
          logical_image_ref=NULL WHERE singleton=1`,
      )
      .run();
  }
  return changed;
}
