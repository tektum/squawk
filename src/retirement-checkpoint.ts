import { sha256 } from "./digest";
import type { RunDeadline } from "./budget";
import {
  currentInventoryGeneration,
  persistRevision,
  type CheckpointCandidate,
  type ReconciliationImageKey,
  StaleInventoryGeneration,
} from "./reconciliation-state";

const immutableImage = /^(.+)@sha256:([a-f0-9]{64})$/;
const actionsRun = /^https:\/\/github\.com\/[^/]+\/[^/]+\/actions\/runs\/\d+$/;
type RetirementEvent = ReconciliationImageKey & {
  readonly event_id: string;
  readonly replacement_logical_image_ref: string;
  readonly replacement_published_at: number;
  readonly replacement_run_url: string;
  readonly retired_at: number;
};
type CandidateBuilder = (generation: number) => Promise<CheckpointCandidate | null>;

async function persistFresh(
  database: D1Database,
  image: ReconciliationImageKey,
  build: CandidateBuilder,
  now: number,
): Promise<boolean> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const generation = await currentInventoryGeneration(database, image);
    const candidate = await build(generation);
    if (!candidate) return false;
    try {
      return await persistRevision(database, image, candidate, now);
    } catch (error) {
      if (error instanceof StaleInventoryGeneration) continue;
      throw error;
    }
  }
  throw new Error("retirement inventory did not stabilize");
}

async function missingCandidate(
  database: D1Database,
  image: ReconciliationImageKey,
  generation: number,
): Promise<CheckpointCandidate | null> {
  const row = await database
    .prepare(
      `SELECT MAX(s.retired_at) AS retired_at FROM image_reconciliation_state r
       LEFT JOIN sboms s ON s.installation_id=r.installation_id
         AND s.repository_id=r.repository_id AND s.logical_image_ref=r.logical_image_ref
       WHERE r.installation_id=? AND r.repository_id=? AND r.logical_image_ref=?
         AND NOT EXISTS (SELECT 1 FROM sboms active WHERE active.installation_id=r.installation_id
           AND active.repository_id=r.repository_id AND active.logical_image_ref=r.logical_image_ref
           AND active.retired_at IS NULL)
         AND NOT EXISTS (SELECT 1 FROM authoritative_retirements a
           WHERE a.installation_id=r.installation_id AND a.repository_id=r.repository_id
             AND a.logical_image_ref=r.logical_image_ref)`,
    )
    .bind(image.installation_id, image.repository_id, image.logical_image_ref)
    .first<{ readonly retired_at: number | null }>();
  if (!row) return null;
  return {
    state: "blocked",
    reason: "retirement_unverified",
    fingerprint: await sha256(
      `${image.installation_id}\u0000${image.repository_id}\u0000${image.logical_image_ref}\u0000${row.retired_at ?? "missing"}\u0000retirement_unverified`,
    ),
    generation,
  };
}

async function loadRetirement(
  database: D1Database,
  image: ReconciliationImageKey,
): Promise<RetirementEvent | null> {
  return database
    .prepare(
      `SELECT r.event_id,r.installation_id,r.repository_id,r.logical_image_ref,
        r.replacement_logical_image_ref,r.replacement_published_at,r.replacement_run_url,r.retired_at
       FROM authoritative_retirements r
       WHERE r.installation_id=? AND r.repository_id=? AND r.logical_image_ref=?
         AND NOT EXISTS (SELECT 1 FROM sboms s WHERE s.installation_id=r.installation_id
           AND s.repository_id=r.repository_id AND s.logical_image_ref=r.logical_image_ref
           AND s.retired_at IS NULL)`,
    )
    .bind(image.installation_id, image.repository_id, image.logical_image_ref)
    .first<RetirementEvent>();
}

async function retirementCandidate(
  database: D1Database,
  image: ReconciliationImageKey,
  generation: number,
): Promise<CheckpointCandidate | null> {
  const event = await loadRetirement(database, image);
  if (!event) return null;
  const fingerprint = await sha256(JSON.stringify(event));
  const retired = immutableImage.exec(event.logical_image_ref);
  const replacement = immutableImage.exec(event.replacement_logical_image_ref);
  if (
    !retired ||
    !replacement ||
    retired[1] !== replacement[1] ||
    retired[2] === replacement[2] ||
    event.replacement_published_at > event.retired_at ||
    !actionsRun.test(event.replacement_run_url)
  )
    return { state: "blocked", reason: "retirement_unverified", fingerprint, generation };
  return {
    state: "ready",
    fingerprint,
    generation,
    payload: {
      logical_image_ref: event.logical_image_ref,
      source: {
        installation_id: event.installation_id,
        repository_id: event.repository_id,
        ingestion_delivery_id: event.event_id,
      },
      kind: "retirement",
      retired_at: Math.floor(event.retired_at / 1000),
      authoritative_source_event_id: event.event_id,
      replacement: {
        logical_image_ref: event.replacement_logical_image_ref,
        published_at: Math.floor(event.replacement_published_at / 1000),
        run_url: event.replacement_run_url,
      },
    },
  };
}

export async function refreshRetirementCheckpoint(
  database: D1Database,
  image: ReconciliationImageKey,
  now = Date.now(),
): Promise<boolean> {
  return persistFresh(
    database,
    image,
    async (generation) =>
      (await loadRetirement(database, image))
        ? retirementCandidate(database, image, generation)
        : missingCandidate(database, image, generation),
    now,
  );
}

export async function refreshRetirementCheckpoints(
  database: D1Database,
  now = Date.now(),
  deadline?: RunDeadline,
): Promise<number> {
  const rows = (
    await database
      .prepare(
        `SELECT installation_id,repository_id,logical_image_ref FROM authoritative_retirements
         UNION
         SELECT r.installation_id,r.repository_id,r.logical_image_ref
         FROM image_reconciliation_state r
         WHERE NOT EXISTS (SELECT 1 FROM sboms s WHERE s.installation_id=r.installation_id
           AND s.repository_id=r.repository_id AND s.logical_image_ref=r.logical_image_ref
           AND s.retired_at IS NULL)
         ORDER BY installation_id,repository_id,logical_image_ref`,
      )
      .all<ReconciliationImageKey>()
  ).results;
  let changed = 0;
  for (const image of rows) {
    if (deadline?.expired) break;
    if (await refreshRetirementCheckpoint(database, image, now)) changed += 1;
  }
  return changed;
}
