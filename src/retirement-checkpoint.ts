import { sha256 } from "./digest";
import {
  currentInventoryGeneration,
  persistRevision,
  type ReconciliationImageKey,
} from "./reconciliation-state";
const immutableImage = /^(.+)@sha256:([a-f0-9]{64})$/;
const actionsRun = /^https:\/\/github\.com\/[^/]+\/[^/]+\/actions\/runs\/\d+$/;

async function blockMissingImages(database: D1Database, now: number): Promise<number> {
  const rows = (
    await database
      .prepare(
        `SELECT r.installation_id,r.repository_id,r.logical_image_ref,MAX(s.retired_at) AS retired_at
         FROM image_reconciliation_state r LEFT JOIN sboms s
           ON s.installation_id=r.installation_id AND s.repository_id=r.repository_id
           AND s.logical_image_ref=r.logical_image_ref
         WHERE NOT EXISTS (SELECT 1 FROM sboms active WHERE active.installation_id=r.installation_id
           AND active.repository_id=r.repository_id AND active.logical_image_ref=r.logical_image_ref
           AND active.retired_at IS NULL)
         AND NOT EXISTS (SELECT 1 FROM authoritative_retirements a
           WHERE a.installation_id=r.installation_id AND a.repository_id=r.repository_id
           AND a.logical_image_ref=r.logical_image_ref)
         GROUP BY r.installation_id,r.repository_id,r.logical_image_ref`,
      )
      .all<ReconciliationImageKey & { readonly retired_at: number | null }>()
  ).results;
  let changed = 0;
  for (const row of rows) {
    const fingerprint = await sha256(
      `${row.installation_id}\u0000${row.repository_id}\u0000${row.logical_image_ref}\u0000${row.retired_at ?? "missing"}\u0000retirement_unverified`,
    );
    const generation = await currentInventoryGeneration(database, row);
    if (
      await persistRevision(
        database,
        row,
        { state: "blocked", reason: "retirement_unverified", fingerprint, generation },
        now,
      )
    )
      changed += 1;
  }
  return changed;
}

async function refreshVerifiedRetirements(database: D1Database, now: number): Promise<number> {
  const events = (
    await database
      .prepare(
        `SELECT r.event_id,r.installation_id,r.repository_id,r.logical_image_ref,
          r.replacement_logical_image_ref,r.replacement_published_at,r.replacement_run_url,r.retired_at
         FROM authoritative_retirements r
         WHERE NOT EXISTS (
           SELECT 1 FROM sboms s WHERE s.installation_id=r.installation_id
             AND s.repository_id=r.repository_id AND s.logical_image_ref=r.logical_image_ref
             AND s.retired_at IS NULL
         ) ORDER BY r.installation_id,r.repository_id,r.logical_image_ref`,
      )
      .all<{
        readonly event_id: string;
        readonly installation_id: string;
        readonly repository_id: string;
        readonly logical_image_ref: string;
        readonly replacement_logical_image_ref: string;
        readonly replacement_published_at: number;
        readonly replacement_run_url: string;
        readonly retired_at: number;
      }>()
  ).results;
  let changed = 0;
  for (const event of events) {
    const fingerprint = await sha256(JSON.stringify(event));
    const generation = await currentInventoryGeneration(database, event);
    const retired = immutableImage.exec(event.logical_image_ref);
    const replacement = immutableImage.exec(event.replacement_logical_image_ref);
    if (
      !retired ||
      !replacement ||
      retired[1] !== replacement[1] ||
      retired[2] === replacement[2] ||
      event.replacement_published_at > event.retired_at ||
      !actionsRun.test(event.replacement_run_url)
    ) {
      if (
        await persistRevision(
          database,
          event,
          { state: "blocked", reason: "retirement_unverified", fingerprint, generation },
          now,
        )
      )
        changed += 1;
      continue;
    }
    const payload = {
      logical_image_ref: event.logical_image_ref,
      source: {
        installation_id: event.installation_id,
        repository_id: event.repository_id,
        ingestion_delivery_id: event.event_id,
      },
      kind: "retirement" as const,
      retired_at: Math.floor(event.retired_at / 1000),
      authoritative_source_event_id: event.event_id,
      replacement: {
        logical_image_ref: event.replacement_logical_image_ref,
        published_at: Math.floor(event.replacement_published_at / 1000),
        run_url: event.replacement_run_url,
      },
    };
    if (
      await persistRevision(
        database,
        event,
        { state: "ready", fingerprint, payload, generation },
        now,
      )
    )
      changed += 1;
  }
  return changed;
}

export async function refreshRetirementCheckpoints(
  database: D1Database,
  now = Date.now(),
): Promise<number> {
  const blocked = await blockMissingImages(database, now);
  return blocked + (await refreshVerifiedRetirements(database, now));
}
