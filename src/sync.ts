import { z } from "zod";
import type { AdvisoryMessage } from "./advisory";
import { registerAdvisoryJobs } from "./advisory-jobs";

const cursorSchema = z.object({ last_synced_at: z.string(), boundary_ids: z.string() });
const feedRowSchema = z.object({ modified: z.string().datetime(), id: z.string().min(1) });
type QueueSender = {
  sendBatch(messages: Iterable<MessageSendRequest<AdvisoryMessage>>): Promise<unknown>;
};

export type DiscoveryOptions = {
  readonly database: D1Database;
  readonly ecosystem: string;
  readonly osvBaseUrl: string;
  readonly queue: QueueSender;
  readonly maxChunks?: number;
};

/**
 * Discovers modified OSV advisories and queues jobs for processing.
 *
 * @param options - Configuration for the database, ecosystem, OSV feed, queue, and batch limit
 * @returns The number of advisories selected for processing
 * @throws If the OSV modified-advisory feed responds unsuccessfully
 */
export async function discoverAdvisories(options: DiscoveryOptions): Promise<number> {
  const rawCursor = await options.database
    .prepare("SELECT last_synced_at,boundary_ids FROM sync_cursors WHERE ecosystem=?")
    .bind(options.ecosystem)
    .first();
  if (!rawCursor) return 0;
  const cursor = cursorSchema.parse(rawCursor);
  const response = await fetch(
    `${options.osvBaseUrl}/${encodeURIComponent(options.ecosystem)}/modified_id.csv`,
    { signal: AbortSignal.timeout(10_000) },
  );
  if (!response.ok) throw new Error(`OSV modified feed failed (${response.status})`);
  const boundary = new Set(cursor.boundary_ids.split(",").filter(Boolean));
  const rows = (await response.text())
    .trim()
    .split("\n")
    .slice(1)
    .map((line) => {
      const [modified, id] = line.split(",");
      return feedRowSchema.parse({ modified: modified?.trim(), id: id?.trim() });
    })
    .filter(
      (row) =>
        row.modified > cursor.last_synced_at ||
        (row.modified === cursor.last_synced_at && !boundary.has(row.id)),
    )
    .sort(
      (left, right) =>
        left.modified.localeCompare(right.modified) || left.id.localeCompare(right.id),
    );
  const maxRows = (options.maxChunks ?? 10) * 100;
  const selected = rows.slice(0, maxRows);
  for (let offset = 0; offset < selected.length; offset += 100) {
    const chunk = selected.slice(offset, offset + 100);
    const registered = await registerAdvisoryJobs(
      options.database,
      chunk.map((row) => ({
        ecosystem: options.ecosystem,
        advisoryId: row.id,
        modifiedAt: row.modified,
      })),
    );
    await options.queue.sendBatch(registered.map(({ jobId }) => ({ body: { jobId } })));
    await checkpoint(options.database, options.ecosystem, cursor, rows, offset + chunk.length);
  }
  return selected.length;
}
async function checkpoint(
  database: D1Database,
  ecosystem: string,
  initial: z.infer<typeof cursorSchema>,
  rows: readonly z.infer<typeof feedRowSchema>[],
  count: number,
): Promise<void> {
  const last = rows[count - 1];
  if (!last) return;
  const priorBoundary =
    last.modified === initial.last_synced_at ? initial.boundary_ids.split(",").filter(Boolean) : [];
  const ids = [
    ...priorBoundary,
    ...rows
      .slice(0, count)
      .filter((row) => row.modified === last.modified)
      .map((row) => row.id),
  ].sort();
  await database
    .prepare(
      "UPDATE sync_cursors SET last_synced_at=?,boundary_ids=?,continuation_id=? WHERE ecosystem=?",
    )
    .bind(last.modified, [...new Set(ids)].join(","), rows[count] ? last.id : null, ecosystem)
    .run();
}

export async function requeueAdvisoryJobs(options: {
  readonly database: D1Database;
  readonly queue: QueueSender;
  readonly now?: number;
  readonly limit?: number;
}): Promise<number> {
  const now = options.now ?? Date.now();
  const rows = await options.database
    .prepare(
      "SELECT job_id FROM osv_advisory_jobs WHERE status IN ('pending','failed') OR (status='running' AND COALESCE(attempted_at,0)<?) ORDER BY modified_at LIMIT ?",
    )
    .bind(now - 20 * 60_000, options.limit ?? 100)
    .all<{ readonly job_id: string }>();
  if (rows.results.length > 0)
    await options.queue.sendBatch(rows.results.map((row) => ({ body: { jobId: row.job_id } })));
  return rows.results.length;
}
