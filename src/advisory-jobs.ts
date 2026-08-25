import { sha256 } from "./digest";

export type AdvisoryReference = {
  readonly ecosystem: string;
  readonly advisoryId: string;
  readonly modifiedAt: string;
};

export type RegisteredAdvisory = AdvisoryReference & { readonly jobId: string };

/** OSV advisory feeds are per ecosystem family, so Alpine:v3.21 shares Alpine's feed. */
export function ecosystemFamily(ecosystem: string): string {
  return ecosystem.split(":")[0] ?? ecosystem;
}

/**
 * Registers advisory revisions as idempotent jobs.
 *
 * Newer revisions replace older stored revisions and reset their jobs to `pending`;
 * older or equal revisions preserve the existing job state.
 *
 * @param references - Advisory revisions to register
 * @returns The registered advisories with their effective job IDs and modification timestamps
 */
export async function registerAdvisoryJobs(
  database: D1Database,
  references: readonly AdvisoryReference[],
): Promise<readonly RegisteredAdvisory[]> {
  if (references.length === 0) return [];
  const candidates = await Promise.all(
    references.map(async (reference) => ({
      ...reference,
      jobId: await sha256(
        [reference.ecosystem, reference.advisoryId, reference.modifiedAt].join("\u0000"),
      ),
    })),
  );
  // An older revision must never displace a newer one, so identity and revision
  // only move forward. RETURNING hands back whichever revision is now stored, so
  // callers never act on an identity the table rejected.
  const stored = await database.batch<{ readonly job_id: string; readonly modified_at: string }>(
    candidates.map((advisory) =>
      database
        .prepare(
          "INSERT INTO osv_advisory_jobs (job_id,ecosystem,advisory_id,modified_at,status) VALUES (?,?,?,?,'pending') ON CONFLICT(ecosystem,advisory_id) DO UPDATE SET job_id=CASE WHEN excluded.modified_at>osv_advisory_jobs.modified_at THEN excluded.job_id ELSE osv_advisory_jobs.job_id END,modified_at=CASE WHEN excluded.modified_at>osv_advisory_jobs.modified_at THEN excluded.modified_at ELSE osv_advisory_jobs.modified_at END,status=CASE WHEN excluded.modified_at>osv_advisory_jobs.modified_at THEN 'pending' ELSE osv_advisory_jobs.status END,error=CASE WHEN excluded.modified_at>osv_advisory_jobs.modified_at THEN NULL ELSE osv_advisory_jobs.error END RETURNING job_id,modified_at",
        )
        .bind(advisory.jobId, advisory.ecosystem, advisory.advisoryId, advisory.modifiedAt),
    ),
  );
  return candidates.map((advisory, index) => {
    const row = stored[index]?.results[0];
    return row ? { ...advisory, jobId: row.job_id, modifiedAt: row.modified_at } : advisory;
  });
}
