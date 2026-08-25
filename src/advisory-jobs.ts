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
 * Durable identity for an advisory revision. Registering is idempotent and only
 * reopens a completed job when OSV published a newer revision.
 */
export async function registerAdvisoryJobs(
  database: D1Database,
  references: readonly AdvisoryReference[],
): Promise<readonly RegisteredAdvisory[]> {
  if (references.length === 0) return [];
  const registered = await Promise.all(
    references.map(async (reference) => ({
      ...reference,
      jobId: await sha256(
        [reference.ecosystem, reference.advisoryId, reference.modifiedAt].join("\u0000"),
      ),
    })),
  );
  await database.batch(
    registered.map((advisory) =>
      database
        .prepare(
          "INSERT INTO osv_advisory_jobs (job_id,ecosystem,advisory_id,modified_at,status) VALUES (?,?,?,?,'pending') ON CONFLICT(ecosystem,advisory_id) DO UPDATE SET job_id=excluded.job_id,modified_at=excluded.modified_at,status=CASE WHEN excluded.modified_at>osv_advisory_jobs.modified_at THEN 'pending' ELSE osv_advisory_jobs.status END,error=CASE WHEN excluded.modified_at>osv_advisory_jobs.modified_at THEN NULL ELSE osv_advisory_jobs.error END",
        )
        .bind(advisory.jobId, advisory.ecosystem, advisory.advisoryId, advisory.modifiedAt),
    ),
  );
  return registered;
}
