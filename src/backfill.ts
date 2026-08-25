import { z } from "zod";
import { recordActivity } from "./activity";
import { resolveAdvisory } from "./advisory";
import { type AdvisoryReference, ecosystemFamily, registerAdvisoryJobs } from "./advisory-jobs";
import type { SubrequestBudget } from "./budget";
import { describeError } from "./error-detail";

export const backfillLeaseMilliseconds = 20 * 60_000;

const componentSchema = z.object({
  id: z.number(),
  package_name: z.string(),
  ecosystem: z.string(),
  version: z.string(),
});
/**
 * OSV /v1/querybatch answers with advisory identities only; details live in the
 * per-ecosystem advisory documents, so this is an index, not a match result.
 */
const queryBatchSchema = z.object({
  results: z.array(
    z.object({
      vulns: z.array(z.object({ id: z.string().min(1), modified: z.string().min(1) })).optional(),
    }),
  ),
});

type BackfillOptions = {
  readonly database: D1Database;
  readonly sbomId: string;
  readonly osvApiUrl: string;
  readonly osvBaseUrl: string;
  readonly now?: number;
  readonly budget?: SubrequestBudget;
};

/**
 * Backfills advisory data for an eligible SBOM and records the scan outcome.
 *
 * @param options - Configuration, database access, and identifiers for the backfill operation
 */
export async function backfillSbom(options: BackfillOptions): Promise<void> {
  const now = options.now ?? Date.now();
  const claim = await options.database
    .prepare(
      "UPDATE sboms SET backfill_status='running',backfill_attempted_at=?,backfill_error=NULL WHERE id=? AND retired_at IS NULL AND (backfill_status IN ('pending','failed') OR (backfill_status='running' AND COALESCE(backfill_attempted_at,0)<?))",
    )
    .bind(now, options.sbomId, now - backfillLeaseMilliseconds)
    .run();
  if (claim.meta.changes === 0) return;
  try {
    const components = (
      await options.database
        .prepare(
          "SELECT c.id,c.package_name,c.ecosystem,c.version FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE c.sbom_id=? AND c.matchable=1 AND s.retired_at IS NULL",
        )
        .bind(options.sbomId)
        .all()
    ).results.map((row) => componentSchema.parse(row));
    if (components.length > 0) {
      options.budget?.take();
      const response = await fetch(`${options.osvApiUrl}/v1/querybatch`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          queries: components.map((component) => ({
            package: { name: component.package_name, ecosystem: component.ecosystem },
            version: component.version,
          })),
        }),
        signal: AbortSignal.timeout(15_000),
      });
      if (!response.ok) throw new Error(`OSV querybatch failed (${response.status})`);
      const batch = queryBatchSchema.parse(await response.json());
      const references = new Map<string, AdvisoryReference>();
      for (const [index, result] of batch.results.entries()) {
        const component = components[index];
        if (!component) throw new Error("OSV querybatch result count mismatch");
        const ecosystem = ecosystemFamily(component.ecosystem);
        for (const vulnerability of result.vulns ?? [])
          references.set(`${ecosystem}\u0000${vulnerability.id}`, {
            ecosystem,
            advisoryId: vulnerability.id,
            modifiedAt: vulnerability.modified,
          });
      }
      // Every advisory is registered before any is resolved, so a run that stops
      // on the subrequest budget leaves the remainder for the queue to finish.
      const registered = await registerAdvisoryJobs(options.database, [...references.values()]);
      for (const advisory of registered) {
        if (options.budget && options.budget.remaining <= 1) break;
        options.budget?.take();
        await resolveAdvisory({
          database: options.database,
          ecosystem: advisory.ecosystem,
          advisoryId: advisory.advisoryId,
          osvBaseUrl: options.osvBaseUrl,
          now,
        });
        await options.database
          .prepare(
            "UPDATE osv_advisory_jobs SET status='complete',error=NULL WHERE job_id=? AND modified_at=?",
          )
          .bind(advisory.jobId, advisory.modifiedAt)
          .run();
      }
    }
    await options.database
      .prepare("UPDATE sboms SET backfill_status='complete',backfill_error=NULL WHERE id=?")
      .bind(options.sbomId)
      .run();
    await recordActivity(options.database, "scan", "completed", now);
  } catch (error) {
    const message = describeError(error);
    await options.database
      .prepare("UPDATE sboms SET backfill_status='failed',backfill_error=? WHERE id=?")
      .bind(message.slice(0, 500), options.sbomId)
      .run();
    await recordActivity(options.database, "scan", "failed", now);
    throw error;
  }
}
