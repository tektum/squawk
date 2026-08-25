import { z } from "zod";
import { compareVersion } from "./osv/comparator";

export const advisoryMessageSchema = z.object({ jobId: z.string().regex(/^[a-f0-9]{64}$/) });
export type AdvisoryMessage = z.infer<typeof advisoryMessageSchema>;
export const advisoryLeaseMilliseconds = 20 * 60_000;

const jobSchema = z.object({
  advisory_id: z.string(),
  ecosystem: z.string(),
  modified_at: z.string().datetime(),
});
const advisorySchema = z.object({
  id: z.string(),
  modified: z.string(),
  summary: z.string().optional(),
  severity: z.array(z.object({ score: z.string() })).optional(),
  affected: z.array(
    z.object({
      package: z.object({ ecosystem: z.string(), name: z.string() }),
      ranges: z
        .array(
          z.object({
            type: z.string(),
            events: z.array(
              z.object({
                introduced: z.string().optional(),
                fixed: z.string().optional(),
                last_affected: z.string().optional(),
                limit: z.string().optional(),
              }),
            ),
          }),
        )
        .default([]),
      versions: z.array(z.string()).default([]),
    }),
  ),
});
const componentSchema = z.object({ id: z.number(), org_id: z.string(), version: z.string() });

/**
 * Processes a queued advisory job and records its completion or failure.
 *
 * @param message - The advisory queue message identifying the job.
 * @param now - The timestamp used for lease and job updates.
 * @param osvBaseUrl - The base URL of the OSV advisory service.
 */
export async function processAdvisory(options: {
  readonly database: D1Database;
  readonly message: AdvisoryMessage;
  readonly now?: number;
  readonly osvBaseUrl: string;
}): Promise<void> {
  const { jobId } = advisoryMessageSchema.parse(options.message);
  const now = options.now ?? Date.now();
  const claim = await options.database
    .prepare(
      "UPDATE osv_advisory_jobs SET status='running',attempted_at=?,error=NULL WHERE job_id=? AND (status IN ('pending','failed') OR (status='running' AND COALESCE(attempted_at,0)<?))",
    )
    .bind(now, jobId, now - advisoryLeaseMilliseconds)
    .run();
  if (claim.meta.changes === 0) return;
  const rawJob = await options.database
    .prepare("SELECT ecosystem,advisory_id,modified_at FROM osv_advisory_jobs WHERE job_id=?")
    .bind(jobId)
    .first();
  const job = jobSchema.parse(rawJob);
  try {
    await resolveAdvisory({
      database: options.database,
      ecosystem: job.ecosystem,
      advisoryId: job.advisory_id,
      osvBaseUrl: options.osvBaseUrl,
      now,
    });
    await options.database
      .prepare(
        "UPDATE osv_advisory_jobs SET status='complete',error=NULL WHERE job_id=? AND modified_at=?",
      )
      .bind(jobId, job.modified_at)
      .run();
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown advisory error";
    await options.database
      .prepare(
        "UPDATE osv_advisory_jobs SET status='failed',error=? WHERE job_id=? AND modified_at=?",
      )
      .bind(message.slice(0, 500), jobId, job.modified_at)
      .run();
    throw error;
  }
}

/** Fetches one advisory revision and records its vulnerabilities and findings. */
export async function resolveAdvisory(options: {
  readonly database: D1Database;
  readonly ecosystem: string;
  readonly advisoryId: string;
  readonly osvBaseUrl: string;
  readonly now: number;
}): Promise<void> {
  const response = await fetch(
    `${options.osvBaseUrl}/${encodeURIComponent(options.ecosystem)}/${encodeURIComponent(options.advisoryId)}.json`,
    { signal: AbortSignal.timeout(10_000) },
  );
  if (!response.ok) throw new Error(`OSV advisory failed (${response.status})`);
  const advisory = advisorySchema.parse(await response.json());
  for (const affected of advisory.affected.filter(
    (entry) => entry.package.ecosystem.split(":")[0] === options.ecosystem,
  ))
    await persistAffected(options.database, options.ecosystem, advisory, affected, options.now);
}

/**
 * Persists an advisory's affected package data and records matching components.
 *
 * @param ecosystem - The package ecosystem associated with the advisory
 * @param advisory - The advisory metadata to persist
 * @param affected - The affected package, ranges, and versions to evaluate
 * @param now - The timestamp for new findings and matching errors
 */
async function persistAffected(
  database: D1Database,
  ecosystem: string,
  advisory: z.infer<typeof advisorySchema>,
  affected: z.infer<typeof advisorySchema>["affected"][number],
  now: number,
): Promise<void> {
  const components = (
    await database
      .prepare(
        "SELECT c.id,s.org_id,c.version FROM components c JOIN sboms s ON s.id=c.sbom_id AND s.retired_at IS NULL WHERE c.matchable=1 AND c.package_name=? AND (c.ecosystem=? OR c.ecosystem LIKE ?)",
      )
      .bind(affected.package.name, ecosystem, `${ecosystem}:%`)
      .all()
  ).results.map((component) => componentSchema.parse(component));
  if (components.length === 0) return;
  const statements = [
    database
      .prepare(
        "INSERT INTO vulnerabilities (id,ecosystem,package_name,affected_ranges,severity,summary,modified_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id,ecosystem,package_name) DO UPDATE SET affected_ranges=excluded.affected_ranges,severity=excluded.severity,summary=excluded.summary,modified_at=excluded.modified_at",
      )
      .bind(
        advisory.id,
        ecosystem,
        affected.package.name,
        JSON.stringify({ ranges: affected.ranges, versions: affected.versions }),
        advisory.severity?.[0]?.score ?? null,
        advisory.summary ?? null,
        advisory.modified,
      ),
  ];
  for (const component of components) {
    const comparison = await compareVersion({
      ecosystem,
      version: component.version,
      ranges: affected.ranges,
      versions: affected.versions,
    });
    if (comparison.kind === "match")
      statements.push(
        database
          .prepare("INSERT OR IGNORE INTO findings VALUES (?,?,?,?,NULL)")
          .bind(component.org_id, component.id, advisory.id, now),
      );
    if (comparison.kind === "unsupported" || comparison.kind === "error")
      statements.push(
        database
          .prepare(
            "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (?,?,?,?) ON CONFLICT(component_id,vuln_id) DO UPDATE SET reason=excluded.reason,created_at=excluded.created_at",
          )
          .bind(component.id, advisory.id, comparison.reason, now),
      );
  }
  await database.batch(statements);
}
