import type { TenantId } from "./domain";

/* Pipeline internals for the admin panel: the ingestion, advisory, dispatch, and
   matching rows whose errors are invisible from the public surface. Ingestion and
   delivery tables key on installation and repository, so they are scoped through
   `github_sources`, the same join dispatch routing uses. */

const SOURCE_JOIN =
  "JOIN github_sources g ON g.installation_id = j.installation_id AND g.repository_id = j.repository_id";

export type JobFilters = {
  readonly status: string | null;
  readonly limit: number;
};

export async function jobs(database: D1Database, tenantId: TenantId, filters: JobFilters) {
  const [ingestion, advisories, dispatch, matching] = await Promise.all([
    database
      .prepare(`SELECT j.subject_digest, j.logical_image_ref, j.installation_id, j.repository_id,
        j.status, j.next_descriptor, j.saw_spdx, j.attempted_at, j.error, j.created_at
      FROM github_ingestion_jobs j ${SOURCE_JOIN}
      WHERE g.org_id = ? AND (? IS NULL OR j.status = ?)
      ORDER BY j.created_at DESC LIMIT ?`)
      .bind(tenantId, filters.status, filters.status, filters.limit)
      .all(),
    database
      .prepare(`SELECT job_id, ecosystem, advisory_id, modified_at, status, attempted_at, error
      FROM osv_advisory_jobs WHERE (? IS NULL OR status = ?)
      ORDER BY COALESCE(attempted_at, 0) DESC, job_id LIMIT ?`)
      .bind(filters.status, filters.status, filters.limit)
      .all(),
    database
      .prepare(`SELECT delivery_id, logical_image_ref, package_name, ecosystem, version, vuln_id,
        status, attempted_at, error, created_at
      FROM dispatch_deliveries WHERE org_id = ? AND (? IS NULL OR status = ?)
      ORDER BY created_at DESC LIMIT ?`)
      .bind(tenantId, filters.status, filters.status, filters.limit)
      .all(),
    database
      .prepare(`SELECT m.vuln_id, m.reason, m.created_at, c.package_name, c.ecosystem, c.version
      FROM matching_errors m JOIN components c ON c.id = m.component_id JOIN sboms s ON s.id = c.sbom_id
      WHERE s.org_id = ? ORDER BY m.created_at DESC LIMIT ?`)
      .bind(tenantId, filters.limit)
      .all(),
  ]);
  return {
    ingestion: ingestion.results,
    advisories: advisories.results,
    dispatch: dispatch.results,
    matching_errors: matching.results,
  };
}

export type SourceRow = {
  readonly installation_id: string;
  readonly repository_id: string;
  readonly dispatch_workflow: string | null;
  readonly dispatch_ref: string | null;
  readonly created_at: number;
  readonly sboms: number;
  readonly pending_jobs: number;
};

export async function sources(
  database: D1Database,
  tenantId: TenantId,
): Promise<readonly SourceRow[]> {
  const result = await database
    .prepare(`SELECT g.installation_id, g.repository_id, g.dispatch_workflow, g.dispatch_ref, g.created_at,
      (SELECT COUNT(*) FROM sboms s WHERE s.installation_id = g.installation_id AND s.repository_id = g.repository_id) AS sboms,
      (SELECT COUNT(*) FROM github_ingestion_jobs j WHERE j.installation_id = g.installation_id AND j.repository_id = g.repository_id AND j.status = 'pending') AS pending_jobs
    FROM github_sources g WHERE g.org_id = ? ORDER BY g.created_at LIMIT 200`)
    .bind(tenantId)
    .all<SourceRow>();
  return result.results;
}
