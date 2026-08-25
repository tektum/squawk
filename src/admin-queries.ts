import type { TenantId } from "./domain";

/* Reads for the authenticated admin panel. Every statement is scoped by `org_id`, or by
   `github_sources.org_id` for the ingestion tables that key on installation and
   repository instead. Reference corpora (OSV advisories, ecosystems) are shared and are
   reported as totals only. */

export type CountsByKey = Readonly<Record<string, number>>;

async function counts(statement: D1PreparedStatement): Promise<CountsByKey> {
  const result = await statement.all<{ readonly key: string; readonly total: number }>();
  return Object.fromEntries(result.results.map((row) => [row.key, row.total]));
}

export type OverviewTotals = {
  readonly images: number;
  readonly retired_sboms: number;
  readonly components: number;
  readonly matchable_components: number;
  readonly findings: number;
  readonly undispatched_findings: number;
  readonly matching_errors: number;
  readonly vulnerabilities: number;
  readonly ecosystems: number;
  readonly ecosystems_cached_at: number | null;
  readonly latest_sbom_at: number | null;
  readonly latest_delivery_at: number | null;
};

export type SyncCursor = {
  readonly ecosystem: string;
  readonly last_synced_at: string;
  readonly continuation_id: string | null;
};

const SOURCE_JOIN =
  "JOIN github_sources g ON g.installation_id = j.installation_id AND g.repository_id = j.repository_id";

export async function overview(database: D1Database, tenantId: TenantId) {
  const [totals, sboms, findings, ingestion, advisories, dispatch, cursors] = await Promise.all([
    database
      .prepare(`SELECT
        (SELECT COUNT(DISTINCT logical_image_ref) FROM sboms WHERE org_id = ?1 AND retired_at IS NULL) AS images,
        (SELECT COUNT(*) FROM sboms WHERE org_id = ?1 AND retired_at IS NOT NULL) AS retired_sboms,
        (SELECT COUNT(*) FROM components c JOIN sboms s ON s.id = c.sbom_id WHERE s.org_id = ?1) AS components,
        (SELECT COUNT(*) FROM components c JOIN sboms s ON s.id = c.sbom_id WHERE s.org_id = ?1 AND c.matchable = 1) AS matchable_components,
        (SELECT COUNT(*) FROM findings WHERE org_id = ?1) AS findings,
        (SELECT COUNT(*) FROM findings WHERE org_id = ?1 AND dispatched_at IS NULL) AS undispatched_findings,
        (SELECT COUNT(*) FROM matching_errors m JOIN components c ON c.id = m.component_id JOIN sboms s ON s.id = c.sbom_id WHERE s.org_id = ?1) AS matching_errors,
        (SELECT COUNT(*) FROM vulnerabilities) AS vulnerabilities,
        (SELECT COUNT(*) FROM osv_ecosystems) AS ecosystems,
        (SELECT MAX(cached_at) FROM osv_ecosystems) AS ecosystems_cached_at,
        (SELECT MAX(created_at) FROM sboms WHERE org_id = ?1) AS latest_sbom_at,
        (SELECT MAX(d.created_at) FROM github_deliveries d JOIN github_sources g ON g.installation_id = d.installation_id AND g.repository_id = d.repository_id WHERE g.org_id = ?1 AND d.status = 'accepted') AS latest_delivery_at`)
      .bind(tenantId)
      .first<OverviewTotals>(),
    counts(
      database
        .prepare(
          "SELECT backfill_status AS key, COUNT(*) AS total FROM sboms WHERE org_id = ? AND retired_at IS NULL GROUP BY backfill_status",
        )
        .bind(tenantId),
    ),
    counts(
      database
        .prepare(`SELECT COALESCE(v.severity, 'unknown') AS key, COUNT(*) AS total
        FROM findings f JOIN components c ON c.id = f.component_id
        JOIN vulnerabilities v ON v.id = f.vuln_id AND v.ecosystem = c.ecosystem AND v.package_name = c.package_name
        WHERE f.org_id = ? GROUP BY COALESCE(v.severity, 'unknown')`)
        .bind(tenantId),
    ),
    counts(
      database
        .prepare(
          `SELECT j.status AS key, COUNT(*) AS total FROM github_ingestion_jobs j ${SOURCE_JOIN} WHERE g.org_id = ? GROUP BY j.status`,
        )
        .bind(tenantId),
    ),
    counts(
      database.prepare(
        "SELECT status AS key, COUNT(*) AS total FROM osv_advisory_jobs GROUP BY status",
      ),
    ),
    counts(
      database
        .prepare(
          "SELECT status AS key, COUNT(*) AS total FROM dispatch_deliveries WHERE org_id = ? GROUP BY status",
        )
        .bind(tenantId),
    ),
    database
      .prepare(
        "SELECT ecosystem, last_synced_at, continuation_id FROM sync_cursors ORDER BY ecosystem LIMIT 200",
      )
      .all<SyncCursor>(),
  ]);
  return {
    totals,
    sboms,
    findings,
    ingestion_jobs: ingestion,
    advisory_jobs: advisories,
    dispatch_deliveries: dispatch,
    sync_cursors: cursors.results,
  };
}

export type ImageRow = {
  readonly id: string;
  readonly image_ref: string;
  readonly logical_image_ref: string;
  readonly platform: string;
  readonly backfill_status: string;
  readonly backfill_attempted_at: number | null;
  readonly backfill_error: string | null;
  readonly created_at: number;
  readonly retired_at: number | null;
  readonly installation_id: string | null;
  readonly repository_id: string | null;
  readonly components: number;
  readonly findings: number;
};

export type ImageFilters = {
  readonly status: string | null;
  readonly search: string;
  readonly includeRetired: boolean;
  readonly limit: number;
  readonly offset: number;
};

export async function images(
  database: D1Database,
  tenantId: TenantId,
  filters: ImageFilters,
): Promise<readonly ImageRow[]> {
  const result = await database
    .prepare(`SELECT s.id, s.image_ref, s.logical_image_ref, s.platform, s.backfill_status,
      s.backfill_attempted_at, s.backfill_error, s.created_at, s.retired_at, s.installation_id, s.repository_id,
      (SELECT COUNT(*) FROM components c WHERE c.sbom_id = s.id) AS components,
      (SELECT COUNT(*) FROM findings f JOIN components c ON c.id = f.component_id WHERE c.sbom_id = s.id) AS findings
    FROM sboms s
    WHERE s.org_id = ? AND (? IS NULL OR s.backfill_status = ?) AND (? = 1 OR s.retired_at IS NULL)
      AND (? = '' OR s.logical_image_ref LIKE '%' || ? || '%')
    ORDER BY s.created_at DESC LIMIT ? OFFSET ?`)
    .bind(
      tenantId,
      filters.status,
      filters.status,
      Number(filters.includeRetired),
      filters.search,
      filters.search,
      filters.limit,
      filters.offset,
    )
    .all<ImageRow>();
  return result.results;
}

export async function imageDetail(database: D1Database, tenantId: TenantId, sbomId: string) {
  const [image, components, findings, delivery] = await Promise.all([
    database
      .prepare(`SELECT s.id, s.image_ref, s.logical_image_ref, s.platform, s.backfill_status,
        s.backfill_attempted_at, s.backfill_error, s.created_at, s.retired_at, s.installation_id, s.repository_id,
        (SELECT COUNT(*) FROM components c WHERE c.sbom_id = s.id) AS components,
        (SELECT COUNT(*) FROM findings f JOIN components c ON c.id = f.component_id WHERE c.sbom_id = s.id) AS findings
      FROM sboms s WHERE s.org_id = ? AND s.id = ?`)
      .bind(tenantId, sbomId)
      .first<ImageRow>(),
    database
      .prepare(`SELECT c.package_name, c.ecosystem, c.version, c.purl, c.matchable
        FROM components c JOIN sboms s ON s.id = c.sbom_id
        WHERE s.org_id = ? AND c.sbom_id = ? ORDER BY c.package_name LIMIT 500`)
      .bind(tenantId, sbomId)
      .all(),
    database
      .prepare(`SELECT f.vuln_id, f.detected_at, f.dispatched_at, c.package_name, c.ecosystem, c.version, v.severity, v.summary
        FROM findings f JOIN components c ON c.id = f.component_id JOIN sboms s ON s.id = c.sbom_id
        LEFT JOIN vulnerabilities v ON v.id = f.vuln_id AND v.ecosystem = c.ecosystem AND v.package_name = c.package_name
        WHERE f.org_id = ? AND c.sbom_id = ? ORDER BY f.detected_at DESC LIMIT 500`)
      .bind(tenantId, sbomId)
      .all(),
    database
      .prepare(`SELECT d.delivery_id, d.status, d.created_at, d.completed_at, d.subject_digest
        FROM github_deliveries d JOIN sboms s ON s.installation_id = d.installation_id AND s.repository_id = d.repository_id
        WHERE s.org_id = ? AND s.id = ? ORDER BY d.created_at DESC LIMIT 5`)
      .bind(tenantId, sbomId)
      .all(),
  ]);
  if (!image) return null;
  return {
    image,
    components: components.results,
    findings: findings.results,
    deliveries: delivery.results,
  };
}
