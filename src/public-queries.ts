import type { CountsByKey } from "./admin-queries";

/* Reads for the unauthenticated public surface. The disclosure clock is the pipeline
   itself: a finding becomes public only once it has been delivered downstream
   (`dispatched_at` set) and VEX has not adjudicated it `not_affected` or `fixed`.
   Pipeline internals stay out entirely: no undispatched counts, matching errors,
   backfill errors, job states, delivery targets, or installation ids. */

const LATEST_VEX = `latest_vex AS (
  SELECT org_id, package_name, ecosystem, vuln_id, status,
    ROW_NUMBER() OVER (PARTITION BY org_id, package_name, ecosystem, vuln_id ORDER BY created_at DESC, id DESC) AS row_number
  FROM vex_statements
)`;

/* Mirrors repository.listFindings: a LEFT JOIN keeps findings without any VEX
   statement, and the COALESCE drops only the adjudicated-not-vulnerable ones. */
const DISCLOSED = `f.dispatched_at IS NOT NULL AND COALESCE(x.status, '') NOT IN ('not_affected', 'fixed')`;

const VEX_JOIN = `LEFT JOIN latest_vex x ON x.row_number = 1
    AND x.org_id = f.org_id AND x.package_name = c.package_name
    AND x.ecosystem = c.ecosystem AND x.vuln_id = f.vuln_id`;

export type PublicTotals = {
  readonly images: number;
  readonly components: number;
  readonly matchable_components: number;
  readonly findings: number;
  readonly vulnerabilities: number;
  readonly ecosystems: number;
  readonly latest_sbom_at: number | null;
};

export type PublicOverview = {
  readonly totals: PublicTotals;
  readonly severity: CountsByKey;
};

type PublicPlatform = PublicImageDetail["platforms"][number];
type PublicComponent = PublicImageDetail["components"][number];
type PublicFinding = PublicImageDetail["findings"][number];

export async function publicOverview(database: D1Database): Promise<PublicOverview> {
  const [totals, severity] = await Promise.all([
    database
      .prepare(`WITH ${LATEST_VEX} SELECT
      (SELECT COUNT(DISTINCT s.logical_image_ref) FROM sboms s
        WHERE s.retired_at IS NULL AND s.logical_image_ref GLOB '*@sha256:[0-9a-f]*'
          AND length(substr(s.logical_image_ref, instr(s.logical_image_ref, '@sha256:') + 8)) = 64) AS images,
      (SELECT COUNT(*) FROM components c JOIN sboms s ON s.id = c.sbom_id
        WHERE s.retired_at IS NULL AND s.logical_image_ref GLOB '*@sha256:[0-9a-f]*'
          AND length(substr(s.logical_image_ref, instr(s.logical_image_ref, '@sha256:') + 8)) = 64) AS components,
      (SELECT COUNT(*) FROM components c JOIN sboms s ON s.id = c.sbom_id
        WHERE s.retired_at IS NULL AND c.matchable = 1 AND s.logical_image_ref GLOB '*@sha256:[0-9a-f]*'
          AND length(substr(s.logical_image_ref, instr(s.logical_image_ref, '@sha256:') + 8)) = 64) AS matchable_components,
      (SELECT COUNT(DISTINCT s.logical_image_ref || char(0) || f.vuln_id || char(0) || c.package_name || char(0) || c.ecosystem)
        FROM findings f
        JOIN components c ON c.id = f.component_id
        JOIN sboms s ON s.id = c.sbom_id
        ${VEX_JOIN}
        WHERE s.retired_at IS NULL AND ${DISCLOSED}
          AND s.logical_image_ref GLOB '*@sha256:[0-9a-f]*'
          AND length(substr(s.logical_image_ref, instr(s.logical_image_ref, '@sha256:') + 8)) = 64) AS findings,
      (SELECT COUNT(*) FROM vulnerabilities) AS vulnerabilities,
      (SELECT COUNT(*) FROM osv_ecosystems) AS ecosystems,
      (SELECT MAX(s.created_at) FROM sboms s WHERE s.retired_at IS NULL
        AND s.logical_image_ref GLOB '*@sha256:[0-9a-f]*'
        AND length(substr(s.logical_image_ref, instr(s.logical_image_ref, '@sha256:') + 8)) = 64) AS latest_sbom_at`)
      .first<PublicTotals>(),
    database
      .prepare(`WITH ${LATEST_VEX} SELECT COALESCE(v.severity, 'unknown') AS key,
      COUNT(DISTINCT s.logical_image_ref || char(0) || f.vuln_id || char(0) || c.package_name || char(0) || c.ecosystem) AS total
    FROM findings f
    JOIN components c ON c.id = f.component_id
    JOIN sboms s ON s.id = c.sbom_id
    LEFT JOIN vulnerabilities v ON v.id = f.vuln_id AND v.ecosystem = c.ecosystem AND v.package_name = c.package_name
    ${VEX_JOIN}
    WHERE s.retired_at IS NULL AND ${DISCLOSED}
      AND s.logical_image_ref GLOB '*@sha256:[0-9a-f]*'
      AND length(substr(s.logical_image_ref, instr(s.logical_image_ref, '@sha256:') + 8)) = 64
    GROUP BY key`)
      .all<{ readonly key: string; readonly total: number }>(),
  ]);
  if (!totals) throw new Error("Public overview aggregation returned no row");
  return {
    totals,
    severity: Object.fromEntries(severity.results.map((row) => [row.key, row.total])),
  };
}

export type PublicImageRow = {
  readonly image_ref: string;
  readonly platforms: string | null;
  readonly components: number;
  readonly findings: number;
  readonly status: string;
  readonly created_at: number;
};

export async function publicImages(
  database: D1Database,
  filters: { search: string; limit: number; offset: number },
): Promise<readonly PublicImageRow[]> {
  const result = await database
    .prepare(`WITH ${LATEST_VEX}, visible AS (
      SELECT f.component_id, f.vuln_id
      FROM findings f
      JOIN components c ON c.id = f.component_id
      ${VEX_JOIN}
      WHERE ${DISCLOSED}
    )
    SELECT s.logical_image_ref AS image_ref,
      GROUP_CONCAT(DISTINCT s.platform) AS platforms,
      COUNT(DISTINCT c.id) AS components,
      COUNT(DISTINCT v.vuln_id || char(0) || v.component_id) AS findings,
      CASE WHEN SUM(s.backfill_status != 'complete') = 0 THEN 'indexed' ELSE 'processing' END AS status,
      MAX(s.created_at) AS created_at
    FROM sboms s
    LEFT JOIN components c ON c.sbom_id = s.id
    LEFT JOIN visible v ON v.component_id = c.id
    WHERE s.retired_at IS NULL
      AND s.logical_image_ref GLOB '*@sha256:[0-9a-f]*'
      AND length(substr(s.logical_image_ref, instr(s.logical_image_ref, '@sha256:') + 8)) = 64
      AND (? = '' OR s.logical_image_ref LIKE '%' || ? || '%')
    GROUP BY s.logical_image_ref
    ORDER BY MAX(s.created_at) DESC LIMIT ? OFFSET ?`)
    .bind(filters.search, filters.search, filters.limit, filters.offset)
    .all<PublicImageRow>();
  return result.results;
}

export type PublicImageDetail = {
  readonly platforms: readonly {
    readonly image_ref: string;
    readonly platform: string;
    readonly status: string;
    readonly created_at: number;
  }[];
  readonly components: readonly {
    readonly package_name: string;
    readonly ecosystem: string;
    readonly version: string;
    readonly matchable: number;
  }[];
  readonly findings: readonly {
    readonly vuln_id: string;
    readonly package_name: string;
    readonly ecosystem: string;
    readonly version: string;
    readonly severity: string | null;
    readonly summary: string | null;
    readonly detected_at: number;
  }[];
};

export async function publicImageDetail(
  database: D1Database,
  reference: string,
): Promise<PublicImageDetail | null> {
  const [platforms, components, findings] = await Promise.all([
    database
      .prepare(`SELECT s.image_ref, s.platform,
        CASE WHEN s.backfill_status = 'complete' THEN 'indexed' ELSE 'processing' END AS status,
        s.created_at
      FROM sboms s
      WHERE s.retired_at IS NULL AND s.logical_image_ref = ?
        AND s.logical_image_ref GLOB '*@sha256:[0-9a-f]*'
        AND length(substr(s.logical_image_ref, instr(s.logical_image_ref, '@sha256:') + 8)) = 64
      ORDER BY s.platform LIMIT 50`)
      .bind(reference)
      .all<PublicPlatform>(),
    database
      .prepare(`SELECT c.package_name, c.ecosystem, c.version, MAX(c.matchable) AS matchable
      FROM components c JOIN sboms s ON s.id = c.sbom_id
      WHERE s.retired_at IS NULL AND s.logical_image_ref = ?
      GROUP BY c.package_name, c.ecosystem, c.version
      ORDER BY c.package_name LIMIT 500`)
      .bind(reference)
      .all<PublicComponent>(),
    database
      .prepare(`WITH ${LATEST_VEX} SELECT f.vuln_id, c.package_name, c.ecosystem, c.version,
        v.severity, v.summary, MIN(f.detected_at) AS detected_at
      FROM findings f
      JOIN components c ON c.id = f.component_id
      JOIN sboms s ON s.id = c.sbom_id
      LEFT JOIN vulnerabilities v ON v.id = f.vuln_id AND v.ecosystem = c.ecosystem AND v.package_name = c.package_name
      ${VEX_JOIN}
      WHERE s.retired_at IS NULL AND s.logical_image_ref = ? AND ${DISCLOSED}
      GROUP BY f.vuln_id, c.package_name, c.ecosystem, c.version, v.severity, v.summary
      ORDER BY detected_at DESC LIMIT 500`)
      .bind(reference)
      .all<PublicFinding>(),
  ]);
  if (platforms.results.length === 0) return null;
  return {
    platforms: platforms.results,
    components: components.results,
    findings: findings.results,
  };
}
