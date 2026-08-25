import {
  type Component,
  type SbomId,
  SbomIdSchema,
  type TenantId,
  type UserId,
  type VexStatus,
} from "./domain";
import type { SbomInput } from "./sbom";

export type IngestResult =
  | { readonly kind: "created"; readonly sbomId: SbomId }
  | { readonly kind: "retry"; readonly sbomId: SbomId }
  | { readonly kind: "conflict" };

export type IngestRequest = {
  readonly components: readonly Component[];
  readonly input: SbomInput;
  readonly predicateSha256: string;
};

type IngestManyResult =
  | {
      readonly kind: "created" | "retry";
      readonly createdSbomIds: readonly SbomId[];
      readonly sbomIds: readonly SbomId[];
    }
  | { readonly kind: "conflict" };

async function loadExisting(database: D1Database, tenantId: TenantId, request: IngestRequest) {
  const existing = await database
    .prepare(
      "SELECT id, predicate_sha256 FROM sboms WHERE org_id = ? AND image_ref = ? AND platform = ?",
    )
    .bind(tenantId, request.input.image_ref, request.input.platform)
    .first<{ readonly id: string; readonly predicate_sha256: string }>();
  if (!existing) return null;
  return existing.predicate_sha256 === request.predicateSha256
    ? { kind: "retry" as const, sbomId: SbomIdSchema.parse(existing.id) }
    : { kind: "conflict" as const };
}

export type IngestSource = {
  readonly installationId: string;
  readonly repositoryId: string;
};

export async function ingestSboms(
  database: D1Database,
  tenantId: TenantId,
  requests: readonly IngestRequest[],
  source?: IngestSource,
): Promise<IngestManyResult> {
  const prepared: {
    readonly current: Exclude<IngestResult, { readonly kind: "conflict" }> | null;
    readonly request: IngestRequest;
    readonly sbomId: SbomId;
  }[] = [];
  for (const request of requests) {
    const current = await loadExisting(database, tenantId, request);
    if (current?.kind === "conflict") return current;
    prepared.push({
      request,
      current,
      sbomId: current?.sbomId ?? SbomIdSchema.parse(crypto.randomUUID()),
    });
  }
  const statements: D1PreparedStatement[] = [];
  for (const item of prepared.filter((candidate) => !candidate.current)) {
    statements.push(
      database
        .prepare(
          "INSERT INTO sboms (id, org_id, image_ref, logical_image_ref, platform, predicate_sha256, backfill_status, created_at, installation_id, repository_id) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
        )
        .bind(
          item.sbomId,
          tenantId,
          item.request.input.image_ref,
          item.request.input.logical_image_ref,
          item.request.input.platform,
          item.request.predicateSha256,
          Date.now(),
          source?.installationId ?? null,
          source?.repositoryId ?? null,
        ),
    );
    for (const component of item.request.components)
      statements.push(
        database
          .prepare(
            "INSERT INTO components (sbom_id, package_name, ecosystem, version, purl, matchable) VALUES (?, ?, ?, ?, ?, ?)",
          )
          .bind(
            item.sbomId,
            component.packageName,
            component.ecosystem,
            component.version,
            component.purl,
            Number(component.matchable),
          ),
      );
  }
  if (statements.length === 0)
    return { kind: "retry", createdSbomIds: [], sbomIds: prepared.map((item) => item.sbomId) };
  try {
    await database.batch(statements);
  } catch (error) {
    const raced = [];
    for (const request of requests) {
      const current = await loadExisting(database, tenantId, request);
      if (current?.kind === "conflict") return current;
      if (!current) throw error;
      raced.push(current.sbomId);
    }
    return { kind: "retry", createdSbomIds: [], sbomIds: raced };
  }
  return {
    kind: "created",
    createdSbomIds: prepared.filter((item) => !item.current).map((item) => item.sbomId),
    sbomIds: prepared.map((item) => item.sbomId),
  };
}

export async function ingestSbom(
  database: D1Database,
  tenantId: TenantId,
  input: SbomInput,
  predicateSha256: string,
  components: readonly Component[],
): Promise<IngestResult> {
  const result = await ingestSboms(database, tenantId, [{ input, predicateSha256, components }]);
  if (result.kind === "conflict") return result;
  return { kind: result.kind, sbomId: SbomIdSchema.parse(result.sbomIds[0]) };
}

export async function retireSbom(
  database: D1Database,
  tenantId: TenantId,
  sbomId: SbomId,
): Promise<boolean> {
  const result = await database
    .prepare("UPDATE sboms SET retired_at = COALESCE(retired_at, ?) WHERE id = ? AND org_id = ?")
    .bind(Date.now(), sbomId, tenantId)
    .run();
  return result.meta.changes > 0;
}

export async function appendVex(
  database: D1Database,
  tenantId: TenantId,
  userId: UserId,
  input: {
    readonly packageName: string;
    readonly ecosystem: string;
    readonly vulnId: string;
    readonly status: VexStatus;
    readonly justification?: string;
  },
): Promise<void> {
  await database
    .prepare(
      "INSERT INTO vex_statements (org_id, package_name, ecosystem, vuln_id, status, justification, created_by_descope_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      tenantId,
      input.packageName,
      input.ecosystem,
      input.vulnId,
      input.status,
      input.justification ?? null,
      userId,
      Date.now(),
    )
    .run();
}

export type Finding = {
  readonly sbom_id: string;
  readonly image_ref: string;
  readonly logical_image_ref: string;
  readonly platform: string;
  readonly package_name: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly vuln_id: string;
  readonly severity: string | null;
  readonly summary: string | null;
  readonly detected_at: number;
  readonly dispatched_at: number | null;
  readonly vex_status: VexStatus | null;
  readonly vex_justification: string | null;
};

export type FindingFilters = {
  readonly severity: string | null;
  readonly includeSuppressed: boolean;
  readonly includeRetired: boolean;
  readonly image?: string;
  readonly limit?: number;
  readonly offset?: number;
};

export async function listFindings(
  database: D1Database,
  tenantId: TenantId,
  filters: FindingFilters,
): Promise<readonly Finding[]> {
  const statement = database
    .prepare(`WITH latest_vex AS (
    SELECT org_id, package_name, ecosystem, vuln_id, status, justification,
      ROW_NUMBER() OVER (PARTITION BY org_id, package_name, ecosystem, vuln_id ORDER BY created_at DESC, id DESC) AS row_number
    FROM vex_statements
  )
  SELECT s.id AS sbom_id, s.image_ref, s.logical_image_ref, s.platform, c.package_name, c.ecosystem, c.version,
    f.vuln_id, v.severity, v.summary, f.detected_at, f.dispatched_at,
    x.status AS vex_status, x.justification AS vex_justification
  FROM findings f JOIN components c ON c.id = f.component_id JOIN sboms s ON s.id = c.sbom_id
  JOIN vulnerabilities v ON v.id = f.vuln_id AND v.ecosystem = c.ecosystem AND v.package_name = c.package_name
  LEFT JOIN latest_vex x ON x.row_number = 1 AND x.org_id = f.org_id AND x.package_name = c.package_name AND x.ecosystem = c.ecosystem AND x.vuln_id = f.vuln_id
  WHERE f.org_id = ? AND (? = 1 OR s.retired_at IS NULL) AND (? IS NULL OR v.severity = ?)
    AND (? = 1 OR COALESCE(x.status, '') NOT IN ('not_affected', 'fixed'))
    AND (? IS NULL OR s.logical_image_ref = ?)
  ORDER BY f.detected_at DESC, f.vuln_id LIMIT ? OFFSET ?`)
    .bind(
      tenantId,
      Number(filters.includeRetired),
      filters.severity,
      filters.severity,
      Number(filters.includeSuppressed),
      filters.image ?? null,
      filters.image ?? null,
      filters.limit ?? 1000,
      filters.offset ?? 0,
    );
  return (await statement.all<Finding>()).results;
}
