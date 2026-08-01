import {
  SbomIdSchema,
  type Component,
  type SbomId,
  type TenantId,
  type UserId,
  type VexStatus,
} from "./domain";
import type { SbomInput } from "./sbom";

export type IngestResult =
  | { readonly kind: "created"; readonly sbomId: SbomId }
  | { readonly kind: "retry"; readonly sbomId: SbomId }
  | { readonly kind: "conflict" };

export async function ingestSbom(
  database: D1Database,
  tenantId: TenantId,
  input: SbomInput,
  predicateSha256: string,
  components: readonly Component[],
): Promise<IngestResult> {
  const sbomId = SbomIdSchema.parse(crypto.randomUUID());
  const now = Date.now();
  const inserted = await database
    .prepare(
      "INSERT INTO sboms (id, org_id, image_ref, logical_image_ref, platform, predicate_sha256, backfill_status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?) ON CONFLICT(org_id, image_ref, platform) DO NOTHING",
    )
    .bind(
      sbomId,
      tenantId,
      input.image_ref,
      input.logical_image_ref,
      input.platform,
      predicateSha256,
      now,
    )
    .run();
  if (inserted.meta.changes === 0) {
    const existing = await database
      .prepare(
        "SELECT id, predicate_sha256 FROM sboms WHERE org_id = ? AND image_ref = ? AND platform = ?",
      )
      .bind(tenantId, input.image_ref, input.platform)
      .first<{ readonly id: string; readonly predicate_sha256: string }>();
    return existing?.predicate_sha256 === predicateSha256
      ? { kind: "retry", sbomId: SbomIdSchema.parse(existing.id) }
      : { kind: "conflict" };
  }
  const statements: D1PreparedStatement[] = [];
  for (const component of components) {
    statements.push(
      database
        .prepare(
          "INSERT INTO components (sbom_id, package_name, ecosystem, version, purl, matchable) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(
          sbomId,
          component.packageName,
          component.ecosystem,
          component.version,
          component.purl,
          Number(component.matchable),
        ),
    );
  }
  await database.batch(statements);
  return { kind: "created", sbomId };
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
  readonly image_ref: string;
  readonly logical_image_ref: string;
  readonly platform: string;
  readonly package_name: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly vuln_id: string;
  readonly severity: string | null;
  readonly summary: string | null;
  readonly vex_status: VexStatus | null;
  readonly vex_justification: string | null;
};

export async function listFindings(
  database: D1Database,
  tenantId: TenantId,
  severity: string | null,
  includeSuppressed: boolean,
  includeRetired: boolean,
): Promise<readonly Finding[]> {
  const statement = database
    .prepare(`WITH latest_vex AS (
    SELECT org_id, package_name, ecosystem, vuln_id, status, justification,
      ROW_NUMBER() OVER (PARTITION BY org_id, package_name, ecosystem, vuln_id ORDER BY created_at DESC, id DESC) AS row_number
    FROM vex_statements
  )
  SELECT s.image_ref, s.logical_image_ref, s.platform, c.package_name, c.ecosystem, c.version,
    f.vuln_id, v.severity, v.summary, x.status AS vex_status, x.justification AS vex_justification
  FROM findings f JOIN components c ON c.id = f.component_id JOIN sboms s ON s.id = c.sbom_id
  JOIN vulnerabilities v ON v.id = f.vuln_id AND v.ecosystem = c.ecosystem AND v.package_name = c.package_name
  LEFT JOIN latest_vex x ON x.row_number = 1 AND x.org_id = f.org_id AND x.package_name = c.package_name AND x.ecosystem = c.ecosystem AND x.vuln_id = f.vuln_id
  WHERE f.org_id = ? AND (? = 1 OR s.retired_at IS NULL) AND (? IS NULL OR v.severity = ?)
    AND (? = 1 OR COALESCE(x.status, '') NOT IN ('not_affected', 'fixed'))`)
    .bind(tenantId, Number(includeRetired), severity, severity, Number(includeSuppressed));
  return (await statement.all<Finding>()).results;
}
