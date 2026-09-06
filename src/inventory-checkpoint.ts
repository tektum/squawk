import { sha256 } from "./digest";
import { ecosystemFamily } from "./advisory-jobs";
import { currentInventoryGeneration, type InventoryImageKey } from "./inventory-generation";
import type { InventoryCandidate, ReconciliationReason } from "./reconciliation-contract";

type ImageKey = InventoryImageKey;

const sha256Hex = /^[a-f0-9]{64}$/;

const digestReference = /^(.+)@sha256:[a-f0-9]{64}$/;
const expectedPlatforms = ["linux/amd64", "linux/arm64"] as const;
const freshnessMilliseconds = 6 * 60 * 60_000;

export async function buildInventoryCandidate(
  database: D1Database,
  image: ImageKey,
  now: number,
): Promise<InventoryCandidate> {
  const generation = await currentInventoryGeneration(database, image);
  const sboms = (
    await database
      .prepare(
        `SELECT id,image_ref,platform,predicate_sha256,backfill_status,created_at
         FROM sboms WHERE installation_id=? AND repository_id=? AND logical_image_ref=?
           AND retired_at IS NULL ORDER BY platform,image_ref,id`,
      )
      .bind(image.installation_id, image.repository_id, image.logical_image_ref)
      .all<{
        readonly id: string;
        readonly image_ref: string;
        readonly platform: string;
        readonly predicate_sha256: string;
        readonly backfill_status: string;
        readonly created_at: number;
      }>()
  ).results;
  const components = (
    await database
      .prepare(
        `SELECT c.id,c.package_name,c.ecosystem,c.version,c.matchable,s.platform,
          EXISTS(SELECT 1 FROM matching_errors m WHERE m.component_id=c.id) AS matching_error
         FROM components c JOIN sboms s ON s.id=c.sbom_id
         WHERE s.installation_id=? AND s.repository_id=? AND s.logical_image_ref=?
           AND s.retired_at IS NULL ORDER BY c.ecosystem,c.package_name,c.version,c.id`,
      )
      .bind(image.installation_id, image.repository_id, image.logical_image_ref)
      .all<{
        readonly id: number;
        readonly package_name: string;
        readonly ecosystem: string;
        readonly version: string;
        readonly matchable: number;
        readonly platform: string;
        readonly matching_error: number;
      }>()
  ).results;
  const ingestion = await database
    .prepare(
      `SELECT status,next_descriptor,saw_spdx FROM github_ingestion_jobs
       WHERE installation_id=? AND repository_id=? AND logical_image_ref=?`,
    )
    .bind(image.installation_id, image.repository_id, image.logical_image_ref)
    .first<{
      readonly status: string;
      readonly next_descriptor: number;
      readonly saw_spdx: number;
    }>();
  const baseFingerprint = JSON.stringify({ sboms, components, ingestion });
  const blocked = async (reason: ReconciliationReason, detail = "") => ({
    state: "blocked" as const,
    reason,
    fingerprint: await sha256(`${baseFingerprint}\u0000${reason}\u0000${detail}`),
    generation,
  });
  if (ingestion) return blocked("inventory_incomplete", JSON.stringify(ingestion));
  const logicalName = digestReference.exec(image.logical_image_ref)?.[1];
  if (!logicalName || sboms.length !== 2) return blocked("inventory_incomplete");
  const platforms = [] as {
    platform: "linux/amd64" | "linux/arm64";
    image_ref: string;
    sbom_sha256: string;
    indexed_at: number;
    status: "complete";
  }[];
  for (const expected of expectedPlatforms) {
    const rows = sboms.filter((sbom) => sbom.platform === expected);
    if (
      rows.length !== 1 ||
      rows[0]?.backfill_status !== "complete" ||
      rows[0].created_at > now ||
      !sha256Hex.test(rows[0]?.predicate_sha256 ?? "") ||
      digestReference.exec(rows[0].image_ref)?.[1] !== logicalName
    )
      return blocked("inventory_incomplete", expected);
    platforms.push({
      platform: expected,
      image_ref: rows[0].image_ref,
      sbom_sha256: rows[0].predicate_sha256,
      indexed_at: Math.floor(rows[0].created_at / 1000),
      status: "complete",
    });
  }
  const unsupported = components.filter(
    (component) =>
      (component.matchable !== 1 && component.ecosystem !== "unknown:oci") ||
      component.matching_error === 1,
  );
  if (unsupported.length > 0)
    return blocked(
      "unsupported_coverage",
      unsupported
        .map((component) => `${component.ecosystem}\u0000${component.package_name}`)
        .join("\u0001"),
    );
  const ecosystems = [
    ...new Set(
      components
        .filter((component) => component.matchable === 1)
        .map((component) => ecosystemFamily(component.ecosystem)),
    ),
  ].sort();
  const feedChecks: { readonly checkpoint_id: string; readonly checked_at: number }[] = [];
  for (const ecosystem of ecosystems) {
    const check = await database
      .prepare(
        `SELECT checkpoint_id,status,discovery_complete,cursor_modified_at,checked_at,completed_at
         FROM advisory_feed_checks
         WHERE ecosystem=? ORDER BY checked_at DESC,checkpoint_id DESC LIMIT 1`,
      )
      .bind(ecosystem)
      .first<{
        readonly checkpoint_id: string;
        readonly status: string;
        readonly discovery_complete: number;
        readonly cursor_modified_at: string;
        readonly checked_at: number;
        readonly completed_at: number | null;
      }>();
    if (
      !check ||
      check.status !== "complete" ||
      check.discovery_complete !== 1 ||
      check.completed_at === null
    )
      return blocked("feed_incomplete", ecosystem);
    const unfinished = await database
      .prepare(
        `SELECT 1 FROM osv_advisory_jobs
         WHERE ecosystem=? AND (status!='complete' OR modified_at>?) LIMIT 1`,
      )
      .bind(ecosystem, check.cursor_modified_at)
      .first();
    if (unfinished) return blocked("feed_incomplete", ecosystem);
    if (check.checked_at > now || now - check.checked_at > freshnessMilliseconds)
      return blocked("feed_stale", `${ecosystem}\u0000${check.checkpoint_id}`);
    feedChecks.push({ checkpoint_id: check.checkpoint_id, checked_at: check.checked_at });
  }
  const receipt = await database
    .prepare(
      `SELECT delivery_id FROM github_deliveries
       WHERE installation_id=? AND repository_id=? AND subject_digest=? AND status='accepted'
       ORDER BY completed_at DESC,created_at DESC LIMIT 1`,
    )
    .bind(
      image.installation_id,
      image.repository_id,
      image.logical_image_ref.slice(image.logical_image_ref.lastIndexOf("@") + 1),
    )
    .first<{ readonly delivery_id: string }>();
  if (!receipt) return blocked("inventory_incomplete", "missing ingestion receipt");
  const rows = (
    await database
      .prepare(
        `SELECT c.package_name,c.ecosystem,c.version,f.vuln_id,v.severity,s.platform
         FROM findings f JOIN components c ON c.id=f.component_id
         JOIN sboms s ON s.id=c.sbom_id
         JOIN vulnerabilities v ON v.id=f.vuln_id AND v.ecosystem=c.ecosystem AND v.package_name=c.package_name
         WHERE s.installation_id=? AND s.repository_id=? AND s.logical_image_ref=? AND s.retired_at IS NULL
           AND NOT EXISTS (SELECT 1 FROM vex_statements x WHERE x.id=(SELECT id FROM vex_statements
             WHERE org_id=f.org_id AND package_name=c.package_name AND ecosystem=c.ecosystem AND vuln_id=f.vuln_id
             ORDER BY created_at DESC,id DESC LIMIT 1) AND x.status IN ('not_affected','fixed'))
         ORDER BY c.ecosystem,c.package_name,c.version,f.vuln_id,s.platform`,
      )
      .bind(image.installation_id, image.repository_id, image.logical_image_ref)
      .all<{
        readonly package_name: string;
        readonly ecosystem: string;
        readonly version: string;
        readonly vuln_id: string;
        readonly severity: string | null;
        readonly platform: string;
      }>()
  ).results;
  const grouped = new Map<string, (typeof rows)[number] & { platforms: Set<string> }>();
  for (const row of rows) {
    const key = [row.package_name, row.ecosystem, row.version, row.vuln_id].join("\u0000");
    const finding = grouped.get(key) ?? { ...row, platforms: new Set<string>() };
    finding.platforms.add(row.platform);
    grouped.set(key, finding);
  }
  const findings = await Promise.all(
    [...grouped].map(async ([key, finding]) => ({
      delivery_id: await sha256(
        [image.installation_id, image.repository_id, image.logical_image_ref, key].join("\u0000"),
      ),
      package_name: finding.package_name,
      ecosystem: finding.ecosystem,
      version: finding.version,
      vuln_id: finding.vuln_id,
      severity: finding.severity,
      platforms: [...finding.platforms].sort(),
    })),
  );
  const evaluatedAt = Math.floor(now / 1000);
  const payload = {
    logical_image_ref: image.logical_image_ref,
    source: {
      installation_id: image.installation_id,
      repository_id: image.repository_id,
      ingestion_delivery_id: receipt.delivery_id,
    },
    kind: "inventory_snapshot" as const,
    coverage: {
      status: "complete" as const,
      evaluated_at: evaluatedAt,
      advisory_feed_checked_at: Math.floor(
        Math.min(...feedChecks.map((check) => check.checked_at), now) / 1000,
      ),
      feed_checkpoint_ids: feedChecks.map((check) => check.checkpoint_id).sort(),
      unsupported_components: [] as const,
    },
    platforms,
    findings,
  };
  const fingerprintPayload = {
    ...payload,
    coverage: { ...payload.coverage, evaluated_at: 0 },
  };
  return {
    state: "ready",
    fingerprint: await sha256(JSON.stringify(fingerprintPayload)),
    generation,
    payload,
  };
}
