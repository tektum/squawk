export const reconciliationNow = 20_000_000;
export const reconciliationImage = `ghcr.io/owner/demo@sha256:${"a".repeat(64)}`;
export const reconciliationSource = {
  installation_id: "123",
  repository_id: "9",
  logical_image_ref: reconciliationImage,
};

export async function seedCompleteImage(database: D1Database): Promise<void> {
  await database.batch([
    database.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
    database.prepare(
      "INSERT INTO github_sources (installation_id,repository_id,org_id,dispatch_workflow,dispatch_ref,created_at) VALUES ('123','9','tenant','monitor.yaml','main',0)",
    ),
    database
      .prepare(
        "INSERT INTO github_deliveries (delivery_id,installation_id,repository_id,statement_sha256,status,created_at,completed_at,subject_digest) VALUES ('ingestion','123','9','statement','accepted',1,2,?)",
      )
      .bind(`sha256:${"a".repeat(64)}`),
    database
      .prepare(
        "INSERT INTO advisory_feed_checks (checkpoint_id,ecosystem,cursor_modified_at,checked_at,completed_at,discovery_complete,status) VALUES (?,'Ubuntu','2026-09-06T00:00:00Z',?,?,1,'complete')",
      )
      .bind("f".repeat(64), reconciliationNow - 2_000, reconciliationNow - 1_000),
  ]);
  for (const [index, platform] of ["linux/amd64", "linux/arm64"].entries()) {
    const sbom = `sbom-${index}`;
    await database.batch([
      database
        .prepare(
          "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at,installation_id,repository_id) VALUES (?,'tenant',?,?,?,?,'complete',1,'123','9')",
        )
        .bind(
          sbom,
          `ghcr.io/owner/demo@sha256:${String(index + 1).repeat(64)}`,
          reconciliationImage,
          platform,
          String(index + 3).repeat(64),
        ),
      database
        .prepare(
          "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (?,?,?,?,?,?,1)",
        )
        .bind(
          index + 1,
          sbom,
          "openssl",
          "Ubuntu:24.04:LTS",
          "3.0.13-0ubuntu3.15",
          `pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.15?arch=${index === 0 ? "amd64" : "arm64"}&distro=ubuntu-24.04`,
        ),
    ]);
  }
}
