import { backfillSbom } from "./backfill";
import { statementsForImage } from "./registry-attestation";
import { ingestSbom } from "./repository";
import { imageIdentityFromPredicate, parsePredicate, sbomInputSchema } from "./sbom";
import { parseWebhook, sourceSchema, WebhookError, type WebhookEnv } from "./webhook-contract";

export { WebhookError } from "./webhook-contract";

export async function handleGithubWebhook(request: Request, env: WebhookEnv): Promise<Response> {
  const { deliveryId, event } = await parseWebhook(request, env.GH_WEBHOOK_SECRET);
  const published = event.action === "published" || event.action === "updated";
  const metadata = event.registry_package.package_version.container_metadata;
  if (
    !published ||
    event.registry_package.package_type.toLowerCase() !== "container" ||
    !metadata.tag.name ||
    metadata.tag.name.startsWith("sha256-") ||
    ![
      "application/vnd.oci.image.index.v1+json",
      "application/vnd.docker.distribution.manifest.list.v2+json",
    ].includes(metadata.manifest.media_type)
  )
    return new Response(null, { status: 204 });
  if (metadata.tag.digest !== metadata.manifest.digest)
    throw new WebhookError(400, "manifest digest mismatch");
  const repositoryId = String(event.repository.id);
  const source = sourceSchema.parse(
    await env.DB.prepare("SELECT installation_id,org_id FROM github_sources WHERE repository_id=?")
      .bind(repositoryId)
      .first(),
  );
  if (source.installation_id !== String(event.installation.id))
    throw new WebhookError(403, "wrong installation");
  const packageVersionId = String(event.registry_package.package_version.id);
  const digest = metadata.manifest.digest;
  const image = `ghcr.io/${metadata.manifest.uri.toLowerCase()}`;
  const existing = await env.DB.prepare(
    "SELECT COALESCE(subject_digest,statement_sha256) AS subject_digest,status FROM github_deliveries WHERE delivery_id=? OR deployment_id=?",
  )
    .bind(deliveryId, packageVersionId)
    .first<{ readonly subject_digest: string; readonly status: string }>();
  if (existing) {
    if (existing.subject_digest !== digest) throw new WebhookError(409, "delivery collision");
    return Response.json({ status: existing.status }, { status: 200 });
  }
  const statements = await statementsForImage(image, digest);
  if (statements.length === 0) return new Response(null, { status: 204 });
  const now = Date.now();
  const sbomIds: string[] = [];
  let created = false;
  for (const statement of statements) {
    const identity = imageIdentityFromPredicate(statement.predicate);
    const input = sbomInputSchema.parse({
      image_ref: `${image}@${identity.imageDigest}`,
      logical_image_ref: `${image}@${digest}`,
      platform: identity.platform,
      idempotency_key: `${digest}:${identity.platform}`,
      predicate: statement.predicate,
    });
    const result = await ingestSbom(
      env.DB,
      source.org_id,
      input,
      input.idempotency_key,
      parsePredicate(statement.predicate),
    );
    if (result.kind === "conflict") throw new WebhookError(409, "conflicting platform submission");
    sbomIds.push(result.sbomId);
    if (result.kind === "created") {
      created = true;
      env.EXECUTION_CONTEXT.waitUntil(
        backfillSbom({ database: env.DB, sbomId: result.sbomId, osvBaseUrl: env.OSV_BASE_URL }),
      );
    }
  }
  await env.DB.prepare(
    "INSERT OR IGNORE INTO github_deliveries (delivery_id,deployment_id,installation_id,repository_id,statement_sha256,subject_digest,status,created_at,completed_at) VALUES (?,?,?,?,?,?, 'accepted',?,?)",
  )
    .bind(
      deliveryId,
      packageVersionId,
      source.installation_id,
      repositoryId,
      digest,
      digest,
      now,
      now,
    )
    .run();
  return Response.json(
    { sbom_ids: sbomIds, status: created ? "pending" : "complete" },
    { status: created ? 202 : 200 },
  );
}
