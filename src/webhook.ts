import { backfillSbom } from "./backfill";
import { sha256 } from "./digest";
import { statementsForImage } from "./registry-attestation";
import { ingestSboms } from "./repository";
import { imageIdentityFromPredicate, parsePredicate, sbomInputSchema } from "./sbom";
import { parseWebhook, sourceSchema, type WebhookEnv, WebhookError } from "./webhook-contract";

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
    const pending = await env.DB.prepare(
      "SELECT id FROM sboms WHERE org_id=? AND logical_image_ref=? AND retired_at IS NULL AND backfill_status IN ('pending','failed')",
    )
      .bind(source.org_id, `${image}@${digest}`)
      .all<{ readonly id: string }>();
    for (const { id } of pending.results)
      env.EXECUTION_CONTEXT.waitUntil(
        backfillSbom({ database: env.DB, sbomId: id, osvBaseUrl: env.OSV_BASE_URL }),
      );
    return Response.json({ status: existing.status }, { status: 200 });
  }
  const statements = await statementsForImage(image, digest);
  if (statements.length === 0) return new Response(null, { status: 204 });
  const now = Date.now();
  const requests = await Promise.all(
    statements.map(async (statement) => {
      const identity = imageIdentityFromPredicate(statement.predicate);
      if (!identity) return null;
      const input = sbomInputSchema.parse({
        image_ref: `${image}@${identity.imageDigest}`,
        logical_image_ref: `${image}@${digest}`,
        platform: identity.platform,
        idempotency_key: `${digest}:${identity.platform}`,
        predicate: statement.predicate,
      });
      return {
        input,
        components: parsePredicate(statement.predicate),
        predicateSha256: await sha256(JSON.stringify(statement.predicate)),
      };
    }),
  );
  const platformRequests = requests.filter((request) => request !== null);
  if (platformRequests.length === 0) return new Response(null, { status: 204 });
  const uniqueRequests = platformRequests.filter(
    (request, index) =>
      platformRequests.findIndex(
        (candidate) =>
          candidate.input.image_ref === request.input.image_ref &&
          candidate.input.platform === request.input.platform,
      ) === index,
  );
  const result = await ingestSboms(env.DB, source.org_id, uniqueRequests);
  if (result.kind === "conflict") throw new WebhookError(409, "conflicting platform submission");
  for (const sbomId of result.createdSbomIds)
    env.EXECUTION_CONTEXT.waitUntil(
      backfillSbom({ database: env.DB, sbomId, osvBaseUrl: env.OSV_BASE_URL }),
    );
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
    { sbom_ids: result.sbomIds, status: result.kind === "created" ? "pending" : "complete" },
    { status: result.kind === "created" ? 202 : 200 },
  );
}
