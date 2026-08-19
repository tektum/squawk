import { backfillSbom } from "./backfill";
import { enqueueIngestion, ingestPendingImage } from "./webhook-ingestion";
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
        backfillSbom({ database: env.DB, sbomId: id, osvApiUrl: env.OSV_API_URL }),
      );
    return Response.json({ status: existing.status }, { status: 200 });
  }
  const job = {
    deliveryId,
    deploymentId: packageVersionId,
    image,
    installationId: source.installation_id,
    repositoryId,
    subjectDigest: digest,
  };
  const now = Date.now();
  await enqueueIngestion(env, job, now);
  const outcome = await ingestPendingImage(env, job, now);
  if (outcome === "ignored") return new Response(null, { status: 204 });
  return Response.json(
    { status: outcome === "complete" ? "accepted" : "pending" },
    { status: 202 },
  );
}
