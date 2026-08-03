import type { z } from "zod";
import { backfillSbom } from "./backfill";
import { GitHubApiError } from "./github";
import { ingestSbom } from "./repository";
import { parsePredicate, sbomInputSchema } from "./sbom";
import { statementFor } from "./webhook-attestation";
import {
  parseWebhook,
  sourceSchema,
  type statementSchema,
  WebhookError,
  type WebhookEnv,
} from "./webhook-contract";

export { WebhookError } from "./webhook-contract";

export async function handleGithubWebhook(request: Request, env: WebhookEnv): Promise<Response> {
  const { deliveryId, event } = await parseWebhook(request, env.GH_WEBHOOK_SECRET);
  const installationId = String(event.installation.id);
  const repositoryId = String(event.repository.id);
  const source = sourceSchema.parse(
    await env.DB.prepare(
      "SELECT org_id FROM github_sources WHERE installation_id=? AND repository_id=?",
    )
      .bind(installationId, repositoryId)
      .first(),
  );
  const deploymentId = String(event.deployment.id);
  const existing = await env.DB.prepare(
    "SELECT COALESCE(subject_digest,statement_sha256) AS subject_digest,status FROM github_deliveries WHERE delivery_id=? OR deployment_id=?",
  )
    .bind(deliveryId, deploymentId)
    .first<{ readonly subject_digest: string; readonly status: string }>();
  if (existing) {
    if (existing.subject_digest !== event.deployment.payload.subject_digest)
      throw new WebhookError(409, "delivery collision");
    return Response.json({ status: existing.status }, { status: 200 });
  }
  let statement: z.infer<typeof statementSchema>;
  try {
    statement = await statementFor({
      payload: event.deployment.payload,
      repository: event.repository.full_name,
      installationId,
      repositoryId,
      env,
    });
  } catch (error) {
    if (error instanceof GitHubApiError) throw new WebhookError(502, error.message);
    throw error;
  }
  const subject = statement.subject.find(
    (candidate) =>
      candidate.name === event.deployment.payload.image_ref.split("@")[0] &&
      candidate.digest.sha256 === event.deployment.payload.subject_digest.slice(7),
  );
  if (!subject) throw new WebhookError(400, "wrong subject");
  const input = sbomInputSchema.parse({
    image_ref: event.deployment.payload.image_ref,
    logical_image_ref: event.deployment.payload.logical_image_ref,
    platform: event.deployment.payload.platform,
    idempotency_key: event.deployment.payload.subject_digest,
    predicate: statement.predicate,
  });
  const components = parsePredicate(statement.predicate);
  const now = Date.now();
  const result = await ingestSbom(env.DB, source.org_id, input, input.idempotency_key, components);
  if (result.kind === "conflict") {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO github_deliveries (delivery_id,deployment_id,installation_id,repository_id,statement_sha256,subject_digest,status,created_at,completed_at) VALUES (?,?,?,?,?,?, 'rejected',?,?)",
    )
      .bind(
        deliveryId,
        deploymentId,
        installationId,
        repositoryId,
        event.deployment.payload.subject_digest,
        event.deployment.payload.subject_digest,
        now,
        now,
      )
      .run();
    throw new WebhookError(409, "conflicting platform submission");
  }
  await env.DB.prepare(
    "INSERT OR IGNORE INTO github_deliveries (delivery_id,deployment_id,installation_id,repository_id,statement_sha256,subject_digest,status,created_at,completed_at) VALUES (?,?,?,?,?,?, 'accepted',?,?)",
  )
    .bind(
      deliveryId,
      deploymentId,
      installationId,
      repositoryId,
      event.deployment.payload.subject_digest,
      event.deployment.payload.subject_digest,
      now,
      now,
    )
    .run();
  if (result.kind === "created")
    env.EXECUTION_CONTEXT.waitUntil(
      backfillSbom({ database: env.DB, sbomId: result.sbomId, osvBaseUrl: env.OSV_BASE_URL }),
    );
  return Response.json(
    { sbom_id: result.sbomId, status: result.kind === "created" ? "pending" : "complete" },
    { status: result.kind === "created" ? 202 : 200 },
  );
}
