import { createRemoteJWKSet, jwtVerify } from "jose";
import type { z } from "zod";
import { backfillSbom } from "./backfill";
import { GitHubApiError } from "./github";
import { ingestSbom } from "./repository";
import { parsePredicate, sbomInputSchema } from "./sbom";
import { statementFor } from "./webhook-attestation";
import {
  audience,
  claimsSchema,
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
      "SELECT org_id,workflow,ref FROM github_sources WHERE installation_id=? AND repository_id=?",
    )
      .bind(installationId, repositoryId)
      .first(),
  );
  if (source.ref !== event.deployment.ref) throw new WebhookError(403, "untrusted source");
  const verified = await jwtVerify(
    event.deployment.payload.oidc_token,
    createRemoteJWKSet(new URL(env.GH_OIDC_JWKS_URL), { cooldownDuration: 0 }),
    {
      issuer: env.GH_OIDC_ISSUER,
      audience: audience(event.deployment.payload, repositoryId, event.deployment.sha),
      algorithms: ["RS256"],
      clockTolerance: 5,
    },
  );
  const claims = claimsSchema.parse(verified.payload);
  if (
    claims.repository_id !== repositoryId ||
    claims.repository !== event.repository.full_name ||
    claims.ref !== source.ref ||
    claims.workflow_sha !== event.deployment.sha ||
    claims.job_workflow_ref !== `${event.repository.full_name}/${source.workflow}@${source.ref}` ||
    claims.sub !== `repo:${event.repository.full_name}:ref:${source.ref}`
  )
    throw new WebhookError(403, "untrusted identity");
  const existing = await env.DB.prepare(
    "SELECT statement_sha256,status FROM github_deliveries WHERE delivery_id=?",
  )
    .bind(deliveryId)
    .first<{ readonly statement_sha256: string; readonly status: string }>();
  if (existing) {
    if (existing.statement_sha256 !== event.deployment.payload.statement_sha256)
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
      candidate.name === event.deployment.payload.image &&
      candidate.digest.sha256 === event.deployment.payload.image_digest.slice(7),
  );
  if (!subject) throw new WebhookError(400, "wrong subject");
  const input = sbomInputSchema.parse({
    image_ref: `${event.deployment.payload.image}@${event.deployment.payload.image_digest}`,
    logical_image_ref: `${event.deployment.payload.image}@${event.deployment.payload.index_digest}`,
    platform: event.deployment.payload.platform,
    idempotency_key: event.deployment.payload.statement_sha256,
    predicate: statement.predicate,
  });
  const components = parsePredicate(statement.predicate);
  const now = Date.now();
  const result = await ingestSbom(env.DB, source.org_id, input, input.idempotency_key, components);
  if (result.kind === "conflict") {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO github_deliveries (delivery_id,installation_id,repository_id,statement_sha256,status,created_at,completed_at) VALUES (?,?,?,?, 'rejected',?,?)",
    )
      .bind(
        deliveryId,
        installationId,
        repositoryId,
        event.deployment.payload.statement_sha256,
        now,
        now,
      )
      .run();
    throw new WebhookError(409, "conflicting platform submission");
  }
  await env.DB.prepare(
    "INSERT OR IGNORE INTO github_deliveries (delivery_id,installation_id,repository_id,statement_sha256,status,created_at,completed_at) VALUES (?,?,?,?, 'accepted',?,?)",
  )
    .bind(
      deliveryId,
      installationId,
      repositoryId,
      event.deployment.payload.statement_sha256,
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
