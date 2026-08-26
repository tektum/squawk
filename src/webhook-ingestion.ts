import { backfillSbom } from "./backfill";
import type { SubrequestBudget } from "./budget";
import { sha256 } from "./digest";
import { TenantIdSchema } from "./domain";
import { statementsForImage } from "./registry-attestation";
import { ingestSboms } from "./repository";
import { imageIdentityFromPredicate, parsePredicate, sbomInputSchema } from "./sbom";
import type { WebhookEnv } from "./webhook-contract";
import { WebhookError } from "./webhook-contract";

export type IngestionJob = {
  readonly deliveryId?: string;
  readonly deploymentId?: string;
  readonly image: string;
  readonly installationId: string;
  readonly nextDescriptor?: number;
  readonly sawSpdx?: boolean;
  readonly repositoryId: string;
  readonly subjectDigest: string;
};

export async function enqueueIngestion(env: WebhookEnv, job: IngestionJob, now = Date.now()) {
  await env.DB.prepare(
    "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,delivery_id,deployment_id,status,created_at) VALUES (?,?,?,?,?,?,'pending',?) ON CONFLICT(installation_id,repository_id,subject_digest) DO UPDATE SET delivery_id=COALESCE(excluded.delivery_id,delivery_id),deployment_id=COALESCE(excluded.deployment_id,deployment_id),status='pending',error=NULL",
  )
    .bind(
      job.subjectDigest,
      job.installationId,
      job.repositoryId,
      `${job.image}@${job.subjectDigest}`,
      job.deliveryId ?? null,
      job.deploymentId ?? null,
      now,
    )
    .run();
}
/**
 * Records an accepted ingestion delivery and removes the corresponding ingestion job.
 *
 * Also stamps provenance on SBOM rows for this image that were ingested before SBOMs
 * recorded their source, so images published before that column existed become
 * routable once seen again.
 *
 * @param job - The ingestion job to finalize
 * @param orgId - The organization resolved for this run, so the stamp and the ingested
 *   SBOMs agree on one owner even if the source is reassigned mid-run
 * @param now - The timestamp to use for delivery creation and completion
 */
async function finishIngestion(
  env: Pick<WebhookEnv, "DB">,
  job: IngestionJob,
  orgId: string,
  now: number,
) {
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO github_deliveries (delivery_id,deployment_id,installation_id,repository_id,statement_sha256,subject_digest,status,created_at,completed_at) VALUES (?,?,?,?,?,?,'accepted',?,?)",
    ).bind(
      job.deliveryId ?? crypto.randomUUID(),
      job.deploymentId ?? null,
      job.installationId,
      job.repositoryId,
      job.subjectDigest,
      job.subjectDigest,
      now,
      now,
    ),
    env.DB.prepare(
      "DELETE FROM github_ingestion_jobs WHERE installation_id=? AND repository_id=? AND subject_digest=?",
    ).bind(job.installationId, job.repositoryId, job.subjectDigest),
    env.DB.prepare(
      `UPDATE sboms SET installation_id=?, repository_id=? WHERE installation_id IS NULL
       AND repository_id IS NULL AND logical_image_ref=? AND org_id=?`,
    ).bind(job.installationId, job.repositoryId, `${job.image}@${job.subjectDigest}`, orgId),
  ]);
}

/**
 * Processes a pending image ingestion job and advances it through registry discovery and SBOM ingestion.
 *
 * @param job - The pending image ingestion job to process
 * @param now - Timestamp used to record the processing attempt
 * @param budget - Optional limit for registry and backfill subrequests
 * @returns `"pending"` if more registry results remain, `"ignored"` if the job has no usable statements, or `"complete"` when ingestion finishes
 * @throws WebhookError If the repository is not configured, a matching SPDX statement is missing, or platform submissions conflict
 */
export async function ingestPendingImage(
  env: Pick<WebhookEnv, "DB" | "OSV_API_URL" | "OSV_BASE_URL" | "GHCR_URL"> & {
    readonly EXECUTION_CONTEXT?: ExecutionContext;
  },
  job: IngestionJob,
  now = Date.now(),
  budget?: SubrequestBudget,
) {
  const source = await env.DB.prepare(
    "SELECT org_id FROM github_sources WHERE installation_id=? AND repository_id=?",
  )
    .bind(job.installationId, job.repositoryId)
    .first<{ readonly org_id: string }>();
  if (!source) throw new WebhookError(403, "wrong repository");
  const registry = await statementsForImage(
    job.image,
    job.subjectDigest,
    budget,
    job.nextDescriptor,
    env.GHCR_URL,
  );
  const sawSpdx = (job.sawSpdx ?? false) || registry.sawStatement;
  const statements = registry.statements;
  if (statements.length === 0) {
    if (!registry.complete) {
      await env.DB.prepare(
        "UPDATE github_ingestion_jobs SET next_descriptor=?,saw_spdx=?,status='pending',attempted_at=?,error=NULL WHERE installation_id=? AND repository_id=? AND subject_digest=?",
      )
        .bind(
          registry.nextDescriptor,
          sawSpdx ? 1 : 0,
          now,
          job.installationId,
          job.repositoryId,
          job.subjectDigest,
        )
        .run();
      return "pending" as const;
    }
    if (sawSpdx) throw new WebhookError(400, "matching statement not found");
    const ingested = await env.DB.prepare(
      "SELECT 1 FROM sboms WHERE logical_image_ref=? AND retired_at IS NULL LIMIT 1",
    )
      .bind(`${job.image}@${job.subjectDigest}`)
      .first();
    if (ingested) {
      await finishIngestion(env, job, source.org_id, now);
      return "complete" as const;
    }
    await env.DB.prepare(
      "DELETE FROM github_ingestion_jobs WHERE installation_id=? AND repository_id=? AND subject_digest=?",
    )
      .bind(job.installationId, job.repositoryId, job.subjectDigest)
      .run();
    return "ignored" as const;
  }
  const requests = await Promise.all(
    statements.map(async (statement) => {
      const identity = imageIdentityFromPredicate(statement.predicate);
      if (!identity) return null;
      const input = sbomInputSchema.parse({
        image_ref: `${job.image}@${identity.imageDigest}`,
        logical_image_ref: `${job.image}@${job.subjectDigest}`,
        platform: identity.platform,
        idempotency_key: `${job.subjectDigest}:${identity.platform}`,
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
  if (platformRequests.length === 0) {
    if (!registry.complete) {
      await env.DB.prepare(
        "UPDATE github_ingestion_jobs SET next_descriptor=?,saw_spdx=?,status='pending',attempted_at=?,error=NULL WHERE installation_id=? AND repository_id=? AND subject_digest=?",
      )
        .bind(
          registry.nextDescriptor,
          sawSpdx ? 1 : 0,
          now,
          job.installationId,
          job.repositoryId,
          job.subjectDigest,
        )
        .run();
      return "pending" as const;
    }
    await env.DB.prepare(
      "DELETE FROM github_ingestion_jobs WHERE installation_id=? AND repository_id=? AND subject_digest=?",
    )
      .bind(job.installationId, job.repositoryId, job.subjectDigest)
      .run();
    return "ignored" as const;
  }
  const uniqueRequests = platformRequests.filter(
    (request, index) =>
      platformRequests.findIndex(
        (candidate) =>
          candidate.input.image_ref === request.input.image_ref &&
          candidate.input.platform === request.input.platform,
      ) === index,
  );
  const result = await ingestSboms(env.DB, TenantIdSchema.parse(source.org_id), uniqueRequests, {
    installationId: job.installationId,
    repositoryId: job.repositoryId,
  });
  if (result.kind === "conflict") throw new WebhookError(409, "conflicting platform submission");
  if (!registry.complete) {
    await env.DB.prepare(
      "UPDATE github_ingestion_jobs SET next_descriptor=?,saw_spdx=?,status='pending',attempted_at=?,error=NULL WHERE installation_id=? AND repository_id=? AND subject_digest=?",
    )
      .bind(
        registry.nextDescriptor,
        sawSpdx ? 1 : 0,
        now,
        job.installationId,
        job.repositoryId,
        job.subjectDigest,
      )
      .run();
  }
  await finishIngestion(env, job, source.org_id, now);
  const backfills = result.createdSbomIds.map((sbomId) =>
    backfillSbom({
      database: env.DB,
      sbomId,
      osvApiUrl: env.OSV_API_URL,
      osvBaseUrl: env.OSV_BASE_URL,
      ...(budget ? { budget } : {}),
    }),
  );
  if (env.EXECUTION_CONTEXT)
    for (const backfill of backfills) env.EXECUTION_CONTEXT.waitUntil(backfill);
  else await Promise.all(backfills);
  return "complete" as const;
}
