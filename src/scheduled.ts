import { z } from "zod";
import { recordActivity } from "./activity";
import { backfillLeaseMilliseconds, backfillSbom } from "./backfill";
import { RunDeadline, SubrequestBudget } from "./budget";
import { dispatchPending } from "./dispatch";
import { describeError } from "./error-detail";
import { discoverAdvisories, requeueAdvisoryJobs } from "./sync";
import { type IngestionJob, ingestPendingImage } from "./webhook-ingestion";

type ScheduledEnv = Parameters<typeof dispatchPending>[0] &
  Parameters<typeof ingestPendingImage>[0] & {
    readonly DISPATCH_ENABLED: string;
    readonly OSV_API_URL: string;
    readonly OSV_BASE_URL: string;
    readonly OSV_ADVISORY_JOBS: Queue;
  };
const ingestionRetryDelayMilliseconds = 15 * 60_000;
/** Leaves headroom under the fifteen-minute limit Cloudflare imposes on cron runs. */
const runBudgetMilliseconds = 8 * 60_000;

/**
 * Runs the scheduled workflow and records its completion status.
 *
 * @param now - The timestamp associated with the scheduled run
 * @param deadlineMilliseconds - Wall-clock allowance before remaining work is left for the next run
 */
export async function runScheduled(
  env: ScheduledEnv,
  now = Date.now(),
  deadlineMilliseconds = runBudgetMilliseconds,
): Promise<void> {
  const deadline = new RunDeadline(Date.now(), deadlineMilliseconds);
  try {
    await executeScheduled(env, now, deadline);
    await recordActivity(env.DB, "cron", "completed", now);
  } catch (error) {
    await recordActivity(env.DB, "cron", "failed", now);
    throw error;
  }
}

/**
 * Executes scheduled ingestion, SBOM backfill, advisory synchronization, and dispatch work.
 *
 * @param now - The current timestamp in milliseconds, used for retry eligibility and lease handling.
 */
async function executeScheduled(
  env: ScheduledEnv,
  now: number,
  deadline: RunDeadline,
): Promise<void> {
  // Ingestion and matching get separate allowances: a large ingestion backlog used
  // to consume the whole budget every run, so already-ingested images were never
  // matched against OSV and no findings were produced.
  const budget = new SubrequestBudget(28);
  const matchingBudget = new SubrequestBudget(17);
  const ingestions = await env.DB.prepare(
    "SELECT delivery_id,deployment_id,installation_id,repository_id,logical_image_ref,next_descriptor,saw_spdx,subject_digest FROM github_ingestion_jobs WHERE status IN ('pending','failed') AND (attempted_at IS NULL OR attempted_at<=?) ORDER BY CASE WHEN attempted_at IS NULL THEN 0 ELSE 1 END,attempted_at,created_at LIMIT 10",
  )
    .bind(now - ingestionRetryDelayMilliseconds)
    .all<{
      readonly delivery_id: string | null;
      readonly deployment_id: string | null;
      readonly installation_id: string;
      readonly repository_id: string;
      readonly logical_image_ref: string;
      readonly next_descriptor: number;
      readonly saw_spdx: number;
      readonly subject_digest: string;
    }>();
  for (const row of ingestions.results) {
    if (budget.remaining <= 8 || deadline.expired) break;
    const job: IngestionJob = {
      ...(row.delivery_id ? { deliveryId: row.delivery_id } : {}),
      ...(row.deployment_id ? { deploymentId: row.deployment_id } : {}),
      image: row.logical_image_ref.slice(0, -row.subject_digest.length - 1),
      nextDescriptor: row.next_descriptor,
      installationId: row.installation_id,
      repositoryId: row.repository_id,
      sawSpdx: row.saw_spdx === 1,
      subjectDigest: row.subject_digest,
    };
    try {
      const outcome = await ingestPendingImage(env, job, now, budget);
      if (outcome === "pending")
        await env.DB.prepare(
          "UPDATE github_ingestion_jobs SET status='pending',attempted_at=?,error=NULL WHERE installation_id=? AND repository_id=? AND subject_digest=?",
        )
          .bind(now, row.installation_id, row.repository_id, row.subject_digest)
          .run();
    } catch (error) {
      await env.DB.prepare(
        "UPDATE github_ingestion_jobs SET status='failed',attempted_at=?,error=? WHERE installation_id=? AND repository_id=? AND subject_digest=?",
      )
        .bind(
          now,
          describeError(error).slice(0, 200),
          row.installation_id,
          row.repository_id,
          row.subject_digest,
        )
        .run();
      console.error("Scheduled GitHub ingestion failed", {
        subjectDigest: row.subject_digest,
        error: describeError(error),
      });
    }
  }
  const backfills = await env.DB.prepare(
    "SELECT id FROM sboms WHERE retired_at IS NULL AND (backfill_status IN ('pending','failed') OR (backfill_status='running' AND COALESCE(backfill_attempted_at,0)<?)) ORDER BY COALESCE(backfill_attempted_at,0),created_at LIMIT 10",
  )
    .bind(now - backfillLeaseMilliseconds)
    .all<{ readonly id: string }>();
  for (const { id } of backfills.results) {
    if (matchingBudget.remaining <= 3 || deadline.expired) break;
    try {
      await backfillSbom({
        database: env.DB,
        sbomId: id,
        osvApiUrl: env.OSV_API_URL,
        osvBaseUrl: env.OSV_BASE_URL,
        now,
        budget: matchingBudget,
        deadline,
      });
    } catch (error) {
      console.error("Scheduled backfill failed", { sbomId: id, error: describeError(error) });
    }
  }
  // Later stages issue their own requests, so an expired deadline ends the run
  // here instead of letting the remaining stages overrun the invocation.
  if (deadline.expired) return;
  const cache = await env.DB.prepare(
    "SELECT MAX(cached_at) AS cached_at FROM osv_ecosystems",
  ).first<{ readonly cached_at: number | null }>();
  if (!cache?.cached_at || now - cache.cached_at >= 86_400_000) {
    try {
      budget.take();
      const response = await fetch(`${env.OSV_BASE_URL}/ecosystems.txt`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error(`OSV ecosystems failed (${response.status})`);
      const ecosystems = z.array(z.string().min(1)).parse(
        (await response.text())
          .split("\n")
          .map((value) => value.trim())
          .filter(Boolean),
      );
      await env.DB.batch(
        ecosystems.map((ecosystem) =>
          env.DB.prepare(
            "INSERT INTO osv_ecosystems (ecosystem,cached_at) VALUES (?,?) ON CONFLICT(ecosystem) DO UPDATE SET cached_at=excluded.cached_at",
          ).bind(ecosystem, now),
        ),
      );
    } catch (error) {
      console.error("Scheduled OSV ecosystems refresh failed", {
        error: describeError(error),
      });
    }
  }
  const active = await env.DB.prepare(
    "SELECT DISTINCT CASE WHEN instr(c.ecosystem, ':')>0 THEN substr(c.ecosystem,1,instr(c.ecosystem,':')-1) ELSE c.ecosystem END AS ecosystem FROM components c JOIN sboms s ON s.id=c.sbom_id AND s.retired_at IS NULL JOIN osv_ecosystems e ON e.ecosystem=CASE WHEN instr(c.ecosystem, ':')>0 THEN substr(c.ecosystem,1,instr(c.ecosystem,':')-1) ELSE c.ecosystem END LEFT JOIN sync_cursors sc ON sc.ecosystem=e.ecosystem WHERE c.matchable=1 ORDER BY COALESCE(sc.last_synced_at,'')",
  ).all<{ readonly ecosystem: string }>();
  for (const { ecosystem } of active.results) {
    const cursor = await env.DB.prepare("SELECT ecosystem FROM sync_cursors WHERE ecosystem=?")
      .bind(ecosystem)
      .first();
    if (!cursor) {
      const pending = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE (c.ecosystem=? OR c.ecosystem LIKE ?) AND s.retired_at IS NULL AND s.backfill_status!='complete'",
      )
        .bind(ecosystem, `${ecosystem}:%`)
        .first<number>("count");
      if (pending === 0)
        await env.DB.prepare(
          "INSERT INTO sync_cursors (ecosystem,last_synced_at,boundary_ids) VALUES (?,?,'')",
        )
          .bind(ecosystem, new Date(now).toISOString())
          .run();
    } else if (budget.remaining > 3 && !deadline.expired) {
      try {
        await discoverAdvisories({
          database: env.DB,
          ecosystem,
          osvBaseUrl: env.OSV_BASE_URL,
          queue: env.OSV_ADVISORY_JOBS,
        });
      } catch (error) {
        console.error("Scheduled OSV discovery failed", { ecosystem, error: describeError(error) });
      }
    }
  }
  if (deadline.expired) return;
  try {
    await requeueAdvisoryJobs({
      database: env.DB,
      queue: env.OSV_ADVISORY_JOBS,
      now,
    });
  } catch (error) {
    console.error("Scheduled advisory requeue failed", { error: describeError(error) });
  }
  if (env.DISPATCH_ENABLED === "true" && budget.remaining > 1 && !deadline.expired) {
    try {
      await dispatchPending(env, now, budget);
    } catch (error) {
      console.error("Scheduled dispatch failed", { error: describeError(error) });
    }
  }
}
