import { z } from "zod";
import { sha256 } from "./digest";
import {
  defaultGitHubApiUrl,
  GitHubApiError,
  installationToken,
  repositoryPath,
  type GitHubAppEnv,
} from "./github";
import { recoverTerminalRuns } from "./reconciliation-recovery";

export type ReconciliationWorkerEnv = GitHubAppEnv & { readonly DB: D1Database };
export type ReconciliationDispatchEnv = ReconciliationWorkerEnv & {
  readonly FINDING_DISPATCH: Queue;
};

type WakeupMessage = { readonly deliveryId: string };
const runSchema = z.object({ workflow_run_id: z.number().int().positive() });

async function failDelivery(
  database: D1Database,
  deliveryId: string,
  attemptId: string,
  workflowRequestStarted: boolean,
  error: unknown,
): Promise<false> {
  const description =
    error instanceof GitHubApiError ? `GitHub ${error.status}` : "dispatch transport failure";
  const updated = await database
    .prepare(
      workflowRequestStarted
        ? `UPDATE reconciliation_deliveries SET error='workflow dispatch outcome unknown'
           WHERE delivery_id=? AND status='pending' AND attempt_id=?`
        : `UPDATE reconciliation_deliveries
           SET status='pending',error=?,attempt_id=NULL,attempted_at=NULL
           WHERE delivery_id=? AND status='pending' AND attempt_id=?`,
    )
    .bind(
      ...(workflowRequestStarted ? [deliveryId, attemptId] : [description, deliveryId, attemptId]),
    )
    .run();
  if (updated.meta.changes === 0) return false;
  throw error;
}

export async function dispatchReconciliation(
  env: ReconciliationWorkerEnv,
  message: WakeupMessage,
  now = Date.now(),
): Promise<boolean | null> {
  const claim = await env.DB.prepare(
    "SELECT status FROM reconciliation_deliveries WHERE delivery_id=?",
  )
    .bind(message.deliveryId)
    .first<{ readonly status: "pending" | "dispatched" | "acked" | "failed" }>();
  if (!claim) return null;
  if (claim.status === "acked" || claim.status === "dispatched") return true;
  if (claim.status === "failed") return false;
  const attemptId = crypto.randomUUID();
  const leased = await env.DB.prepare(
    `UPDATE reconciliation_deliveries SET attempted_at=?,attempt_id=?,error=NULL
     WHERE delivery_id=? AND status='pending' AND attempt_id IS NULL`,
  )
    .bind(now, attemptId, message.deliveryId)
    .run();
  if (leased.meta.changes === 0) throw new Error("reconciliation claim is already processing");
  const row = await env.DB.prepare(
    `SELECT d.installation_id,d.repository_id,d.logical_image_ref,d.target_revision,
      s.dispatch_workflow,s.dispatch_ref
     FROM reconciliation_deliveries d JOIN github_sources s
       ON s.installation_id=d.installation_id AND s.repository_id=d.repository_id
     WHERE d.delivery_id=? AND d.attempt_id=? AND s.dispatch_schema_version=2`,
  )
    .bind(message.deliveryId, attemptId)
    .first<{
      readonly installation_id: string;
      readonly repository_id: string;
      readonly logical_image_ref: string;
      readonly target_revision: number;
      readonly dispatch_workflow: string | null;
      readonly dispatch_ref: string | null;
    }>();
  if (!row?.dispatch_workflow) {
    const failed = await env.DB.prepare(
      `UPDATE reconciliation_deliveries SET status='failed',error='dispatch target unavailable',
        attempt_id=NULL,attempted_at=NULL
       WHERE delivery_id=? AND status='pending' AND attempt_id=?`,
    )
      .bind(message.deliveryId, attemptId)
      .run();
    if (failed.meta.changes === 0) throw new Error("stale reconciliation attempt");
    return false;
  }
  const apiUrl = env.GITHUB_API_URL ?? defaultGitHubApiUrl;
  let workflowRequestStarted = false;
  try {
    const token = await installationToken(env, {
      installationId: row.installation_id,
      repositoryId: row.repository_id,
    });
    const repository = await repositoryPath(apiUrl, row.repository_id, token);
    workflowRequestStarted = true;
    const response = await fetch(
      `${apiUrl}/repos/${repository}/actions/workflows/${row.dispatch_workflow}/dispatches`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/vnd.github+json",
          "content-type": "application/json",
          "user-agent": "squawk",
          "x-github-api-version": "2026-03-10",
        },
        body: JSON.stringify({
          ref: row.dispatch_ref || "main",
          inputs: {
            payload: JSON.stringify({
              schema_version: 2,
              event: "reconcile",
              delivery_id: message.deliveryId,
              logical_image_ref: row.logical_image_ref,
              source: {
                installation_id: row.installation_id,
                repository_id: row.repository_id,
              },
            }),
          },
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!response.ok) throw new GitHubApiError(response.status);
    const run = runSchema.parse(await response.json());
    const workflow = row.dispatch_workflow.replace(/^\.github\/workflows\//, "");
    const ref = row.dispatch_ref?.startsWith("refs/")
      ? row.dispatch_ref
      : `refs/heads/${row.dispatch_ref || "main"}`;
    const workflowRefSha256 = await sha256(`${repository}/.github/workflows/${workflow}@${ref}`);
    const accepted = await env.DB.prepare(
      `UPDATE reconciliation_deliveries
       SET status='dispatched',workflow_run_id=?,workflow_ref_sha256=?,error=NULL
       WHERE delivery_id=? AND status='pending' AND attempt_id=?`,
    )
      .bind(run.workflow_run_id.toString(), workflowRefSha256, message.deliveryId, attemptId)
      .run();
    if (accepted.meta.changes === 0)
      throw new Error("stale reconciliation attempt created a workflow run");
    return true;
  } catch (error) {
    return failDelivery(env.DB, message.deliveryId, attemptId, workflowRequestStarted, error);
  }
}

export async function enqueueReconciliations(
  env: ReconciliationDispatchEnv,
  now = Date.now(),
): Promise<number> {
  await recoverTerminalRuns(env);
  const states = (
    await env.DB.prepare(
      `SELECT r.installation_id,r.repository_id,r.logical_image_ref,r.revision
       FROM image_reconciliation_state r JOIN github_sources s
         ON s.installation_id=r.installation_id AND s.repository_id=r.repository_id
       WHERE s.dispatch_schema_version=2 AND r.state='ready' AND r.revision>r.applied_revision
         AND NOT EXISTS (SELECT 1 FROM reconciliation_deliveries d
           WHERE d.installation_id=r.installation_id AND d.repository_id=r.repository_id
             AND d.logical_image_ref=r.logical_image_ref AND d.status IN ('pending','dispatched'))
       ORDER BY r.updated_at LIMIT 100`,
    ).all<ReconciliationImageKeyRow>()
  ).results;
  for (const state of states) {
    const deliveryId = await sha256(
      [
        "reconciliation-wakeup-v2",
        state.installation_id,
        state.repository_id,
        state.logical_image_ref,
        state.revision.toString(),
      ].join("\u0000"),
    );
    await env.DB.prepare(
      `INSERT OR IGNORE INTO reconciliation_deliveries
       (delivery_id,installation_id,repository_id,logical_image_ref,target_revision,status,created_at)
       VALUES (?,?,?,?,?,'pending',?)`,
    )
      .bind(
        deliveryId,
        state.installation_id,
        state.repository_id,
        state.logical_image_ref,
        state.revision,
        now,
      )
      .run();
  }
  const pending = await env.DB.prepare(
    `SELECT d.delivery_id FROM reconciliation_deliveries d JOIN image_reconciliation_state r
       ON r.installation_id=d.installation_id AND r.repository_id=d.repository_id
       AND r.logical_image_ref=d.logical_image_ref
     WHERE d.status='pending' AND d.attempt_id IS NULL AND r.state='ready'
     ORDER BY d.created_at LIMIT 100`,
  ).all<{ readonly delivery_id: string }>();
  const messages = pending.results.map(({ delivery_id }) => ({ deliveryId: delivery_id }));
  if (messages.length > 0) await env.FINDING_DISPATCH.sendBatch(messages.map((body) => ({ body })));
  return messages.length;
}

type ReconciliationImageKeyRow = {
  readonly installation_id: string;
  readonly repository_id: string;
  readonly logical_image_ref: string;
  readonly revision: number;
};
