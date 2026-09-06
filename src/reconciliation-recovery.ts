import { z } from "zod";
import {
  defaultGitHubApiUrl,
  GitHubApiError,
  installationToken,
  repositoryPath,
  type GitHubAppEnv,
} from "./github";

const runStatusSchema = z.object({
  status: z.string(),
  conclusion: z.string().nullable(),
});

type RecoveryEnv = GitHubAppEnv & { readonly DB: D1Database };

export async function recoverTerminalRuns(env: RecoveryEnv): Promise<void> {
  const rows = (
    await env.DB.prepare(
      `SELECT delivery_id,installation_id,repository_id,workflow_run_id,attempt_id,attempted_at
       FROM reconciliation_deliveries WHERE status='dispatched'
       ORDER BY attempted_at LIMIT 20`,
    ).all<{
      readonly delivery_id: string;
      readonly installation_id: string;
      readonly repository_id: string;
      readonly workflow_run_id: string;
      readonly attempt_id: string;
      readonly attempted_at: number;
    }>()
  ).results;
  for (const row of rows) {
    const apiUrl = env.GITHUB_API_URL ?? defaultGitHubApiUrl;
    try {
      const token = await installationToken(env, {
        installationId: row.installation_id,
        repositoryId: row.repository_id,
        permissions: { actions: "read" },
      });
      const repository = await repositoryPath(apiUrl, row.repository_id, token);
      const response = await fetch(
        `${apiUrl}/repos/${repository}/actions/runs/${row.workflow_run_id}`,
        {
          headers: {
            authorization: `Bearer ${token}`,
            accept: "application/vnd.github+json",
            "user-agent": "squawk",
            "x-github-api-version": "2026-03-10",
          },
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!response.ok) throw new GitHubApiError(response.status);
      const run = runStatusSchema.parse(await response.json());
      if (run.status === "completed") {
        const recovered = await env.DB.prepare(
          `UPDATE reconciliation_deliveries SET status='pending',workflow_run_id=NULL,
            workflow_ref_sha256=NULL,served_checkpoint_id=NULL,served_revision=NULL,
            served_payload_sha256=NULL,attempt_id=NULL,attempted_at=NULL,error=?
           WHERE delivery_id=? AND status='dispatched' AND workflow_run_id=?
             AND attempt_id=? AND attempted_at=?`,
        )
          .bind(
            `missing acknowledgement (${run.conclusion ?? "unknown"})`,
            row.delivery_id,
            row.workflow_run_id,
            row.attempt_id,
            row.attempted_at,
          )
          .run();
        if (recovered.meta.changes === 0) continue;
      }
    } catch (error) {
      if (!(error instanceof GitHubApiError) || (error.status !== 429 && error.status < 500))
        throw error;
    }
  }
}
