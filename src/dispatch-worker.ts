import { z } from "zod";
import type { SubrequestBudget } from "./budget";
import { type DispatchEnv, type DispatchMessage, dispatchRowSchema } from "./dispatch";
import { defaultGitHubApiUrl, GitHubApiError, installationToken } from "./github";

const repositorySchema = z.object({ full_name: z.string().regex(/^[^/]+\/[^/]+$/) });
/** Queue retry_delay is 30s; a 20s lease permits the retry but blocks concurrent delivery. */
const attemptLeaseMilliseconds = 20_000;

export class DispatchClaimBusy extends Error {
  readonly name = "DispatchClaimBusy";
  constructor() {
    super("dispatch claim is already being processed");
  }
}

async function repositoryPath(
  apiUrl: string,
  repositoryId: string,
  token: string,
  budget?: SubrequestBudget,
): Promise<string> {
  budget?.take();
  const response = await fetch(`${apiUrl}/repositories/${repositoryId}`, {
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "user-agent": "squawk",
      "x-github-api-version": "2026-03-10",
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new GitHubApiError(response.status);
  return repositorySchema.parse(await response.json()).full_name;
}

/** Applies one retry policy to token, repository and workflow GitHub requests. */
async function handleGitHubError(
  database: D1Database,
  deliveryId: string,
  error: unknown,
): Promise<false> {
  if (!(error instanceof GitHubApiError)) throw error;
  const retryable = error.status === 429 || error.status >= 500;
  await database
    .prepare("UPDATE dispatch_deliveries SET status=?,error=? WHERE delivery_id=?")
    .bind(retryable ? "pending" : "failed", `GitHub ${error.status}`, deliveryId)
    .run();
  if (retryable) throw error;
  return false;
}

/**
 * Dispatches one immutable claim. Before any GitHub request, a conditional D1 update
 * atomically takes a short processing lease, so concurrent at-least-once deliveries
 * cannot both create workflow runs.
 *
 * Every routing and tenant field is reloaded from D1. The queue message is never an
 * authorization source.
 */
export async function dispatchOne(
  env: DispatchEnv,
  message: DispatchMessage,
  now = Date.now(),
  budget?: SubrequestBudget,
): Promise<boolean> {
  const claim = await env.DB.prepare("SELECT status FROM dispatch_deliveries WHERE delivery_id=?")
    .bind(message.deliveryId)
    .first<{ readonly status: "pending" | "accepted" | "failed" }>();
  if (!claim) return false;
  if (claim.status === "accepted") return true;
  if (claim.status === "failed") return false;

  const claimed = await env.DB.prepare(
    `UPDATE dispatch_deliveries SET attempted_at=?,error=NULL
     WHERE delivery_id=? AND status='pending' AND (attempted_at IS NULL OR attempted_at<=?)`,
  )
    .bind(now, message.deliveryId, now - attemptLeaseMilliseconds)
    .run();
  if (claimed.meta.changes === 0) throw new DispatchClaimBusy();

  const raw =
    await env.DB.prepare(`SELECT d.org_id, d.logical_image_ref, d.package_name, d.ecosystem,
    d.version, d.vuln_id, v.severity, s.installation_id, s.repository_id,
    src.dispatch_workflow, src.dispatch_ref,
    GROUP_CONCAT(s.platform || '|' || s.image_ref, char(10)) AS platforms
    FROM dispatch_deliveries d
    JOIN findings f ON f.org_id=d.org_id AND f.vuln_id=d.vuln_id AND f.dispatched_at IS NULL
    JOIN components c ON c.id=f.component_id AND c.package_name=d.package_name
      AND c.ecosystem=d.ecosystem AND c.version=d.version
    JOIN sboms s ON s.id=c.sbom_id AND s.retired_at IS NULL
      AND s.logical_image_ref=d.logical_image_ref
    JOIN vulnerabilities v ON v.id=d.vuln_id AND v.ecosystem=d.ecosystem
      AND v.package_name=d.package_name
    LEFT JOIN github_sources src ON src.installation_id=s.installation_id
      AND src.repository_id=s.repository_id
    WHERE d.delivery_id=? AND NOT EXISTS (SELECT 1 FROM vex_statements x
      WHERE x.id=(SELECT id FROM vex_statements WHERE org_id=d.org_id
        AND package_name=d.package_name AND ecosystem=d.ecosystem AND vuln_id=d.vuln_id
        ORDER BY created_at DESC,id DESC LIMIT 1) AND x.status IN ('not_affected','fixed'))
    GROUP BY d.delivery_id,s.installation_id,s.repository_id`)
      .bind(message.deliveryId)
      .first();
  if (!raw) {
    await env.DB.prepare("DELETE FROM dispatch_deliveries WHERE delivery_id=?")
      .bind(message.deliveryId)
      .run();
    return true;
  }
  const job = dispatchRowSchema.parse(raw);
  if (!job.installation_id || !job.repository_id || !job.dispatch_workflow) {
    await env.DB.prepare(
      "UPDATE dispatch_deliveries SET status='failed',error='dispatch target unavailable' WHERE delivery_id=?",
    )
      .bind(message.deliveryId)
      .run();
    return false;
  }

  const apiUrl = env.GITHUB_API_URL ?? defaultGitHubApiUrl;
  let token: string;
  let repository: string;
  try {
    token = await installationToken(
      env,
      { installationId: job.installation_id, repositoryId: job.repository_id },
      now,
      budget,
    );
    repository = await repositoryPath(apiUrl, job.repository_id, token, budget);
  } catch (error) {
    return handleGitHubError(env.DB, message.deliveryId, error);
  }
  const platforms = job.platforms.split("\n").map((value) => {
    const [platform, image_ref] = value.split("|");
    return z.object({ platform: z.string(), image_ref: z.string() }).parse({ platform, image_ref });
  });
  budget?.take();
  const response = await fetch(
    `${apiUrl}/repos/${repository}/actions/workflows/${job.dispatch_workflow}/dispatches`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
        "user-agent": "squawk",
      },
      body: JSON.stringify({
        ref: job.dispatch_ref || "main",
        inputs: {
          payload: JSON.stringify({
            schema_version: 1,
            delivery_id: message.deliveryId,
            logical_image_ref: job.logical_image_ref,
            package_name: job.package_name,
            ecosystem: job.ecosystem,
            version: job.version,
            vuln_id: job.vuln_id,
            severity: job.severity,
            platforms,
          }),
        },
      }),
      signal: AbortSignal.timeout(10_000),
    },
  );
  if (!response.ok)
    return handleGitHubError(env.DB, message.deliveryId, new GitHubApiError(response.status));
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE dispatch_deliveries SET status='accepted',error=NULL WHERE delivery_id=?",
    ).bind(message.deliveryId),
    env.DB.prepare(
      "UPDATE findings SET dispatched_at=? WHERE org_id=? AND vuln_id=? AND component_id IN (SELECT c.id FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE s.logical_image_ref=? AND c.package_name=? AND c.ecosystem=? AND c.version=?)",
    ).bind(
      now,
      job.org_id,
      job.vuln_id,
      job.logical_image_ref,
      job.package_name,
      job.ecosystem,
      job.version,
    ),
  ]);
  return true;
}
