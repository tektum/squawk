import { z } from "zod";
import type { SubrequestBudget } from "./budget";
import { sha256 } from "./digest";
import { defaultGitHubApiUrl, GitHubApiError, installationToken } from "./github";

export type DispatchEnv = {
  readonly DB: D1Database;
  readonly GH_APP_ID: string;
  readonly GH_APP_INSTALLATION_ID: string;
  readonly GH_APP_PRIVATE_KEY: string;
  /** Overridden only so a local end-to-end run can serve a fake GitHub. */
  readonly GITHUB_API_URL?: string;
};

const pendingSchema = z.object({
  org_id: z.string(),
  logical_image_ref: z.string(),
  package_name: z.string(),
  ecosystem: z.string(),
  version: z.string(),
  vuln_id: z.string(),
  severity: z.string().nullable(),
  installation_id: z.string().nullable(),
  repository_id: z.string().nullable(),
  dispatch_workflow: z.string().nullable(),
  dispatch_ref: z.string().nullable(),
  platforms: z.string(),
});
const repositorySchema = z.object({ full_name: z.string().regex(/^[^/]+\/[^/]+$/) });

/** Resolves a repository path from its immutable id so no external name is stored. */
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

/** Claim held on a queued group, so a stalled message is retried rather than lost. */
const dispatchLeaseMilliseconds = 15 * 60_000;
/** A queue send accepts at most one hundred messages per call. */
const sendChunk = 100;
export const dispatchMessageSchema = z.object({
  // The only authority crossing the queue boundary is the immutable digest identity.
  // Everything routable is reloaded from D1 by the consumer.
  deliveryId: z.string().regex(/^[a-f0-9]{64}$/),
});
export type DispatchMessage = z.infer<typeof dispatchMessageSchema>;
type DispatchClaim = {
  readonly message: DispatchMessage;
  readonly orgId: string;
  readonly logicalImageRef: string;
  readonly packageName: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly vulnId: string;
};
export type DispatchQueueEnv = Pick<DispatchEnv, "DB"> & { readonly FINDING_DISPATCH: Queue };

/**
 * Selects the finding groups that can be dispatched, using D1 only. No subrequests, so a
 * scheduled run can enqueue an arbitrary backlog without competing for its own allowance.
 *
 * A group is eligible when nothing has claimed it, a previous attempt failed, or a claim
 * has outlived its lease, which is what makes a lost message recoverable.
 */
async function routableGroups(env: Pick<DispatchEnv, "DB">, now: number) {
  // Each SBOM records the source that produced it, so a digest published by two
  // repositories cannot route a finding to the wrong one, and the dispatch target
  // never drifts from the repository actually publishing the images.
  const rows = (
    await env.DB.prepare(`SELECT f.org_id, s.logical_image_ref, c.package_name, c.ecosystem, c.version,
    f.vuln_id, v.severity, s.installation_id, s.repository_id, src.dispatch_workflow, src.dispatch_ref,
    GROUP_CONCAT(s.platform || '|' || s.image_ref, char(10)) AS platforms
    FROM findings f JOIN components c ON c.id=f.component_id JOIN sboms s ON s.id=c.sbom_id AND s.retired_at IS NULL
    JOIN vulnerabilities v ON v.id=f.vuln_id AND v.ecosystem=c.ecosystem AND v.package_name=c.package_name
    LEFT JOIN github_sources src ON src.installation_id=s.installation_id AND src.repository_id=s.repository_id
    WHERE f.dispatched_at IS NULL AND NOT EXISTS (SELECT 1 FROM vex_statements x WHERE x.id=(SELECT id FROM vex_statements
      WHERE org_id=f.org_id AND package_name=c.package_name AND ecosystem=c.ecosystem AND vuln_id=f.vuln_id
      ORDER BY created_at DESC,id DESC LIMIT 1) AND x.status IN ('not_affected','fixed'))
    GROUP BY f.org_id,s.logical_image_ref,s.installation_id,s.repository_id,c.package_name,c.ecosystem,c.version,f.vuln_id`).all()
  ).results.map((row) => pendingSchema.parse(row));
  const routable = rows.filter(
    (row) => row.installation_id && row.repository_id && row.dispatch_workflow,
  );
  const unroutable = rows.length - routable.length;
  if (unroutable > 0) console.warn("Findings without a dispatch target", { findings: unroutable });
  const claims = new Map<
    string,
    { readonly status: "pending" | "failed"; readonly created_at: number }
  >();
  for (const claim of (
    await env.DB.prepare(
      "SELECT delivery_id, status, created_at FROM dispatch_deliveries WHERE status IN ('pending','failed')",
    ).all<{
      readonly delivery_id: string;
      readonly status: "pending" | "failed";
      readonly created_at: number;
    }>()
  ).results)
    claims.set(claim.delivery_id, { status: claim.status, created_at: claim.created_at });
  const jobs: DispatchClaim[] = [];
  for (const row of routable) {
    const deliveryId = await sha256(
      [
        row.org_id,
        row.logical_image_ref,
        row.package_name,
        row.ecosystem,
        row.version,
        row.vuln_id,
      ].join("\u0000"),
    );
    const claim = claims.get(deliveryId);
    // Permanent failures only become eligible through an explicit operator reset. A
    // pending claim is recoverable after its lease if the message was lost before delivery.
    if (claim?.status === "failed") continue;
    if (claim && now - claim.created_at < dispatchLeaseMilliseconds) continue;
    jobs.push({
      message: { deliveryId },
      orgId: row.org_id,
      logicalImageRef: row.logical_image_ref,
      packageName: row.package_name,
      ecosystem: row.ecosystem,
      version: row.version,
      vulnId: row.vuln_id,
    });
  }
  return jobs;
}

/**
 * Claims every dispatchable group and hands each to the queue as its own message, so a
 * dispatch runs in its own invocation with its own subrequest allowance instead of
 * sharing the scheduled run's.
 *
 * @returns The number of groups enqueued.
 */
export async function enqueueDispatch(env: DispatchQueueEnv, now = Date.now()): Promise<number> {
  const jobs = await routableGroups(env, now);
  if (jobs.length === 0) return 0;
  // The claim is written before the message is sent, so a delivery that never reaches the
  // queue still holds a lease and becomes eligible again once that lease expires.
  await env.DB.batch(
    jobs.map((job) =>
      env.DB.prepare(
        `INSERT INTO dispatch_deliveries (delivery_id,org_id,logical_image_ref,package_name,ecosystem,version,vuln_id,status,created_at)
         VALUES (?,?,?,?,?,?,?,'pending',?)
         ON CONFLICT(delivery_id) DO UPDATE SET status='pending',created_at=excluded.created_at,error=NULL`,
      ).bind(
        job.message.deliveryId,
        job.orgId,
        job.logicalImageRef,
        job.packageName,
        job.ecosystem,
        job.version,
        job.vulnId,
        now,
      ),
    ),
  );
  for (let index = 0; index < jobs.length; index += sendChunk)
    await env.FINDING_DISPATCH.sendBatch(
      jobs.slice(index, index + sendChunk).map((job) => ({ body: job.message })),
    );
  return jobs.length;
}

/**
 * Dispatches one finding group. Throws on a retryable GitHub failure so the queue
 * redelivers it with backoff, and records a permanent failure without throwing, because
 * redelivering a 4xx only burns the retry allowance.
 *
 * @returns Whether GitHub accepted the dispatch.
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

  // Never trust route or tenant authority from a queue message. Reload it from the
  // immutable claim, the current finding, and the current source assignment.
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
    // The finding was retired, suppressed, or handled after enqueue. Ack the stale message
    // and remove its claim so it cannot become a permanent failed hot loop.
    await env.DB.prepare("DELETE FROM dispatch_deliveries WHERE delivery_id=?")
      .bind(message.deliveryId)
      .run();
    return true;
  }
  const job = pendingSchema.parse(raw);
  if (!job.installation_id || !job.repository_id || !job.dispatch_workflow) {
    await env.DB.prepare(
      "UPDATE dispatch_deliveries SET status='failed',attempted_at=?,error='dispatch target unavailable' WHERE delivery_id=?",
    )
      .bind(now, message.deliveryId)
      .run();
    return false;
  }
  const apiUrl = env.GITHUB_API_URL ?? defaultGitHubApiUrl;
  const token = await installationToken(
    env,
    { installationId: job.installation_id, repositoryId: job.repository_id },
    now,
    budget,
  );
  const repository = await repositoryPath(apiUrl, job.repository_id, token, budget);
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
  if (!response.ok) {
    await env.DB.prepare(
      "UPDATE dispatch_deliveries SET status='failed',attempted_at=?,error=? WHERE delivery_id=?",
    )
      .bind(now, `GitHub ${response.status}`, message.deliveryId)
      .run();
    if (response.status === 429 || response.status >= 500)
      throw new GitHubApiError(response.status);
    return false;
  }
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE dispatch_deliveries SET status='accepted',attempted_at=?,error=NULL WHERE delivery_id=?",
    ).bind(now, message.deliveryId),
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
