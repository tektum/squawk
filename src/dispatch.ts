import { z } from "zod";
import type { SubrequestBudget } from "./budget";
import { sha256 } from "./digest";
import { GitHubApiError, installationToken } from "./github";

type DispatchEnv = {
  readonly DB: D1Database;
  readonly GH_APP_ID: string;
  readonly GH_APP_INSTALLATION_ID: string;
  readonly GH_APP_PRIVATE_KEY: string;
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
  repositoryId: string,
  token: string,
  budget?: SubrequestBudget,
): Promise<string> {
  budget?.take();
  const response = await fetch(`https://api.github.com/repositories/${repositoryId}`, {
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

export async function dispatchPending(
  env: DispatchEnv,
  now = Date.now(),
  budget?: SubrequestBudget,
): Promise<number> {
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
  if (routable.length === 0) return 0;
  const tokens = new Map<string, string>();
  const paths = new Map<string, string>();
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
    const installationId = row.installation_id ?? "";
    const repositoryId = row.repository_id ?? "";
    // Tokens are scoped to the routed source's installation and repository, so a
    // finding is never dispatched with another installation's authority.
    let token = tokens.get(`${installationId}\u0000${repositoryId}`);
    if (!token) {
      token = await installationToken(env, { installationId, repositoryId }, now, budget);
      tokens.set(`${installationId}\u0000${repositoryId}`, token);
    }
    let repository = paths.get(repositoryId);
    if (!repository) {
      repository = await repositoryPath(repositoryId, token, budget);
      paths.set(repositoryId, repository);
    }
    const platforms = row.platforms.split("\n").map((value) => {
      const [platform, image_ref] = value.split("|");
      return z
        .object({ platform: z.string(), image_ref: z.string() })
        .parse({ platform, image_ref });
    });
    await env.DB.prepare(
      "INSERT OR IGNORE INTO dispatch_deliveries (delivery_id,org_id,logical_image_ref,package_name,ecosystem,version,vuln_id,status,created_at) VALUES (?,?,?,?,?,?,?,'pending',?)",
    )
      .bind(
        deliveryId,
        row.org_id,
        row.logical_image_ref,
        row.package_name,
        row.ecosystem,
        row.version,
        row.vuln_id,
        now,
      )
      .run();
    budget?.take();
    const response = await fetch(
      `https://api.github.com/repos/${repository}/actions/workflows/${row.dispatch_workflow}/dispatches`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/vnd.github+json",
          "content-type": "application/json",
          "user-agent": "squawk",
        },
        body: JSON.stringify({
          ref: row.dispatch_ref || "main",
          inputs: {
            payload: JSON.stringify({
              schema_version: 1,
              delivery_id: deliveryId,
              logical_image_ref: row.logical_image_ref,
              package_name: row.package_name,
              ecosystem: row.ecosystem,
              version: row.version,
              vuln_id: row.vuln_id,
              severity: row.severity,
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
        .bind(now, `GitHub ${response.status}`, deliveryId)
        .run();
      continue;
    }
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE dispatch_deliveries SET status='accepted',attempted_at=?,error=NULL WHERE delivery_id=?",
      ).bind(now, deliveryId),
      env.DB.prepare(
        "UPDATE findings SET dispatched_at=? WHERE org_id=? AND vuln_id=? AND component_id IN (SELECT c.id FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE s.logical_image_ref=? AND c.package_name=? AND c.ecosystem=? AND c.version=?)",
      ).bind(
        now,
        row.org_id,
        row.vuln_id,
        row.logical_image_ref,
        row.package_name,
        row.ecosystem,
        row.version,
      ),
    ]);
  }
  return rows.length;
}
