import { importPKCS8, SignJWT } from "jose";
import { z } from "zod";
import type { SubrequestBudget } from "./budget";

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
  github_dispatch_repo: z.string(),
  github_dispatch_workflow: z.string(),
  platforms: z.string(),
});

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function installationToken(
  env: DispatchEnv,
  now: number,
  budget?: SubrequestBudget,
): Promise<string> {
  const key = await importPKCS8(env.GH_APP_PRIVATE_KEY, "RS256");
  const jwt = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(env.GH_APP_ID)
    .setIssuedAt(Math.floor(now / 1000) - 60)
    .setExpirationTime(Math.floor(now / 1000) + 540)
    .sign(key);
  budget?.take();
  const response = await fetch(
    `https://api.github.com/app/installations/${env.GH_APP_INSTALLATION_ID}/access_tokens`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${jwt}`,
        accept: "application/vnd.github+json",
        "user-agent": "squawk",
      },
      signal: AbortSignal.timeout(10_000),
    },
  );
  if (!response.ok) throw new Error(`GitHub installation token failed (${response.status})`);
  return z.object({ token: z.string().min(1) }).parse(await response.json()).token;
}

export async function dispatchPending(
  env: DispatchEnv,
  now = Date.now(),
  budget?: SubrequestBudget,
): Promise<number> {
  const rows = (
    await env.DB.prepare(`SELECT f.org_id, s.logical_image_ref, c.package_name, c.ecosystem, c.version,
    f.vuln_id, v.severity, o.github_dispatch_repo, o.github_dispatch_workflow,
    GROUP_CONCAT(s.platform || '|' || s.image_ref, char(10)) AS platforms
    FROM findings f JOIN components c ON c.id=f.component_id JOIN sboms s ON s.id=c.sbom_id AND s.retired_at IS NULL
    JOIN vulnerabilities v ON v.id=f.vuln_id AND v.ecosystem=c.ecosystem AND v.package_name=c.package_name
    JOIN orgs o ON o.descope_tenant_id=f.org_id
    WHERE f.dispatched_at IS NULL AND NOT EXISTS (SELECT 1 FROM vex_statements x WHERE x.id=(SELECT id FROM vex_statements
      WHERE org_id=f.org_id AND package_name=c.package_name AND ecosystem=c.ecosystem AND vuln_id=f.vuln_id
      ORDER BY created_at DESC,id DESC LIMIT 1) AND x.status IN ('not_affected','fixed'))
    GROUP BY f.org_id,s.logical_image_ref,c.package_name,c.ecosystem,c.version,f.vuln_id`).all()
  ).results.map((row) => pendingSchema.parse(row));
  if (rows.length === 0) return 0;
  const token = await installationToken(env, now, budget);
  for (const row of rows) {
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
      `https://api.github.com/repos/${row.github_dispatch_repo}/actions/workflows/${row.github_dispatch_workflow}/dispatches`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/vnd.github+json",
          "content-type": "application/json",
          "user-agent": "squawk",
        },
        body: JSON.stringify({
          ref: "main",
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
