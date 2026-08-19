import { z } from "zod";

const inputSchema = z.tuple([z.string().min(1), z.string().min(1)]);
const queryResultSchema = z.array(
  z.object({ results: z.array(z.object({ collision_count: z.number().int().nonnegative() })) }),
);

function quote(value: string) {
  return `'${value.replaceAll("'", "''")}'`;
}

export function assertSuccessfulExit(exitCode: number) {
  if (exitCode !== 0) throw new Error(`wrangler exited with status ${exitCode}`);
}

async function execute(database: string, sql: string) {
  const child = Bun.spawn(
    ["bun", "run", "wrangler", "d1", "execute", database, "--remote", "--json", "--command", sql],
    { stdout: "pipe", stderr: "inherit" },
  );
  const output = await new Response(child.stdout).text();
  assertSuccessfulExit(await child.exited);
  return output;
}

if (import.meta.main) {
  const [database, tenantId] = inputSchema.parse(process.argv.slice(2));
  const target = quote(tenantId);
  const preflight = queryResultSchema.parse(
    JSON.parse(
      await execute(
        database,
        "SELECT COUNT(*) AS collision_count FROM (SELECT image_ref,platform FROM sboms GROUP BY image_ref,platform HAVING COUNT(*)>1)",
      ),
    ),
  );
  if ((preflight[0]?.results[0]?.collision_count ?? 0) > 0)
    throw new Error("tenant reconciliation has conflicting SBOM identities");
  await execute(
    database,
    `
INSERT OR IGNORE INTO orgs
SELECT ${target},descope_inbound_app_id,github_dispatch_repo,github_dispatch_workflow,created_at
FROM orgs ORDER BY created_at LIMIT 1;
UPDATE github_sources SET org_id=${target} WHERE org_id!=${target};
UPDATE sboms SET org_id=${target} WHERE org_id!=${target};
UPDATE findings SET org_id=${target} WHERE org_id!=${target};
UPDATE vex_statements SET org_id=${target} WHERE org_id!=${target};
UPDATE dispatch_deliveries SET org_id=${target} WHERE org_id!=${target};
DELETE FROM orgs WHERE descope_tenant_id!=${target};
`,
  );
}
