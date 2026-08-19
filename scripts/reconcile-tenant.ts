import { z } from "zod";

const [database, tenantId] = z
  .tuple([z.string().min(1), z.string().min(1)])
  .parse(process.argv.slice(2));
const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
const target = quote(tenantId);
const sql = `
INSERT OR IGNORE INTO orgs
SELECT ${target},descope_inbound_app_id,github_dispatch_repo,github_dispatch_workflow,created_at
FROM orgs ORDER BY created_at LIMIT 1;
UPDATE github_sources SET org_id=${target} WHERE org_id!=${target};
UPDATE sboms SET org_id=${target} WHERE org_id!=${target};
UPDATE findings SET org_id=${target} WHERE org_id!=${target};
UPDATE vex_statements SET org_id=${target} WHERE org_id!=${target};
UPDATE dispatch_deliveries SET org_id=${target} WHERE org_id!=${target};
DELETE FROM orgs WHERE descope_tenant_id!=${target};
`;
const processResult = Bun.spawn(
  ["bun", "run", "wrangler", "d1", "execute", database, "--remote", "--command", sql],
  { stdin: "inherit", stdout: "inherit", stderr: "inherit" },
);
process.exit(await processResult.exited);
