import { z } from "zod";

const inputSchema = z.tuple([
  z.string().min(1),
  z.string().regex(/^\d+$/),
  z.string().regex(/^\d+$/),
  z.string().min(1),
]);

function quote(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

const [database, installationId, repositoryId, tenantId] = inputSchema.parse(process.argv.slice(2));
const sql = `INSERT INTO github_sources (installation_id,repository_id,org_id,workflow,ref,created_at) VALUES (${[installationId, repositoryId, tenantId, "deployment", ""].map(quote).join(",")},unixepoch()*1000) ON CONFLICT(installation_id,repository_id) DO UPDATE SET org_id=excluded.org_id`;
const processResult = Bun.spawn(
  ["bun", "run", "wrangler", "d1", "execute", database, "--remote", "--command", sql],
  { stdin: "inherit", stdout: "inherit", stderr: "inherit" },
);
process.exit(await processResult.exited);
