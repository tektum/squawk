import { z } from "zod";

const inputSchema = z.tuple([
  z.string().min(1),
  z.string().regex(/^\d+$/),
  z.string().regex(/^\d+$/),
  z.string().min(1),
  z.string().regex(/^\.github\/workflows\/[a-zA-Z0-9_.-]+$/),
  z.string().regex(/^refs\/heads\/.+$/),
]);

function quote(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

const [database, installationId, repositoryId, tenantId, workflow, ref] = inputSchema.parse(
  process.argv.slice(2),
);
const sql = `INSERT INTO github_sources (installation_id,repository_id,org_id,workflow,ref,created_at) VALUES (${[installationId, repositoryId, tenantId, workflow, ref].map(quote).join(",")},unixepoch()*1000) ON CONFLICT(installation_id,repository_id) DO UPDATE SET org_id=excluded.org_id,workflow=excluded.workflow,ref=excluded.ref`;
const processResult = Bun.spawn(
  ["bun", "run", "wrangler", "d1", "execute", database, "--remote", "--command", sql],
  { stdin: "inherit", stdout: "inherit", stderr: "inherit" },
);
process.exit(await processResult.exited);
