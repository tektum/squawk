import { z } from "zod";
import { parsePurl } from "../src/sbom";

const inputSchema = z.tuple([z.string().min(1)]);
const componentsSchema = z.array(
  z.object({
    results: z.array(
      z.object({
        id: z.number().int().positive(),
        purl: z.string().min(1),
        ecosystem: z.string(),
        matchable: z.number().int(),
      }),
    ),
  }),
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
  const [database] = inputSchema.parse(process.argv.slice(2));
  const parsed = componentsSchema.parse(
    JSON.parse(
      await execute(database, "SELECT id,purl,ecosystem,matchable FROM components ORDER BY id"),
    ),
  );
  const components = parsed[0]?.results ?? [];
  if (components.length === 0) throw new Error("no components to reconcile");

  const updates: string[] = [];
  for (const component of components) {
    const resolved = parsePurl(component.purl);
    const matchable = resolved.matchable ? 1 : 0;
    if (resolved.ecosystem === component.ecosystem && matchable === component.matchable) continue;
    updates.push(
      `UPDATE components SET ecosystem=${quote(resolved.ecosystem)},matchable=${matchable} WHERE id=${component.id};`,
    );
  }
  console.log(`components=${components.length} restated=${updates.length}`);
  if (updates.length > 0) {
    for (let offset = 0; offset < updates.length; offset += 200)
      await execute(database, updates.slice(offset, offset + 200).join("\n"));

    // Findings were matched against the previous ecosystems, so every live SBOM has to
    // be re-queried against OSV. Cron drains the queue in bounded batches.
    await execute(
      database,
      `DELETE FROM matching_errors;
UPDATE sboms SET backfill_status='pending',backfill_error=NULL WHERE retired_at IS NULL;`,
    );
    console.log("queued re-backfill for every live SBOM");
  }
}
