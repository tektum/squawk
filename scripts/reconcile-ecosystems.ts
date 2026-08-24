import { z } from "zod";
import { parsePurl } from "../src/sbom";

const inputSchema = z.tuple([z.string().min(1)]);
const storedComponentSchema = z.object({
  id: z.number().int().positive(),
  purl: z.string().min(1),
  ecosystem: z.string(),
  matchable: z.number().int(),
});
const componentsSchema = z.array(z.object({ results: z.array(storedComponentSchema) }));

export type StoredComponent = z.infer<typeof storedComponentSchema>;

function quote(value: string) {
  return `'${value.replaceAll("'", "''")}'`;
}

/**
 * The requeue statement is part of every plan, never conditional on the update
 * count: a previous run may have restated components and then failed before
 * requeueing, and repeating the reset is harmless.
 */
export function reconciliationPlan(components: readonly StoredComponent[]): {
  readonly updates: readonly string[];
  readonly requeue: string;
} {
  const updates: string[] = [];
  for (const component of components) {
    const resolved = parsePurl(component.purl);
    const matchable = resolved.matchable ? 1 : 0;
    if (resolved.ecosystem === component.ecosystem && matchable === component.matchable) continue;
    updates.push(
      `UPDATE components SET ecosystem=${quote(resolved.ecosystem)},matchable=${matchable} WHERE id=${component.id};`,
    );
  }
  return {
    updates,
    requeue: `DELETE FROM matching_errors;
UPDATE sboms SET backfill_status='pending',backfill_error=NULL WHERE retired_at IS NULL;`,
  };
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
  const plan = reconciliationPlan(components);
  console.log(`components=${components.length} restated=${plan.updates.length}`);
  for (let offset = 0; offset < plan.updates.length; offset += 200)
    await execute(database, plan.updates.slice(offset, offset + 200).join("\n"));
  await execute(database, plan.requeue);
  console.log("queued re-backfill for every live SBOM");
}
