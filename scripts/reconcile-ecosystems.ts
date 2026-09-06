import { z } from "zod";
import { parsePurl } from "../src/sbom";

const inputSchema = z.tuple([z.string().min(1)]);
const storedComponentSchema = z.object({
  id: z.number().int().positive(),
  purl: z.string().min(1),
  ecosystem: z.string(),
  matchable: z.number().int(),
  version: z.string(),
});
const componentsSchema = z.array(z.object({ results: z.array(storedComponentSchema) }));

export type StoredComponent = z.infer<typeof storedComponentSchema>;

function quote(value: string) {
  return `'${value.replaceAll("'", "''")}'`;
}

/**
 * Builds SQL statements to reconcile stored component metadata and requeue live SBOMs for backfill.
 *
 * The requeue statement is part of every plan, including no-op reparses.
 * Each changed component is repaired before its identity update: stale findings,
 * matching errors, and undelivered claims are removed, then its live SBOM is requeued.
 * The final requeue is intentionally non-destructive to unrelated findings and makes
 * reruns safe after an interrupted operator session.
 *
 * @param components - Stored components whose ecosystem, matchability, and version values should be reconciled
 * @returns Targeted component repair statements and the idempotent live-SBOM requeue statement
 */
export function reconciliationPlan(components: readonly StoredComponent[]): {
  readonly updates: readonly string[];
  readonly requeue: string;
} {
  const updates: string[] = [];
  for (const component of components) {
    const resolved = parsePurl(component.purl);
    const matchable = resolved.matchable ? 1 : 0;
    const version = resolved.version ?? component.version;
    if (
      resolved.ecosystem === component.ecosystem &&
      matchable === component.matchable &&
      version === component.version
    )
      continue;
    updates.push(`DELETE FROM dispatch_deliveries WHERE status IN ('pending','failed') AND ecosystem=${quote(component.ecosystem)} AND version=${quote(component.version)} AND package_name=(SELECT package_name FROM components WHERE id=${component.id}) AND logical_image_ref=(SELECT s.logical_image_ref FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE c.id=${component.id});
DELETE FROM findings WHERE component_id=${component.id};
DELETE FROM matching_errors WHERE component_id=${component.id};
UPDATE sboms SET backfill_status='pending',backfill_error=NULL WHERE retired_at IS NULL AND id=(SELECT sbom_id FROM components WHERE id=${component.id});
UPDATE components SET ecosystem=${quote(resolved.ecosystem)},matchable=${matchable},version=${quote(version)} WHERE id=${component.id};`);
  }
  return {
    updates,
    requeue: `DELETE FROM findings
WHERE NOT EXISTS (
  SELECT 1 FROM components c JOIN vulnerabilities v
    ON v.id=findings.vuln_id AND v.ecosystem=c.ecosystem AND v.package_name=c.package_name
  WHERE c.id=findings.component_id
);
DELETE FROM matching_errors
WHERE NOT EXISTS (
  SELECT 1 FROM components c JOIN vulnerabilities v
    ON v.id=matching_errors.vuln_id AND v.ecosystem=c.ecosystem AND v.package_name=c.package_name
  WHERE c.id=matching_errors.component_id
);
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
      await execute(
        database,
        "SELECT id,purl,ecosystem,matchable,version FROM components ORDER BY id",
      ),
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
