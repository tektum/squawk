import { z } from "zod";
import type { SubrequestBudget } from "./budget";
import { compareVersion } from "./osv/comparator";

const advisorySchema = z.object({
  id: z.string(),
  modified: z.string(),
  summary: z.string().optional(),
  severity: z.array(z.object({ score: z.string() })).optional(),
  affected: z.array(
    z.object({
      package: z.object({ ecosystem: z.string(), name: z.string() }),
      ranges: z
        .array(
          z.object({
            type: z.string(),
            events: z.array(
              z.object({
                introduced: z.string().optional(),
                fixed: z.string().optional(),
                last_affected: z.string().optional(),
                limit: z.string().optional(),
              }),
            ),
          }),
        )
        .default([]),
      versions: z.array(z.string()).default([]),
    }),
  ),
});
const cursorSchema = z.object({ last_synced_at: z.string(), boundary_ids: z.string() });
const componentSchema = z.object({ id: z.number(), org_id: z.string(), version: z.string() });

type SyncOptions = {
  readonly database: D1Database;
  readonly ecosystem: string;
  readonly osvBaseUrl: string;
  readonly budget: SubrequestBudget;
  readonly maxAdvisories?: number;
  readonly now?: number;
};

export async function syncEcosystem(options: SyncOptions): Promise<number> {
  const cursorRow = await options.database
    .prepare("SELECT last_synced_at,boundary_ids FROM sync_cursors WHERE ecosystem=?")
    .bind(options.ecosystem)
    .first();
  if (!cursorRow) return 0;
  const cursor = cursorSchema.parse(cursorRow);
  options.budget.take();
  const response = await fetch(
    `${options.osvBaseUrl}/${encodeURIComponent(options.ecosystem)}/modified_id.csv`,
    { signal: AbortSignal.timeout(10_000) },
  );
  if (!response.ok) throw new Error(`OSV modified feed failed (${response.status})`);
  const boundary = new Set(cursor.boundary_ids.split(",").filter(Boolean));
  const rows = (await response.text())
    .trim()
    .split("\n")
    .slice(1)
    .map((line) => {
      const [modified, id] = line.split(",");
      return z
        .object({ modified: z.string().datetime(), id: z.string().min(1) })
        .parse({ modified, id });
    })
    .filter(
      (row) =>
        row.modified > cursor.last_synced_at ||
        (row.modified === cursor.last_synced_at && !boundary.has(row.id)),
    )
    .sort(
      (left, right) =>
        left.modified.localeCompare(right.modified) || left.id.localeCompare(right.id),
    )
    .slice(
      0,
      Math.min(options.maxAdvisories ?? options.budget.remaining, options.budget.remaining),
    );
  let cursorTimestamp = cursor.last_synced_at;
  let cursorBoundary = boundary;
  for (const row of rows) {
    options.budget.take();
    const advisoryResponse = await fetch(
      `${options.osvBaseUrl}/${encodeURIComponent(options.ecosystem)}/${encodeURIComponent(row.id)}.json`,
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!advisoryResponse.ok) throw new Error(`OSV advisory failed (${advisoryResponse.status})`);
    const advisory = advisorySchema.parse(await advisoryResponse.json());
    const statements: D1PreparedStatement[] = [];
    for (const affected of advisory.affected.filter(
      (entry) => entry.package.ecosystem.split(":")[0] === options.ecosystem,
    )) {
      const components = (
        await options.database
          .prepare(
            "SELECT c.id,s.org_id,c.version FROM components c JOIN sboms s ON s.id=c.sbom_id AND s.retired_at IS NULL WHERE c.matchable=1 AND c.package_name=? AND (c.ecosystem=? OR c.ecosystem LIKE ?)",
          )
          .bind(affected.package.name, options.ecosystem, `${options.ecosystem}:%`)
          .all()
      ).results.map((component) => componentSchema.parse(component));
      if (components.length === 0) continue;
      statements.push(
        options.database
          .prepare(
            "INSERT INTO vulnerabilities (id,ecosystem,package_name,affected_ranges,severity,summary,modified_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id,ecosystem,package_name) DO UPDATE SET affected_ranges=excluded.affected_ranges,severity=excluded.severity,summary=excluded.summary,modified_at=excluded.modified_at",
          )
          .bind(
            advisory.id,
            options.ecosystem,
            affected.package.name,
            JSON.stringify({ ranges: affected.ranges, versions: affected.versions }),
            advisory.severity?.[0]?.score ?? null,
            advisory.summary ?? null,
            advisory.modified,
          ),
      );
      for (const component of components) {
        const comparison = await compareVersion({
          ecosystem: options.ecosystem,
          version: component.version,
          ranges: affected.ranges,
          versions: affected.versions,
        });
        if (comparison.kind === "match")
          statements.push(
            options.database
              .prepare("INSERT OR IGNORE INTO findings VALUES (?,?,?,?,NULL)")
              .bind(component.org_id, component.id, advisory.id, options.now ?? Date.now()),
          );
        if (comparison.kind === "unsupported" || comparison.kind === "error")
          statements.push(
            options.database
              .prepare(
                "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (?,?,?,?)",
              )
              .bind(component.id, advisory.id, comparison.reason, options.now ?? Date.now()),
          );
      }
    }
    const nextBoundary =
      row.modified === cursorTimestamp ? new Set([...cursorBoundary, row.id]) : new Set([row.id]);
    statements.push(
      options.database
        .prepare(
          "UPDATE sync_cursors SET last_synced_at=?,boundary_ids=?,continuation_id=? WHERE ecosystem=?",
        )
        .bind(
          row.modified,
          [...nextBoundary].sort().join(","),
          rows.at(-1)?.id === row.id ? null : row.id,
          options.ecosystem,
        ),
    );
    await options.database.batch(statements);
    cursorTimestamp = row.modified;
    cursorBoundary = nextBoundary;
  }
  return rows.length;
}
