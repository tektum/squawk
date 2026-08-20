import { z } from "zod";
import { recordActivity } from "./activity";
import type { SubrequestBudget } from "./budget";
import { compareVersion } from "./osv/comparator";

export const backfillLeaseMilliseconds = 20 * 60_000;

const componentSchema = z.object({
  id: z.number(),
  package_name: z.string(),
  ecosystem: z.string(),
  version: z.string(),
});
const vulnerabilitySchema = z.object({
  id: z.string(),
  modified: z.string(),
  summary: z.string().optional(),
  severity: z.array(z.object({ type: z.string(), score: z.string() })).optional(),
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
const queryBatchSchema = z.object({
  results: z.array(z.object({ vulns: z.array(vulnerabilitySchema).optional() })),
});

type BackfillOptions = {
  readonly database: D1Database;
  readonly sbomId: string;
  readonly osvApiUrl: string;
  readonly now?: number;
  readonly budget?: SubrequestBudget;
};

export async function backfillSbom(options: BackfillOptions): Promise<void> {
  const now = options.now ?? Date.now();
  const claim = await options.database
    .prepare(
      "UPDATE sboms SET backfill_status='running',backfill_attempted_at=?,backfill_error=NULL WHERE id=? AND retired_at IS NULL AND (backfill_status IN ('pending','failed') OR (backfill_status='running' AND COALESCE(backfill_attempted_at,0)<?))",
    )
    .bind(now, options.sbomId, now - backfillLeaseMilliseconds)
    .run();
  if (claim.meta.changes === 0) return;
  try {
    const components = (
      await options.database
        .prepare(
          "SELECT c.id,c.package_name,c.ecosystem,c.version FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE c.sbom_id=? AND c.matchable=1 AND s.retired_at IS NULL",
        )
        .bind(options.sbomId)
        .all()
    ).results.map((row) => componentSchema.parse(row));
    if (components.length === 0) {
      await options.database
        .prepare("UPDATE sboms SET backfill_status='complete',backfill_error=NULL WHERE id=?")
        .bind(options.sbomId)
        .run();
      await recordActivity(options.database, "scan", "completed", now);
      return;
    }
    options.budget?.take();
    const response = await fetch(`${options.osvApiUrl}/v1/querybatch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: components.map((component) => ({
          package: { name: component.package_name, ecosystem: component.ecosystem },
          version: component.version,
        })),
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`OSV querybatch failed (${response.status})`);
    const batch = queryBatchSchema.parse(await response.json());
    for (const [index, result] of batch.results.entries()) {
      const component = components[index];
      if (!component) throw new Error("OSV querybatch result count mismatch");
      for (const vulnerability of result.vulns ?? []) {
        const affected = vulnerability.affected.find(
          (candidate) =>
            candidate.package.name === component.package_name &&
            candidate.package.ecosystem === component.ecosystem,
        );
        if (!affected) continue;
        await options.database
          .prepare(
            "INSERT INTO vulnerabilities (id,ecosystem,package_name,affected_ranges,severity,summary,modified_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id,ecosystem,package_name) DO UPDATE SET affected_ranges=excluded.affected_ranges,severity=excluded.severity,summary=excluded.summary,modified_at=excluded.modified_at",
          )
          .bind(
            vulnerability.id,
            component.ecosystem,
            component.package_name,
            JSON.stringify({ ranges: affected.ranges, versions: affected.versions }),
            vulnerability.severity?.[0]?.score ?? null,
            vulnerability.summary ?? null,
            vulnerability.modified,
          )
          .run();
        const comparison = await compareVersion({
          ecosystem: component.ecosystem,
          version: component.version,
          ranges: affected.ranges,
          versions: affected.versions,
        });
        if (comparison.kind === "match") {
          await options.database
            .prepare(
              "INSERT OR IGNORE INTO findings (org_id,component_id,vuln_id,detected_at) SELECT s.org_id,?,?,? FROM sboms s WHERE s.id=? AND s.retired_at IS NULL",
            )
            .bind(component.id, vulnerability.id, now, options.sbomId)
            .run();
        } else if (comparison.kind === "unsupported" || comparison.kind === "error") {
          await options.database
            .prepare(
              "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (?,?,?,?) ON CONFLICT(component_id,vuln_id) DO UPDATE SET reason=excluded.reason,created_at=excluded.created_at",
            )
            .bind(component.id, vulnerability.id, comparison.reason, now)
            .run();
        }
      }
    }
    await options.database
      .prepare("UPDATE sboms SET backfill_status='complete',backfill_error=NULL WHERE id=?")
      .bind(options.sbomId)
      .run();
    await recordActivity(options.database, "scan", "completed", now);
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown backfill error";
    await options.database
      .prepare("UPDATE sboms SET backfill_status='failed',backfill_error=? WHERE id=?")
      .bind(message.slice(0, 500), options.sbomId)
      .run();
    await recordActivity(options.database, "scan", "failed", now);
    throw error;
  }
}
