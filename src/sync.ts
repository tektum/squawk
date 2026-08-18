import { z } from "zod";
import type { SubrequestBudget } from "./budget";
import { compareVersion } from "./osv/comparator";

export const advisoryJobSchema = z.object({
  advisoryId: z.string().min(1),
  ecosystem: z.string().min(1),
  modifiedAt: z.string().datetime(),
});
export type AdvisoryJob = z.infer<typeof advisoryJobSchema>;

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
const feedRowSchema = z.object({ modified: z.string().datetime(), id: z.string().min(1) });
type QueueSender = {
  sendBatch(messages: Iterable<MessageSendRequest<AdvisoryJob>>): Promise<unknown>;
};

type DiscoveryOptions = {
  readonly database: D1Database;
  readonly ecosystem: string;
  readonly osvBaseUrl: string;
  readonly queue: QueueSender;
  readonly budget: SubrequestBudget;
};

export async function discoverAdvisories(options: DiscoveryOptions): Promise<number> {
  const rawCursor = await options.database
    .prepare("SELECT last_synced_at,boundary_ids FROM sync_cursors WHERE ecosystem=?")
    .bind(options.ecosystem)
    .first();
  if (!rawCursor) return 0;
  const cursor = cursorSchema.parse(rawCursor);
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
      return feedRowSchema.parse({ modified, id });
    })
    .filter(
      (row) =>
        row.modified > cursor.last_synced_at ||
        (row.modified === cursor.last_synced_at && !boundary.has(row.id)),
    )
    .sort(
      (left, right) =>
        left.modified.localeCompare(right.modified) || left.id.localeCompare(right.id),
    );
  if (rows.length === 0) return 0;
  for (let offset = 0; offset < rows.length; offset += 100) {
    const chunk = rows.slice(offset, offset + 100);
    await options.database.batch(
      chunk.map((row) =>
        options.database
          .prepare(
            "INSERT INTO osv_advisory_jobs (ecosystem,advisory_id,modified_at,status) VALUES (?,?,?,'pending') ON CONFLICT(ecosystem,advisory_id) DO UPDATE SET modified_at=excluded.modified_at,status=CASE WHEN excluded.modified_at>osv_advisory_jobs.modified_at THEN 'pending' ELSE osv_advisory_jobs.status END,error=CASE WHEN excluded.modified_at>osv_advisory_jobs.modified_at THEN NULL ELSE osv_advisory_jobs.error END",
          )
          .bind(options.ecosystem, row.id, row.modified),
      ),
    );
    await options.queue.sendBatch(
      chunk.map((row) => ({
        body: {
          advisoryId: row.id,
          ecosystem: options.ecosystem,
          modifiedAt: row.modified,
        },
      })),
    );
  }
  const last = rows.at(-1);
  if (!last) return 0;
  const lastIds = rows
    .filter((row) => row.modified === last.modified)
    .map((row) => row.id)
    .sort();
  await options.database
    .prepare(
      "UPDATE sync_cursors SET last_synced_at=?,boundary_ids=?,continuation_id=NULL WHERE ecosystem=?",
    )
    .bind(last.modified, lastIds.join(","), options.ecosystem)
    .run();
  return rows.length;
}

type ProcessOptions = {
  readonly database: D1Database;
  readonly job: AdvisoryJob;
  readonly now?: number;
  readonly osvBaseUrl: string;
};

export async function processAdvisory(options: ProcessOptions): Promise<void> {
  const job = advisoryJobSchema.parse(options.job);
  const now = options.now ?? Date.now();
  const claim = await options.database
    .prepare(
      "UPDATE osv_advisory_jobs SET status='running',attempted_at=?,error=NULL WHERE ecosystem=? AND advisory_id=? AND modified_at=? AND status IN ('pending','failed')",
    )
    .bind(now, job.ecosystem, job.advisoryId, job.modifiedAt)
    .run();
  if (claim.meta.changes === 0) return;
  try {
    const response = await fetch(
      `${options.osvBaseUrl}/${encodeURIComponent(job.ecosystem)}/${encodeURIComponent(job.advisoryId)}.json`,
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!response.ok) throw new Error(`OSV advisory failed (${response.status})`);
    const advisory = advisorySchema.parse(await response.json());
    for (const affected of advisory.affected.filter(
      (entry) => entry.package.ecosystem.split(":")[0] === job.ecosystem,
    ))
      await persistAffected(options.database, job.ecosystem, advisory, affected, now);
    await options.database
      .prepare(
        "UPDATE osv_advisory_jobs SET status='complete',error=NULL WHERE ecosystem=? AND advisory_id=?",
      )
      .bind(job.ecosystem, job.advisoryId)
      .run();
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown advisory error";
    await options.database
      .prepare(
        "UPDATE osv_advisory_jobs SET status='failed',error=? WHERE ecosystem=? AND advisory_id=?",
      )
      .bind(message.slice(0, 500), job.ecosystem, job.advisoryId)
      .run();
    throw error;
  }
}

async function persistAffected(
  database: D1Database,
  ecosystem: string,
  advisory: z.infer<typeof advisorySchema>,
  affected: z.infer<typeof advisorySchema>["affected"][number],
  now: number,
): Promise<void> {
  const components = (
    await database
      .prepare(
        "SELECT c.id,s.org_id,c.version FROM components c JOIN sboms s ON s.id=c.sbom_id AND s.retired_at IS NULL WHERE c.matchable=1 AND c.package_name=? AND (c.ecosystem=? OR c.ecosystem LIKE ?)",
      )
      .bind(affected.package.name, ecosystem, `${ecosystem}:%`)
      .all()
  ).results.map((component) => componentSchema.parse(component));
  if (components.length === 0) return;
  const statements = [
    database
      .prepare(
        "INSERT INTO vulnerabilities (id,ecosystem,package_name,affected_ranges,severity,summary,modified_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id,ecosystem,package_name) DO UPDATE SET affected_ranges=excluded.affected_ranges,severity=excluded.severity,summary=excluded.summary,modified_at=excluded.modified_at",
      )
      .bind(
        advisory.id,
        ecosystem,
        affected.package.name,
        JSON.stringify({ ranges: affected.ranges, versions: affected.versions }),
        advisory.severity?.[0]?.score ?? null,
        advisory.summary ?? null,
        advisory.modified,
      ),
  ];
  for (const component of components) {
    const comparison = await compareVersion({
      ecosystem,
      version: component.version,
      ranges: affected.ranges,
      versions: affected.versions,
    });
    if (comparison.kind === "match")
      statements.push(
        database
          .prepare("INSERT OR IGNORE INTO findings VALUES (?,?,?,?,NULL)")
          .bind(component.org_id, component.id, advisory.id, now),
      );
    if (comparison.kind === "unsupported" || comparison.kind === "error")
      statements.push(
        database
          .prepare(
            "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (?,?,?,?) ON CONFLICT(component_id,vuln_id) DO UPDATE SET reason=excluded.reason,created_at=excluded.created_at",
          )
          .bind(component.id, advisory.id, comparison.reason, now),
      );
  }
  await database.batch(statements);
}

export async function syncEcosystem(options: {
  readonly database: D1Database;
  readonly ecosystem: string;
  readonly osvBaseUrl: string;
  readonly budget: SubrequestBudget;
  readonly maxAdvisories?: number;
  readonly now?: number;
}): Promise<number> {
  const messages: AdvisoryJob[] = [];
  const queue: QueueSender = {
    sendBatch: async (batch) => {
      for (const item of batch) messages.push(advisoryJobSchema.parse(item.body));
    },
  };
  await discoverAdvisories({
    database: options.database,
    ecosystem: options.ecosystem,
    osvBaseUrl: options.osvBaseUrl,
    budget: options.budget,
    queue,
  });
  const selected = messages.slice(0, options.maxAdvisories ?? options.budget.remaining);
  for (const job of selected)
    await processAdvisory({
      database: options.database,
      job,
      osvBaseUrl: options.osvBaseUrl,
      ...(options.now === undefined ? {} : { now: options.now }),
    });
  return selected.length;
}
