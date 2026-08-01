import { z } from "zod";
import { backfillSbom } from "./backfill";
import { SubrequestBudget } from "./budget";
import { dispatchPending } from "./dispatch";
import { syncEcosystem } from "./sync";

type ScheduledEnv = Parameters<typeof dispatchPending>[0] & {
  readonly DISPATCH_ENABLED: string;
  readonly OSV_BASE_URL: string;
};

export async function runScheduled(env: ScheduledEnv, now = Date.now()): Promise<void> {
  const budget = new SubrequestBudget(45);
  const backfills = await env.DB.prepare(
    "SELECT id FROM sboms WHERE retired_at IS NULL AND backfill_status IN ('pending','failed') ORDER BY COALESCE(backfill_attempted_at,0),created_at LIMIT 10",
  ).all<{ readonly id: string }>();
  for (const { id } of backfills.results) {
    if (budget.remaining <= 3) break;
    try {
      await backfillSbom({
        database: env.DB,
        sbomId: id,
        osvBaseUrl: env.OSV_BASE_URL,
        now,
        budget,
      });
    } catch (error) {
      if (!(error instanceof Error)) throw error;
    }
  }
  const cache = await env.DB.prepare(
    "SELECT MAX(cached_at) AS cached_at FROM osv_ecosystems",
  ).first<{ readonly cached_at: number | null }>();
  if (!cache?.cached_at || now - cache.cached_at >= 86_400_000) {
    budget.take();
    const response = await fetch(`${env.OSV_BASE_URL}/ecosystems.txt`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`OSV ecosystems failed (${response.status})`);
    const ecosystems = z.array(z.string().min(1)).parse(
      (await response.text())
        .split("\n")
        .map((value) => value.trim())
        .filter(Boolean),
    );
    await env.DB.batch(
      ecosystems.map((ecosystem) =>
        env.DB.prepare(
          "INSERT INTO osv_ecosystems (ecosystem,cached_at) VALUES (?,?) ON CONFLICT(ecosystem) DO UPDATE SET cached_at=excluded.cached_at",
        ).bind(ecosystem, now),
      ),
    );
  }
  const active = await env.DB.prepare(
    "SELECT DISTINCT CASE WHEN instr(c.ecosystem, ':')>0 THEN substr(c.ecosystem,1,instr(c.ecosystem,':')-1) ELSE c.ecosystem END AS ecosystem FROM components c JOIN sboms s ON s.id=c.sbom_id AND s.retired_at IS NULL JOIN osv_ecosystems e ON e.ecosystem=CASE WHEN instr(c.ecosystem, ':')>0 THEN substr(c.ecosystem,1,instr(c.ecosystem,':')-1) ELSE c.ecosystem END LEFT JOIN sync_cursors sc ON sc.ecosystem=e.ecosystem WHERE c.matchable=1 ORDER BY COALESCE(sc.last_synced_at,'')",
  ).all<{ readonly ecosystem: string }>();
  for (const { ecosystem } of active.results) {
    const cursor = await env.DB.prepare("SELECT ecosystem FROM sync_cursors WHERE ecosystem=?")
      .bind(ecosystem)
      .first();
    if (!cursor) {
      const pending = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE (c.ecosystem=? OR c.ecosystem LIKE ?) AND s.retired_at IS NULL AND s.backfill_status!='complete'",
      )
        .bind(ecosystem, `${ecosystem}:%`)
        .first<number>("count");
      if (pending === 0)
        await env.DB.prepare(
          "INSERT INTO sync_cursors (ecosystem,last_synced_at,boundary_ids) VALUES (?,?,'')",
        )
          .bind(ecosystem, new Date(now).toISOString())
          .run();
    } else {
      if (budget.remaining > 3) {
        try {
          await syncEcosystem({
            database: env.DB,
            ecosystem,
            osvBaseUrl: env.OSV_BASE_URL,
            budget,
            maxAdvisories: 1,
            now,
          });
        } catch (error) {
          if (!(error instanceof Error)) throw error;
        }
      }
    }
  }
  if (env.DISPATCH_ENABLED === "true" && budget.remaining > 1)
    await dispatchPending(env, now, budget);
}
