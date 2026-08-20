import { z } from "zod";
import { sha256 } from "./digest";

export const activityKindSchema = z.enum(["webhook", "cron", "scan", "advisory"]);
export const activityOutcomeSchema = z.enum([
  "accepted",
  "pending",
  "ignored",
  "completed",
  "failed",
]);

const activitySchema = z.object({
  event_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  kind: activityKindSchema,
  outcome: activityOutcomeSchema,
  occurred_at: z.number().int().nonnegative(),
});

export type ActivityKind = z.infer<typeof activityKindSchema>;
export type ActivityOutcome = z.infer<typeof activityOutcomeSchema>;

export async function recordActivity(
  database: D1Database,
  kind: ActivityKind,
  outcome: ActivityOutcome,
  occurredAt = Date.now(),
): Promise<void> {
  const eventSha256 = await sha256(
    `${kind}\u0000${outcome}\u0000${occurredAt}\u0000${crypto.randomUUID()}`,
  );
  try {
    await database
      .prepare(
        "INSERT INTO public_activity (event_sha256,kind,outcome,occurred_at) VALUES (?,?,?,?)",
      )
      .bind(eventSha256, kind, outcome, occurredAt)
      .run();
  } catch {
    console.error("Public activity recording failed", { kind, outcome });
  }
}

export async function activityResponse(database: D1Database): Promise<Response> {
  const result = await database
    .prepare(
      "SELECT event_sha256,kind,outcome,occurred_at FROM public_activity ORDER BY occurred_at DESC,event_sha256 DESC LIMIT 100",
    )
    .all();
  const activities = result.results.map((row) => activitySchema.parse(row));
  return new Response(renderActivity(activities), {
    headers: {
      "content-security-policy":
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
      "content-type": "text/html; charset=utf-8",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}

function renderActivity(activities: readonly z.infer<typeof activitySchema>[]): string {
  const rows = activities
    .map(
      (activity) => `<li class="event ${activity.outcome}">
      <span class="rail" aria-hidden="true"></span><div class="event-body">
      <div class="event-head"><span class="kind">${labels[activity.kind]}</span><span class="outcome">${activity.outcome}</span></div>
      <time datetime="${new Date(activity.occurred_at).toISOString()}">${formatTime(activity.occurred_at)}</time>
      <code title="Immutable event digest">${activity.event_sha256.slice(0, 12)}</code></div></li>`,
    )
    .join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Squawk activity</title><style>${styles}</style></head><body><nav><a class="wordmark" href="/">SQUAWK</a><span>public operations record</span></nav><main>
  <header><p class="eyebrow">SYSTEM ACTIVITY</p><h1>The pulse, without the payload.</h1>
  <p>Public operational history for incoming hooks, scheduled runs, vulnerability scans, and advisory processing. Identifiers and request data stay private.</p></header>
  <section><div class="section-head"><h2>Latest events</h2><span>${activities.length} shown</span></div>
  <ol>${rows || `<li class="empty">No activity recorded yet.</li>`}</ol></section>
  <footer><a href="/">image inventory</a><span>Only event type, outcome, time, and an opaque digest are published.</span></footer>
  </main></body></html>`;
}

const labels: Record<ActivityKind, string> = {
  webhook: "Webhook",
  cron: "Scheduled run",
  scan: "Vulnerability scan",
  advisory: "Advisory processing",
};

function formatTime(timestamp: number): string {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(timestamp);
}

const styles = `:root{color-scheme:dark;--ink:#e8edf2;--muted:#7f94a1;--line:#172732;--surface:#0a1720;--void:#060d12;--teal:#00f0cc;--orange:#fb923c;--red:#f87171;--mono:"SFMono-Regular",Consolas,monospace}*{box-sizing:border-box}body{margin:0;background:var(--void);color:var(--ink);font-family:var(--mono);background-image:linear-gradient(90deg,transparent 29px,rgba(0,240,204,.035) 30px,transparent 31px)}nav{height:58px;padding:0 max(20px,calc((100% - 920px)/2));display:flex;align-items:center;gap:16px;border-bottom:1px solid var(--line);background:rgba(6,13,18,.92);position:sticky;top:0;z-index:2}.wordmark{font-size:17px;letter-spacing:.18em;color:var(--ink);text-decoration:none}nav span,.eyebrow,.section-head span,footer{font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)}main{max-width:920px;margin:auto;padding:0 24px 64px}header{padding:64px 0 46px;border-bottom:1px solid var(--line)}.eyebrow{color:var(--teal);margin:0}h1{font-size:clamp(29px,5vw,48px);font-weight:400;letter-spacing:-.04em;margin:18px 0}header>p:last-child{max-width:680px;color:#9db0bb;line-height:1.75;font-size:14px}.section-head{display:flex;align-items:baseline;justify-content:space-between;margin:42px 0 18px}h2{font-size:18px;font-weight:400;margin:0}ol{list-style:none;margin:0;padding:0;border:1px solid var(--line);background:var(--surface)}.event{display:grid;grid-template-columns:38px 1fr;min-height:92px;border-bottom:1px solid var(--line)}.event:last-child{border-bottom:0}.rail{position:relative}.rail:before{content:"";position:absolute;left:18px;top:0;bottom:0;width:1px;background:var(--line)}.rail:after{content:"";position:absolute;left:14px;top:24px;width:7px;height:7px;border:1px solid var(--teal);background:var(--void);transform:rotate(45deg)}.failed .rail:after{border-color:var(--red)}.pending .rail:after{border-color:var(--orange)}.event-body{display:grid;grid-template-columns:1fr auto;gap:9px 24px;padding:20px 22px 18px 6px}.event-head{display:flex;align-items:center;gap:12px}.kind{font-size:14px}.outcome{padding:3px 7px;border:1px solid rgba(0,240,204,.3);color:var(--teal);font-size:9px;letter-spacing:.12em;text-transform:uppercase}.failed .outcome{border-color:rgba(248,113,113,.35);color:var(--red)}.pending .outcome{border-color:rgba(251,146,60,.35);color:var(--orange)}time,code{font-size:11px;color:var(--muted)}code{grid-column:2;grid-row:2}.empty{padding:28px;color:var(--muted)}footer{display:flex;justify-content:space-between;gap:24px;margin-top:34px;line-height:1.6}a{color:var(--teal)}a:focus-visible{outline:2px solid var(--teal);outline-offset:3px}@media(max-width:560px){header{padding:42px 0 32px}.event-body{grid-template-columns:1fr}.event-head{align-items:flex-start;flex-direction:column}.event-body code{grid-column:1;grid-row:auto}footer{flex-direction:column}}`;
