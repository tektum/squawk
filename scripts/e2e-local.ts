import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sign } from "@octokit/webhooks-methods";
import { exportPKCS8, generateKeyPair } from "jose";
import { loadFixtures, type Origin, startOrigin } from "../test/e2e-local/origin";
import { publishedPayload } from "../test/e2e-local/payload";
import { checkImage, createReporter, printDiagnostics } from "../test/e2e-local/report";
import {
  applyMigrations,
  bindAddress,
  freePort,
  type LocalWorker,
  query,
  startWorker,
  writeLocalConfig,
} from "../test/e2e-local/harness";

const installationId = "151159455";
const repositoryId = "1316006990";
const tenantId = "local-tenant";

const { checks, record } = createReporter();

/**
 * Triggers exactly one scheduled pass and waits for the outcome it records. `scheduled`
 * hands work to `waitUntil`, so the HTTP response returns before anything is written.
 */
async function scheduledOnce(
  worker: LocalWorker,
  config: string,
  workspace: string,
): Promise<void> {
  const completed = (): number =>
    Number(
      query<RunsRow>(
        config,
        workspace,
        "SELECT COUNT(*) AS runs FROM public_activity WHERE kind='cron'",
      )[0]?.runs ?? 0,
    );
  const before = completed();
  const response = await fetch(`${worker.url}/__scheduled?cron=0+*/4+*+*+*`);
  if (!response.ok) throw new Error(`scheduled run failed with ${response.status}`);
  await response.text();
  const deadline = Date.now() + 30_000;
  while (completed() === before && Date.now() < deadline) await Bun.sleep(200);
  if (completed() === before) throw new Error("scheduled run never recorded an outcome");
}

/**
 * Each run advances ingestion, backfill, advisory resolution and dispatch within one
 * subrequest budget, so the pipeline needs several. `scheduled` hands the work to
 * `waitUntil`, so the HTTP response returns before anything is written: each run is
 * awaited through the completion row it records, never a sleep.
 */
async function drain(worker: LocalWorker, config: string, workspace: string): Promise<number> {
  const limit = 20;
  const completed = (): number =>
    Number(
      query<RunsRow>(
        config,
        workspace,
        "SELECT COUNT(*) AS runs FROM public_activity WHERE kind='cron'",
      )[0]?.runs ?? 0,
    );
  for (let run = 1; run <= limit; run += 1) {
    const before = completed();
    const response = await fetch(`${worker.url}/__scheduled?cron=0+*/4+*+*+*`);
    if (!response.ok) throw new Error(`scheduled run failed with ${response.status}`);
    await response.text();
    const deadline = Date.now() + 30_000;
    while (completed() === before && Date.now() < deadline) await Bun.sleep(200);
    if (completed() === before) throw new Error(`scheduled run ${run} never recorded an outcome`);
    const [outstanding] = query<RemainingRow>(
      config,
      workspace,
      `SELECT
         (SELECT COUNT(*) FROM github_ingestion_jobs) +
         (SELECT COUNT(*) FROM osv_advisory_jobs WHERE status<>'complete') +
         (SELECT COUNT(*) FROM sboms WHERE backfill_status IN ('pending','running')) +
         (SELECT COUNT(*) FROM findings WHERE dispatched_at IS NULL) AS remaining`,
    );
    if (Number(outstanding?.remaining ?? 0) === 0) return run;
  }
  const [outstanding] = query<RemainingRow>(
    config,
    workspace,
    `SELECT
       (SELECT COUNT(*) FROM github_ingestion_jobs) +
       (SELECT COUNT(*) FROM osv_advisory_jobs WHERE status<>'complete') +
       (SELECT COUNT(*) FROM sboms WHERE backfill_status IN ('pending','running')) +
       (SELECT COUNT(*) FROM findings WHERE dispatched_at IS NULL) AS remaining`,
  );
  throw new Error(
    `scheduled work did not drain after ${limit} runs (${String(outstanding?.remaining)} remaining)`,
  );
}

type Delivery = { readonly status: number; readonly body: string };
type CountRow = { readonly count: number };
type RunsRow = { readonly runs: number };
type ActivityRow = { readonly kind: string; readonly outcome: string; readonly count: number };
type DispatchPayload = { readonly vuln_id?: string; readonly logical_image_ref?: string };

async function deliver(
  worker: LocalWorker,
  secret: string,
  payload: unknown,
  deliveryId: string,
): Promise<Delivery> {
  const body = JSON.stringify(payload);
  const response = await fetch(`${worker.url}/webhooks/github`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-github-event": "registry_package",
      "x-github-delivery": deliveryId,
      // Signed by GitHub's own reference implementation, so a bug in our verifier
      // cannot be masked by the same bug in a hand-rolled test signer.
      "x-hub-signature-256": await sign(secret, body),
      "user-agent": "GitHub-Hookshot/local",
    },
    body,
  });
  return { status: response.status, body: (await response.text()).slice(0, 300) };
}

const workspace = mkdtempSync(join(tmpdir(), "squawk-e2e-"));
let worker: LocalWorker | undefined;
let origin: Origin | undefined;

try {
  // The Worker imports generated artefacts; a clean checkout has neither, and the
  // failure would otherwise surface as an opaque bundling error.
  for (const [artefact, build] of [
    ["src/generated/admin-client.ts", "scripts/build-admin.ts"],
    ["src/generated/osv_matcher.wasm", undefined],
  ] as const) {
    if (await Bun.file(artefact).exists()) continue;
    if (!build) throw new Error(`${artefact} is missing; run "bun run build:matcher" first`);
    console.log(`building ${artefact}`);
    const built = Bun.spawnSync(["bun", build], { stdout: "inherit", stderr: "inherit" });
    if (built.exitCode !== 0) throw new Error(`failed to build ${artefact}`);
  }
  const fixturesDir = join(import.meta.dir, "..", "test", "fixtures", "e2e");
  const fixtures = loadFixtures(fixturesDir);
  const hostname = bindAddress();
  origin = await startOrigin({ hostname, port: await freePort(hostname), fixturesDir });
  console.log(`origin  ${origin.url}`);

  const pair = await generateKeyPair("RS256", { extractable: true });
  const privateKey = await exportPKCS8(pair.privateKey);
  const webhookSecret = crypto.randomUUID();
  const vars = {
    GH_APP_ID: "42",
    GH_APP_INSTALLATION_ID: installationId,
    GH_WEBHOOK_SECRET: webhookSecret,
    GH_APP_PRIVATE_KEY: privateKey,
  };
  const config = writeLocalConfig(origin.url);
  applyMigrations(config, workspace);

  worker = await startWorker({
    config,
    persistTo: workspace,
    vars,
    hostname,
    port: await freePort(hostname),
  });
  console.log(`worker  ${worker.url}`);

  query(
    config,
    workspace,
    `INSERT INTO orgs VALUES ('${tenantId}','local-app',0);
     INSERT INTO github_sources (installation_id,repository_id,org_id,dispatch_workflow,dispatch_ref,created_at)
     VALUES ('${installationId}','${repositoryId}','${tenantId}','monitor.yaml','main',0);`,
  );

  // A body signed with the wrong secret must be refused before it can create any work,
  // so this runs before the valid deliveries queue anything.
  const forged = await deliver(
    worker,
    "a-different-secret",
    publishedPayload(fixtures.images.vulnerable, { installationId, repositoryId }),
    crypto.randomUUID(),
  );
  const forgedJobs = query<CountRow>(
    config,
    workspace,
    "SELECT COUNT(*) AS count FROM github_ingestion_jobs",
  );
  record(
    "webhook signed with the wrong secret is rejected",
    forged.status === 401 && forgedJobs[0]?.count === 0,
    `HTTP ${forged.status}, ${String(forgedJobs[0]?.count)} ingestion jobs queued`,
  );

  for (const scenario of ["vulnerable", "clean"] as const) {
    const image = fixtures.images[scenario];
    const delivery = await deliver(
      worker,
      webhookSecret,
      publishedPayload(image, { installationId, repositoryId }),
      crypto.randomUUID(),
    );
    record(
      `${scenario}: webhook accepted`,
      delivery.status === 202 || delivery.status === 200,
      `HTTP ${delivery.status} for ${image.name}@${image.indexDigest.slice(0, 19)}${
        delivery.status >= 300 ? ` ${delivery.body}` : ""
      }`,
    );
  }

  const runs = await drain(worker, config, workspace);
  console.log(`scheduled runs to quiescence: ${runs}`);

  for (const scenario of ["vulnerable", "clean"] as const)
    checkImage(scenario, fixtures.images[scenario], config, workspace, record);

  const vulnerable = fixtures.images.vulnerable;
  const dispatched = origin.dispatches.filter(
    (record_) => record_.workflow === "monitor.yaml" && record_.ref === "main",
  );
  record(
    "dispatch reached the fake GitHub",
    dispatched.length > 0,
    `${dispatched.length} workflow_dispatch calls`,
  );
  const payloads = dispatched.map((record_) => record_.payload as DispatchPayload);
  record(
    "dispatch payload carries a real advisory for the vulnerable image",
    payloads.some(
      (payload) =>
        vulnerable.expectedFindings.some((finding) => finding.vulnId === payload.vuln_id) &&
        String(payload.logical_image_ref).startsWith(vulnerable.image),
    ),
    payloads
      .map((payload) => String(payload.vuln_id))
      .slice(0, 4)
      .join(","),
  );
  record(
    "no dispatch for the clean image",
    !payloads.some((payload) =>
      String(payload.logical_image_ref).startsWith(fixtures.images.clean.image),
    ),
    `clean image ${fixtures.images.clean.name}`,
  );

  // The regression that started this: ingestion used to spend the whole subrequest
  // allowance before dispatch was reached, so 1508 production findings never sent one.
  // Enqueueing is now D1-only, so a backlog cannot starve it.
  const backlog = 40;
  query(
    config,
    workspace,
    Array.from(
      { length: backlog },
      (_, index) =>
        `INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,created_at)
         VALUES ('sha256:${index.toString(16).padStart(64, "0")}','${installationId}','${repositoryId}','ghcr.io/tektum/backlog-${index}@sha256:${index.toString(16).padStart(64, "0")}','pending',0);`,
    ).join("\n"),
  );
  query(
    config,
    workspace,
    `DELETE FROM dispatch_deliveries;
     DELETE FROM public_activity;
     UPDATE findings SET dispatched_at=NULL;`,
  );
  origin.reset();
  // Exactly one pass. Draining to quiescence would hide the bug: later passes have no
  // ingestion left, so a budget-dependent dispatch would eventually deliver anyway.
  // Production never gets a clear pass, which is why it never dispatched at all.
  await scheduledOnce(worker, config, workspace);
  const deliveredBy = Date.now() + 20_000;
  while (origin.dispatches.length === 0 && Date.now() < deliveredBy) await Bun.sleep(250);

  const pressured = query<ActivityRow>(
    config,
    workspace,
    "SELECT kind, outcome, COUNT(*) AS count FROM public_activity GROUP BY kind, outcome",
  );
  const attempted = query<CountRow>(
    config,
    workspace,
    "SELECT COUNT(*) AS count FROM github_ingestion_jobs WHERE attempted_at IS NOT NULL",
  );
  record(
    "an ingestion backlog consumes the run's allowance",
    (attempted[0]?.count ?? 0) > 0,
    `${String(attempted[0]?.count)} of ${backlog} backlog jobs attempted`,
  );
  record(
    "dispatch still delivers under that backlog",
    origin.dispatches.length > 0,
    `${origin.dispatches.length} workflow_dispatch calls, activity ${pressured
      .filter((row) => row.kind === "dispatch")
      .map((row) => `${row.outcome}=${String(row.count)}`)
      .join(" ")}`,
  );

  const activity = query<ActivityRow>(
    config,
    workspace,
    "SELECT kind, outcome, COUNT(*) AS count FROM public_activity GROUP BY kind, outcome ORDER BY kind",
  );
  record(
    "pipeline recorded its own activity",
    activity.some((row) => row.kind === "cron" && row.outcome === "completed"),
    activity
      .map((row) => `${String(row["kind"])}/${String(row["outcome"])}=${String(row["count"])}`)
      .join(" "),
  );
  await printDiagnostics(checks, config, workspace, origin, worker);
} finally {
  await worker?.stop();
  await origin?.stop();
  rmSync(workspace, { recursive: true, force: true });
  rmSync("wrangler.e2e.local.json", { force: true });
}

const failed = checks.filter((check) => !check.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length > 0) process.exit(1);
