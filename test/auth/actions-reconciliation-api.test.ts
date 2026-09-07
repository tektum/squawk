import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../../src/index";
import { refreshReconciliationCheckpoints } from "../../src/reconciliation-state";
import { refreshRetirementCheckpoints } from "../../src/retirement-checkpoint";
import { recordingQueue } from "../queue";
import { actionsToken, installActionsJwks, workflowRefSha256 } from "./actions-fixture";

installActionsJwks();
const logical = `ghcr.io/owner/demo@sha256:${"a".repeat(64)}`;
const deliveryId = "b".repeat(64);
type ApiFixture = {
  readonly auth: string;
  readonly bindings: never;
  readonly checkpointId: string;
  readonly payloadSha256: string;
  readonly producer: { readonly sent: readonly unknown[] };
  readonly revision: number;
  readonly route: string;
};

async function seedApi(dispatchEnabled = "true") {
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
    env.DB.prepare(
      "INSERT INTO github_sources (installation_id,repository_id,org_id,dispatch_workflow,dispatch_ref,created_at,dispatch_schema_version) VALUES ('123','9','tenant','monitor.yaml','main',0,2)",
    ),
    env.DB.prepare(
      "INSERT INTO github_deliveries (delivery_id,installation_id,repository_id,statement_sha256,status,created_at,completed_at,subject_digest) VALUES ('inbound','123','9','statement','accepted',1,2,?)",
    ).bind(`sha256:${"a".repeat(64)}`),
    env.DB.prepare(
      "INSERT INTO advisory_feed_checks (checkpoint_id,ecosystem,cursor_modified_at,checked_at,completed_at,discovery_complete,status,error) VALUES (?,'npm','2026-09-06T00:00:00Z',?,?,1,'complete',NULL)",
    ).bind("f".repeat(64), now - 1_000, now - 500),
  ]);
  for (const [index, platform] of ["linux/amd64", "linux/arm64"].entries())
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at,installation_id,repository_id) VALUES (?,'tenant',?,?,?,?,'complete',1,'123','9')",
      ).bind(
        `sbom-${index}`,
        `ghcr.io/owner/demo@sha256:${String(index + 1).repeat(64)}`,
        logical,
        platform,
        String(index + 3).repeat(64),
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (?,?,'demo','npm','1.0.0','pkg:npm/demo@1.0.0',1)",
      ).bind(index + 1, `sbom-${index}`),
    ]);
  await refreshReconciliationCheckpoints(env.DB, now);
  const current = await env.DB.prepare(
    `SELECT r.revision,r.checkpoint_id,c.payload_sha256 FROM image_reconciliation_state r
     JOIN reconciliation_checkpoints c ON c.checkpoint_id=r.checkpoint_id`,
  ).first<{ revision: number; checkpoint_id: string; payload_sha256: string }>();
  if (!current) throw new Error("missing checkpoint");
  await env.DB.prepare(
    "INSERT INTO reconciliation_deliveries (delivery_id,installation_id,repository_id,logical_image_ref,target_revision,status,workflow_run_id,attempt_id,workflow_ref_sha256,created_at) VALUES (?,'123','9',?,?,'dispatched','77','attempt-1',?,0)",
  )
    .bind(deliveryId, logical, current.revision, workflowRefSha256)
    .run();
  const producer = recordingQueue();
  return {
    auth: `Bearer ${await actionsToken()}`,
    bindings: {
      ...env,
      DISPATCH_ENABLED: dispatchEnabled,
      FINDING_DISPATCH: producer.queue,
    } as never,
    checkpointId: current.checkpoint_id,
    payloadSha256: current.payload_sha256,
    producer,
    revision: current.revision,
    route: `/v1/actions/reconciliations/${deliveryId}`,
  };
}

async function fetchCheckpoint(fixture: ApiFixture) {
  return worker.fetch(
    new Request(`https://squawk.test${fixture.route}`, {
      headers: { authorization: fixture.auth },
    }),
    fixture.bindings,
    createExecutionContext(),
  );
}

function ackRequest(fixture: ApiFixture) {
  return new Request(`https://squawk.test${fixture.route}/ack`, {
    method: "POST",
    headers: { authorization: fixture.auth, "content-type": "application/json" },
    body: JSON.stringify({
      checkpoint_id: fixture.checkpointId,
      revision: fixture.revision,
      payload_sha256: fixture.payloadSha256,
    }),
  });
}

describe("Actions reconciliation API", () => {
  it("rejects an acknowledgement before serving the checkpoint", async () => {
    const fixture = await seedApi();
    const response = await worker.fetch(
      ackRequest(fixture),
      fixture.bindings,
      createExecutionContext(),
    );
    expect(response.status).toBe(409);
  });

  it("serves the latest bound checkpoint", async () => {
    const fixture = await seedApi();
    const response = await fetchCheckpoint(fixture);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      schema_version: 2,
      state: "ready",
      checkpoint: {
        checkpoint_id: fixture.checkpointId,
        revision: fixture.revision,
        payload_sha256: fixture.payloadSha256,
      },
    });
  });

  it("rejects an acknowledgement after inventory generation changes", async () => {
    const fixture = await seedApi();
    await fetchCheckpoint(fixture);
    await env.DB.prepare("UPDATE image_inventory_generations SET generation=generation+1").run();
    const response = await worker.fetch(
      ackRequest(fixture),
      fixture.bindings,
      createExecutionContext(),
    );
    expect(response.status).toBe(409);
    await expect(
      env.DB.prepare("SELECT status FROM reconciliation_deliveries").first("status"),
    ).resolves.toBe("dispatched");
  });

  it("rejects an acknowledgement from a superseded workflow run", async () => {
    const fixture = await seedApi();
    await fetchCheckpoint(fixture);
    await env.DB.prepare(
      "UPDATE reconciliation_deliveries SET workflow_run_id='78',attempt_id='attempt-2'",
    ).run();
    const response = await worker.fetch(
      ackRequest(fixture),
      fixture.bindings,
      createExecutionContext(),
    );
    expect(response.status).toBe(403);
  });

  it("acknowledges the exact served checkpoint", async () => {
    const fixture = await seedApi();
    await fetchCheckpoint(fixture);
    const context = createExecutionContext();
    const response = await worker.fetch(ackRequest(fixture), fixture.bindings, context);
    expect(response.status).toBe(204);
    await waitOnExecutionContext(context);
    await expect(
      env.DB.prepare("SELECT applied_revision FROM image_reconciliation_state").first(
        "applied_revision",
      ),
    ).resolves.toBe(fixture.revision);
  });

  it("does not enqueue follow-up work while dispatch is paused", async () => {
    const fixture = await seedApi("false");
    await fetchCheckpoint(fixture);
    const context = createExecutionContext();
    const response = await worker.fetch(ackRequest(fixture), fixture.bindings, context);
    expect(response.status).toBe(204);
    await waitOnExecutionContext(context);
    expect(fixture.producer.sent).toEqual([]);
  });

  it("serves an authoritative retirement without replacing it with inventory blocked", async () => {
    const fixture = await seedApi();
    await env.DB.prepare("UPDATE sboms SET retired_at=?").bind(Date.now()).run();
    await env.DB.prepare(
      `INSERT INTO authoritative_retirements
       (event_id,installation_id,repository_id,logical_image_ref,replacement_logical_image_ref,
        replacement_published_at,replacement_run_url,retired_at,created_at)
       VALUES ('retirement-event','123','9',?,?,1,'https://github.com/owner/repo/actions/runs/42',2,2)`,
    )
      .bind(logical, `ghcr.io/owner/demo@sha256:${"9".repeat(64)}`)
      .run();
    await refreshRetirementCheckpoints(env.DB, Date.now());

    const response = await fetchCheckpoint(fixture);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      state: "ready",
      checkpoint: { kind: "retirement", authoritative_source_event_id: "retirement-event" },
    });
  });
});
