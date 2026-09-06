import { createExecutionContext, env } from "cloudflare:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { HttpResponse, http } from "msw";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { authenticateActionsRun, reconciliationAudience } from "../../src/actions-oidc";
import worker from "../../src/index";
import { refreshReconciliationCheckpoints } from "../../src/reconciliation-state";
import { recordingQueue } from "../queue";
import { server } from "../server";

let signingKey: CryptoKey;
const keyId = "actions-test-key";
let publicJwk: JsonWebKey;
const binding = {
  repositoryId: "9",
  runId: "77",
  workflowRefSha256: "9c8629e077b28b0fe69f38b3b14ba13b4de8c9e40b80d498fbb7ed2273962eae",
};
const validClaims = {
  repository_id: "9",
  run_id: "77",
  event_name: "workflow_dispatch",
  actor_id: "312570741",
  workflow_ref: "owner/repo/.github/workflows/monitor.yaml@refs/heads/main",
};

async function token(
  claims: Record<string, unknown> = validClaims,
  options: { issuer?: string; audience?: string; expired?: boolean; key?: CryptoKey } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: keyId })
    .setIssuer(options.issuer ?? "https://token.actions.githubusercontent.com")
    .setAudience(options.audience ?? reconciliationAudience)
    .setIssuedAt(now - 1)
    .setExpirationTime(options.expired ? now - 1 : now + 300)
    .sign(options.key ?? signingKey);
}
beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  signingKey = pair.privateKey;
  publicJwk = await exportJWK(pair.publicKey);
});

beforeEach(() => {
  server.use(
    http.get("https://token.actions.githubusercontent.com/.well-known/jwks", () =>
      HttpResponse.json({ keys: [{ ...publicJwk, kid: keyId, alg: "RS256", use: "sig" }] }),
    ),
  );
});

describe("GitHub Actions reconciliation identity", () => {
  it("accepts only the exact persisted run and workflow binding", async () => {
    await expect(
      authenticateActionsRun(`Bearer ${await token()}`, binding),
    ).resolves.toBeUndefined();
  });

  it.each([
    ["issuer", { issuer: "https://issuer.invalid" }, validClaims],
    ["audience", { audience: "wrong" }, validClaims],
    ["expiry", { expired: true }, validClaims],
    ["repository", {}, { ...validClaims, repository_id: "10" }],
    ["event", {}, { ...validClaims, event_name: "push" }],
    ["run", {}, { ...validClaims, run_id: "78" }],
    ["actor", {}, { ...validClaims, actor_id: "1" }],
    [
      "workflow",
      {},
      { ...validClaims, workflow_ref: "owner/repo/.github/workflows/other.yaml@refs/heads/main" },
    ],
    [
      "workflow repository",
      {},
      {
        ...validClaims,
        workflow_ref: "attacker/repo/.github/workflows/monitor.yaml@refs/heads/main",
      },
    ],
  ])("rejects a wrong %s claim", async (_name, options, claims) => {
    await expect(
      authenticateActionsRun(`Bearer ${await token(claims, options)}`, binding),
    ).rejects.toThrow();
  });

  it("rejects a token signed by an untrusted key", async () => {
    const attacker = await generateKeyPair("RS256");
    await expect(
      authenticateActionsRun(
        `Bearer ${await token(validClaims, { key: attacker.privateKey })}`,
        binding,
      ),
    ).rejects.toThrow();
  });
});

describe("Actions reconciliation API", () => {
  it("serves and acknowledges only the latest bound checkpoint", async () => {
    const now = Date.now();
    const logical = `ghcr.io/owner/demo@sha256:${"a".repeat(64)}`;
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
    const checkpointId = current.checkpoint_id;
    const payloadSha256 = current.payload_sha256;
    await env.DB.prepare(
      "INSERT INTO reconciliation_deliveries (delivery_id,installation_id,repository_id,logical_image_ref,target_revision,status,workflow_run_id,attempt_id,workflow_ref_sha256,created_at) VALUES (?,'123','9',?,?,'dispatched','77','attempt-1',?,0)",
    )
      .bind(
        "b".repeat(64),
        logical,
        current.revision,
        "9c8629e077b28b0fe69f38b3b14ba13b4de8c9e40b80d498fbb7ed2273962eae",
      )
      .run();
    const auth = `Bearer ${await token()}`;
    const bindings = {
      ...env,
      FINDING_DISPATCH: recordingQueue().queue,
    } as never;
    const route = `/v1/actions/reconciliations/${"b".repeat(64)}`;
    const unserved = await worker.fetch(
      new Request(`https://squawk.test${route}/ack`, {
        method: "POST",
        headers: { authorization: auth, "content-type": "application/json" },
        body: JSON.stringify({
          checkpoint_id: checkpointId,
          revision: current.revision,
          payload_sha256: payloadSha256,
        }),
      }),
      bindings,
      createExecutionContext(),
    );
    expect(unserved.status).toBe(409);
    const response = await worker.fetch(
      new Request(`https://squawk.test${route}`, { headers: { authorization: auth } }),
      bindings,
      createExecutionContext(),
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      schema_version: 2,
      state: "ready",
      checkpoint: {
        checkpoint_id: checkpointId,
        revision: current.revision,
        payload_sha256: payloadSha256,
      },
    });

    await env.DB.prepare("UPDATE image_inventory_generations SET generation=generation+1").run();
    const generationStaleAck = await worker.fetch(
      new Request(`https://squawk.test${route}/ack`, {
        method: "POST",
        headers: { authorization: auth, "content-type": "application/json" },
        body: JSON.stringify({
          checkpoint_id: checkpointId,
          revision: current.revision,
          payload_sha256: payloadSha256,
        }),
      }),
      bindings,
      createExecutionContext(),
    );
    expect(generationStaleAck.status).toBe(409);
    await env.DB.prepare(
      `UPDATE image_reconciliation_state SET inventory_generation=(
        SELECT generation FROM image_inventory_generations
      )`,
    ).run();

    await env.DB.prepare(
      "UPDATE reconciliation_deliveries SET workflow_run_id='78',attempt_id='attempt-2' WHERE delivery_id=?",
    )
      .bind("b".repeat(64))
      .run();
    const priorRunAck = await worker.fetch(
      new Request(`https://squawk.test${route}/ack`, {
        method: "POST",
        headers: { authorization: auth, "content-type": "application/json" },
        body: JSON.stringify({
          checkpoint_id: checkpointId,
          revision: current.revision,
          payload_sha256: payloadSha256,
        }),
      }),
      bindings,
      createExecutionContext(),
    );
    expect(priorRunAck.status).toBe(403);
    await env.DB.prepare(
      "UPDATE reconciliation_deliveries SET workflow_run_id='77',attempt_id='attempt-1' WHERE delivery_id=?",
    )
      .bind("b".repeat(64))
      .run();

    await env.DB.prepare(
      `UPDATE image_reconciliation_state SET revision=${current.revision + 1},state='blocked',reason='feed_incomplete'`,
    ).run();
    const blocked = await worker.fetch(
      new Request(`https://squawk.test${route}`, { headers: { authorization: auth } }),
      bindings,
      createExecutionContext(),
    );
    expect(blocked.status).toBe(409);
    await expect(blocked.json()).resolves.toEqual({
      schema_version: 2,
      state: "blocked",
      delivery_id: "b".repeat(64),
      revision: current.revision + 1,
      reason: "feed_incomplete",
    });
    const staleAcknowledgement = await worker.fetch(
      new Request(`https://squawk.test${route}/ack`, {
        method: "POST",
        headers: { authorization: auth, "content-type": "application/json" },
        body: JSON.stringify({
          checkpoint_id: checkpointId,
          revision: current.revision,
          payload_sha256: payloadSha256,
        }),
      }),
      bindings,
      createExecutionContext(),
    );
    expect(staleAcknowledgement.status).toBe(409);
    await expect(
      env.DB.prepare("SELECT status FROM reconciliation_deliveries").first("status"),
    ).resolves.toBe("dispatched");
    await env.DB.prepare(
      `UPDATE image_reconciliation_state SET revision=${current.revision},state='ready',reason=NULL`,
    ).run();

    const acknowledgement = await worker.fetch(
      new Request(`https://squawk.test${route}/ack`, {
        method: "POST",
        headers: { authorization: auth, "content-type": "application/json" },
        body: JSON.stringify({
          checkpoint_id: checkpointId,
          revision: current.revision,
          payload_sha256: payloadSha256,
        }),
      }),
      bindings,
      createExecutionContext(),
    );
    expect(acknowledgement.status).toBe(204);
    await expect(
      env.DB.prepare("SELECT applied_revision FROM image_reconciliation_state").first(
        "applied_revision",
      ),
    ).resolves.toBe(current.revision);
  });
});
