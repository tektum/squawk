import { createExecutionContext, env } from "cloudflare:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { respond } from "../http";

describe("manual scheduled operation", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('pending','tenant','image','logical','linux/amd64','digest','failed',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (sbom_id,package_name,ecosystem,version,purl,matchable) VALUES ('pending','image','unknown:oci','digest','pkg:oci/image@digest',0)",
      ),
      env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 1000)"),
    ]);
  });

  it("requires authentication", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/v1/operations/scheduled", { method: "POST" }),
      env,
      createExecutionContext(),
    );
    expect(response.status).toBe(401);
  });

  it.each([
    ["a human without operations.run", ["findings.read"], "user"],
    ["a non-human principal", ["operations.run"], undefined],
  ] as const)("rejects %s", async (_name, permissions, subject) => {
    const bindings = await authenticatedBindings(permissions, subject);
    const response = await worker.fetch(
      new Request("https://squawk.test/v1/operations/scheduled", {
        method: "POST",
        headers: { authorization: `Bearer ${bindings.token}` },
      }),
      bindings.env,
      createExecutionContext(),
    );
    expect(response.status).toBe(403);
  });

  it("runs scheduled work for an authorized human", async () => {
    const bindings = await authenticatedBindings(["operations.run"], "operator");
    const response = await worker.fetch(
      new Request("https://squawk.test/v1/operations/scheduled", {
        method: "POST",
        headers: { authorization: `Bearer ${bindings.token}` },
      }),
      bindings.env,
      createExecutionContext(),
    );

    expect(response.status).toBe(204);
    await expect(
      env.DB.prepare("SELECT backfill_status FROM sboms WHERE id='pending'").first(
        "backfill_status",
      ),
    ).resolves.toBe("complete");
  });

  it("releases only an exact quarantined attempt while dispatch is paused", async () => {
    const deliveryId = "a".repeat(64);
    const attemptId = crypto.randomUUID();
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO github_sources (installation_id,repository_id,org_id,dispatch_workflow,dispatch_ref,created_at) VALUES ('1','2','tenant','monitor.yaml','main',0)",
      ),
      env.DB.prepare(
        `INSERT INTO reconciliation_deliveries
         (delivery_id,installation_id,repository_id,logical_image_ref,target_revision,status,
          attempt_id,attempted_at,error,created_at)
         VALUES (?,'1','2',?,1,'pending',?,1,'workflow dispatch outcome unknown',1)`,
      ).bind(deliveryId, `ghcr.io/owner/demo@sha256:${"b".repeat(64)}`, attemptId),
    ]);
    const bindings = await authenticatedBindings(["operations.run"], "operator");
    const request = (dispatchEnabled: string) =>
      worker.fetch(
        new Request(`https://squawk.test/v1/orgs/tenant/reconciliations/${deliveryId}/release`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${bindings.token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ attempt_id: attemptId }),
        }),
        { ...bindings.env, DISPATCH_ENABLED: dispatchEnabled },
        createExecutionContext(),
      );

    expect((await request("true")).status).toBe(409);
    expect((await request("false")).status).toBe(204);
    await expect(
      env.DB.prepare("SELECT attempt_id FROM reconciliation_deliveries").first("attempt_id"),
    ).resolves.toBeNull();
  });
});

async function authenticatedBindings(permissions: readonly string[], subject: string | undefined) {
  const baseUrl = `https://${crypto.randomUUID()}.manual-scheduled.test`;
  const projectId = crypto.randomUUID();
  const pair = await generateKeyPair("RS256");
  const jwk = await exportJWK(pair.publicKey);
  respond({
    url: `${baseUrl}/v2/keys/${projectId}`,
    status: 200,
    body: { keys: [{ ...jwk, kid: "manual-key", alg: "RS256", use: "sig" }] },
  });
  let token = new SignJWT({ tenants: { tenant: { permissions, roles: [] } } })
    .setProtectedHeader({ alg: "RS256", kid: "manual-key" })
    .setIssuer(projectId)
    .setAudience("audience")
    .setIssuedAt()
    .setExpirationTime("5m");
  if (subject) token = token.setSubject(subject);
  return {
    token: await token.sign(pair.privateKey),
    env: {
      ...env,
      DESCOPE_BASE_URL: baseUrl,
      DESCOPE_PROJECT_ID: projectId,
      DISPATCH_ENABLED: "false",
    },
  };
}
