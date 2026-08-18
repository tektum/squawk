import { createExecutionContext, env } from "cloudflare:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { respond } from "../http";

describe("manual scheduled operation", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)"),
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
});

async function authenticatedBindings(permissions: readonly string[], subject: string | undefined) {
  const authIssuer = `https://${crypto.randomUUID()}.manual-scheduled.test`;
  const pair = await generateKeyPair("RS256");
  const jwk = await exportJWK(pair.publicKey);
  respond({
    url: `${authIssuer}/.well-known/openid-configuration`,
    status: 200,
    body: { issuer: authIssuer, jwks_uri: `${authIssuer}/jwks` },
  });
  respond({
    url: `${authIssuer}/jwks`,
    status: 200,
    body: { keys: [{ ...jwk, kid: "manual-key", alg: "RS256", use: "sig" }] },
  });
  let token = new SignJWT({ tenants: ["tenant"], permissions })
    .setProtectedHeader({ alg: "RS256", kid: "manual-key" })
    .setIssuer(authIssuer)
    .setAudience("audience")
    .setIssuedAt()
    .setExpirationTime("5m");
  if (subject) token = token.setSubject(subject);
  return {
    token: await token.sign(pair.privateKey),
    env: {
      ...env,
      DESCOPE_ISSUER: authIssuer,
      DESCOPE_AUDIENCE: "audience",
      DESCOPE_DISCOVERY_URL: `${authIssuer}/.well-known/openid-configuration`,
      DISPATCH_ENABLED: "false",
    },
  };
}
