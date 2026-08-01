import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { respond } from "../http";

describe("authenticated HTTP pipeline", () => {
  beforeEach(async () => {
    await env.DB.prepare(
      "INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)",
    ).run();
  });

  it("ingests, backfills, queries, applies human VEX, and retires through HTTP", async () => {
    const issuer = "https://pipeline.test";
    const pair = await generateKeyPair("RS256");
    const jwk = await exportJWK(pair.publicKey);
    respond({
      url: `${issuer}/.well-known/openid-configuration`,
      status: 200,
      body: { issuer, jwks_uri: `${issuer}/jwks` },
    });
    respond({
      url: `${issuer}/jwks`,
      status: 200,
      body: { keys: [{ ...jwk, kid: "key", alg: "RS256", use: "sig" }] },
    });
    respond({
      method: "POST",
      url: "https://osv.test/v1/querybatch",
      status: 200,
      body: {
        results: [
          {
            vulns: [
              {
                id: "OSV-1",
                modified: "2020-01-01T00:00:00Z",
                affected: [
                  {
                    package: { ecosystem: "npm", name: "demo" },
                    ranges: [
                      { type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] },
                    ],
                    versions: [],
                  },
                ],
              },
            ],
          },
        ],
      },
    });
    const sign = (claims: Record<string, unknown>) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "RS256", kid: "key" })
        .setIssuer(issuer)
        .setAudience("audience")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(pair.privateKey);
    const machine = await sign({ tenants: ["tenant"], permissions: ["sbom.write"] });
    const human = await sign({
      sub: "user",
      tenants: ["tenant"],
      permissions: ["findings.read", "vex.write"],
    });
    const predicate = {
      bomFormat: "CycloneDX",
      components: [{ name: "demo", version: "1.5.0", purl: "pkg:npm/demo@1.5.0" }],
    };
    const bytes = new TextEncoder().encode(JSON.stringify(predicate));
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (value) =>
      value.toString(16).padStart(2, "0"),
    ).join("");
    const bindings = {
      ...env,
      DESCOPE_ISSUER: issuer,
      DESCOPE_AUDIENCE: "audience",
      DESCOPE_DISCOVERY_URL: `${issuer}/.well-known/openid-configuration`,
      OSV_BASE_URL: "https://osv.test",
      DISPATCH_ENABLED: "false",
    };
    const context = createExecutionContext();
    const submitted = await worker.fetch(
      new Request("https://squawk.test/v1/sboms", {
        method: "POST",
        headers: { authorization: `Bearer ${machine}`, "content-type": "application/json" },
        body: JSON.stringify({
          image_ref: `ghcr.io/x@sha256:${"a".repeat(64)}`,
          logical_image_ref: `ghcr.io/x@sha256:${"b".repeat(64)}`,
          platform: "linux/amd64",
          idempotency_key: hash,
          predicate,
        }),
      }),
      bindings,
      context,
    );
    expect(submitted.status).toBe(202);
    const body = await submitted.json<{ readonly sbom_id: string }>();
    await waitOnExecutionContext(context);
    expect(
      await env.DB.prepare("SELECT backfill_status FROM sboms WHERE id=?")
        .bind(body.sbom_id)
        .first<string>("backfill_status"),
    ).toBe("complete");
    expect(
      await env.DB.prepare("SELECT COUNT(*) AS count FROM findings").first<number>("count"),
    ).toBe(1);
    const findings = await worker.fetch(
      new Request("https://squawk.test/v1/orgs/tenant/findings", {
        headers: { authorization: `Bearer ${human}` },
      }),
      bindings,
      createExecutionContext(),
    );
    expect(
      (await findings.json<{ readonly findings: readonly unknown[] }>()).findings,
    ).toHaveLength(1);
    const vex = await worker.fetch(
      new Request("https://squawk.test/v1/orgs/tenant/vex", {
        method: "POST",
        headers: { authorization: `Bearer ${human}`, "content-type": "application/json" },
        body: JSON.stringify({
          package_name: "demo",
          ecosystem: "npm",
          vuln_id: "OSV-1",
          status: "not_affected",
        }),
      }),
      bindings,
      createExecutionContext(),
    );
    expect(vex.status).toBe(204);
    const suppressed = await worker.fetch(
      new Request("https://squawk.test/v1/orgs/tenant/findings", {
        headers: { authorization: `Bearer ${human}` },
      }),
      bindings,
      createExecutionContext(),
    );
    expect(
      (await suppressed.json<{ readonly findings: readonly unknown[] }>()).findings,
    ).toHaveLength(0);
    const retired = await worker.fetch(
      new Request(`https://squawk.test/v1/sboms/${body.sbom_id}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${machine}` },
      }),
      bindings,
      createExecutionContext(),
    );
    expect(retired.status).toBe(204);
  });
});
