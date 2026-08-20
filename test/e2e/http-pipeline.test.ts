import { createExecutionContext, env } from "cloudflare:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { respond } from "../http";

describe("human HTTP pipeline", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('00000000-0000-4000-8000-000000000001','tenant','image','logical','linux/amd64','digest','complete',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'00000000-0000-4000-8000-000000000001','demo','npm','1.5.0','pkg:npm/demo@1.5.0',1)",
      ),
      env.DB.prepare(
        "INSERT INTO vulnerabilities (id,ecosystem,package_name,affected_ranges,modified_at) VALUES ('OSV-1','npm','demo','[]','2020-01-01T00:00:00Z')",
      ),
      env.DB.prepare(
        "INSERT INTO findings (org_id,component_id,vuln_id,detected_at) VALUES ('tenant',1,'OSV-1',0)",
      ),
    ]);
  });

  it("queries findings, applies VEX, and retires data with a human principal", async () => {
    const baseUrl = "https://pipeline.test";
    const projectId = "pipeline-project";
    const pair = await generateKeyPair("RS256");
    const jwk = await exportJWK(pair.publicKey);
    respond({
      url: `${baseUrl}/v2/keys/${projectId}`,
      status: 200,
      body: { keys: [{ ...jwk, kid: "key", alg: "RS256", use: "sig" }] },
    });
    const token = await new SignJWT({
      tenants: {
        tenant: { permissions: ["sbom.manage", "findings.read", "vex.write"], roles: [] },
      },
    })
      .setProtectedHeader({ alg: "RS256", kid: "key" })
      .setIssuer(projectId)
      .setAudience("audience")
      .setSubject("user")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(pair.privateKey);
    const bindings = {
      ...env,
      DESCOPE_AUDIENCE: "audience",
      DESCOPE_BASE_URL: baseUrl,
      DESCOPE_PROJECT_ID: projectId,
    };
    const headers = { authorization: `Bearer ${token}` };
    const findings = await worker.fetch(
      new Request("https://squawk.test/v1/orgs/tenant/findings", { headers }),
      bindings,
      createExecutionContext(),
    );
    expect(
      (await findings.json<{ readonly findings: readonly unknown[] }>()).findings,
    ).toHaveLength(1);
    const vex = await worker.fetch(
      new Request("https://squawk.test/v1/orgs/tenant/vex", {
        method: "POST",
        headers: { ...headers, "content-type": "application/json" },
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
    const retired = await worker.fetch(
      new Request("https://squawk.test/v1/sboms/00000000-0000-4000-8000-000000000001", {
        method: "DELETE",
        headers,
      }),
      bindings,
      createExecutionContext(),
    );
    expect(retired.status).toBe(204);
  });
});
