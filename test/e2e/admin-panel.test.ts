import { createExecutionContext, env } from "cloudflare:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { respond } from "../http";

const READS = ["pipeline.read"];

describe("admin panel", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare("INSERT INTO orgs VALUES ('other','app',0)"),
      env.DB.prepare(
        "INSERT INTO github_sources (installation_id,repository_id,org_id,created_at,dispatch_workflow,dispatch_ref) VALUES ('1','2','tenant',0,'monitor.yaml','main')",
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,backfill_error,created_at,installation_id,repository_id) VALUES ('11111111-1111-4111-8111-111111111111','tenant','ghcr.io/t/ruby@sha256:abc','ghcr.io/t/ruby','linux/amd64','d1','failed','boom',100,'1','2')",
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at,retired_at) VALUES ('22222222-2222-4222-8222-222222222222','tenant','ghcr.io/t/old@sha256:def','ghcr.io/t/old','linux/arm64','d2','complete',90,95)",
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('33333333-3333-4333-8333-333333333333','other','ghcr.io/o/x@sha256:aaa','ghcr.io/o/x','linux/amd64','d3','complete',80)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'11111111-1111-4111-8111-111111111111','libcrypto3','Wolfi','3.6.3-r3','pkg:apk/wolfi/libcrypto3@3.6.3-r3',1)",
      ),
      env.DB.prepare(
        "INSERT INTO vulnerabilities VALUES ('CGA-1','Wolfi','libcrypto3','[]','high','openssl','2026-08-01')",
      ),
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',1,'CGA-1',120,NULL)"),
      env.DB.prepare(
        "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,next_descriptor,error,created_at) VALUES ('sha256:abc','1','2','ghcr.io/t/ruby','failed',12,'unparsable purl',110)",
      ),
      env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('Wolfi', 1000)"),
    ]);
  });

  it("serves a script-only shell that carries no tenant data", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/admin"),
      env,
      createExecutionContext(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(response.headers.get("content-security-policy")).toContain(
      "connect-src 'self' https://api.descope.com",
    );
    expect(body).toContain('data-project-id="');
    expect(body).not.toContain("tenant");
  });

  it("serves the bundled client and revalidates it by digest", async () => {
    const first = await worker.fetch(
      new Request("https://squawk.test/admin/app.js"),
      env,
      createExecutionContext(),
    );
    const etag = first.headers.get("etag") ?? "";

    expect(first.headers.get("content-type")).toBe("text/javascript; charset=utf-8");
    expect(first.headers.get("cache-control")).toContain("immutable");
    expect(await first.text()).toContain("descope");

    const second = await worker.fetch(
      new Request("https://squawk.test/admin/app.js", { headers: { "if-none-match": etag } }),
      env,
      createExecutionContext(),
    );
    expect(second.status).toBe(304);
  });

  it("refuses every read route without a session", async () => {
    for (const path of ["/v1/me", "/v1/orgs/tenant/overview", "/v1/orgs/tenant/jobs"]) {
      const response = await worker.fetch(
        new Request(`https://squawk.test${path}`),
        env,
        createExecutionContext(),
      );
      expect(response.status).toBe(401);
    }
  });

  it("reports the capabilities the panel may use", async () => {
    const response = await request("/v1/me", await authenticated(["vex.write", ...READS]));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      tenant_id: "tenant",
      user_id: "operator",
      capabilities: ["pipeline.read", "vex.write"],
    });
  });

  it("refuses pipeline reads without pipeline.read", async () => {
    const bindings = await authenticated(["findings.read"]);

    for (const path of [
      "/v1/orgs/tenant/overview",
      "/v1/orgs/tenant/images",
      "/v1/orgs/tenant/jobs",
      "/v1/orgs/tenant/sources",
    ]) {
      expect((await request(path, bindings)).status).toBe(403);
    }
  });

  it("refuses to read another tenant's pipeline", async () => {
    const bindings = await authenticated(READS);

    expect((await request("/v1/orgs/other/overview", bindings)).status).toBe(403);
    expect((await request("/v1/orgs/other/images", bindings)).status).toBe(403);
  });

  it("aggregates only the caller's tenant in the overview", async () => {
    const response = await request("/v1/orgs/tenant/overview", await authenticated(READS));
    const body = await response.json<{
      totals: {
        images: number;
        retired_sboms: number;
        components: number;
        findings: number;
        undispatched_findings: number;
      };
      sboms: Record<string, number>;
      findings: Record<string, number>;
      ingestion_jobs: Record<string, number>;
    }>();

    expect(body.totals.images).toBe(1);
    expect(body.totals.retired_sboms).toBe(1);
    expect(body.totals.components).toBe(1);
    expect(body.totals.findings).toBe(1);
    expect(body.totals.undispatched_findings).toBe(1);
    expect(body.sboms).toEqual({ failed: 1 });
    expect(body.findings).toEqual({ high: 1 });
    expect(body.ingestion_jobs).toEqual({ failed: 1 });
  });

  it("shows the backfill error the public inventory hides", async () => {
    const response = await request("/v1/orgs/tenant/images", await authenticated(READS));
    const body = await response.json<{ images: { id: string; backfill_error: string | null }[] }>();

    expect(body.images).toHaveLength(1);
    expect(body.images[0]?.backfill_error).toBe("boom");
  });

  it("includes retired images only when asked", async () => {
    const bindings = await authenticated(READS);
    const withRetired = await request("/v1/orgs/tenant/images?include_retired=true", bindings).then(
      (response) => response.json<{ images: unknown[] }>(),
    );

    expect(withRetired.images).toHaveLength(2);
  });

  it("refuses image detail belonging to another tenant", async () => {
    const bindings = await authenticated(READS);

    const foreign = await request(
      "/v1/orgs/tenant/images/33333333-3333-4333-8333-333333333333",
      bindings,
    );
    expect(foreign.status).toBe(404);

    const own = await request(
      "/v1/orgs/tenant/images/11111111-1111-4111-8111-111111111111",
      bindings,
    );
    expect(own.status).toBe(200);
    await expect(
      own.json<{ findings: { vuln_id: string }[] }>().then((body) => body.findings[0]?.vuln_id),
    ).resolves.toBe("CGA-1");
  });

  it("exposes stalled job errors and the dispatch target", async () => {
    const bindings = await authenticated(READS);
    const jobs = await request("/v1/orgs/tenant/jobs", bindings).then((response) =>
      response.json<{ ingestion: { error: string | null; next_descriptor: number }[] }>(),
    );
    const sources = await request("/v1/orgs/tenant/sources", bindings).then((response) =>
      response.json<{ sources: { dispatch_workflow: string | null; sboms: number }[] }>(),
    );

    expect(jobs.ingestion[0]).toMatchObject({ error: "unparsable purl", next_descriptor: 12 });
    expect(sources.sources[0]).toMatchObject({ dispatch_workflow: "monitor.yaml", sboms: 1 });
  });
});

type Bindings = {
  readonly token: string;
  readonly env: Omit<typeof env, "DESCOPE_BASE_URL" | "DESCOPE_PROJECT_ID"> & {
    readonly DESCOPE_BASE_URL: string;
    readonly DESCOPE_PROJECT_ID: string;
  };
};

async function request(path: string, bindings: Bindings): Promise<Response> {
  return worker.fetch(
    new Request(`https://squawk.test${path}`, {
      headers: { authorization: `Bearer ${bindings.token}` },
    }),
    bindings.env,
    createExecutionContext(),
  );
}

async function authenticated(permissions: readonly string[]): Promise<Bindings> {
  const baseUrl = `https://${crypto.randomUUID()}.admin-panel.test`;
  const projectId = crypto.randomUUID();
  const pair = await generateKeyPair("RS256");
  const jwk = await exportJWK(pair.publicKey);
  respond({
    url: `${baseUrl}/v2/keys/${projectId}`,
    status: 200,
    body: { keys: [{ ...jwk, kid: "admin-key", alg: "RS256", use: "sig" }] },
  });
  const token = await new SignJWT({ tenants: { tenant: { permissions, roles: [] } } })
    .setProtectedHeader({ alg: "RS256", kid: "admin-key" })
    .setIssuer(projectId)
    .setAudience("audience")
    .setSubject("operator")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(pair.privateKey);
  return { token, env: { ...env, DESCOPE_BASE_URL: baseUrl, DESCOPE_PROJECT_ID: projectId } };
}
