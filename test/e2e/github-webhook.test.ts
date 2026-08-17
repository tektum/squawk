import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { exportPKCS8, generateKeyPair } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { runScheduled } from "../../src/scheduled";
import { statementSchema, webhookSchema } from "../../src/webhook-contract";
import {
  type FailureCase,
  githubWebhookFixture,
  INSTALLATION_ID,
  REPOSITORY_ID,
} from "../fixtures/github-webhook";
import { respond } from "../http";

describe("GitHub registry package webhook", () => {
  beforeEach(async () => {
    await env.DB.prepare(
      "INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)",
    ).run();
    await env.DB.prepare(
      "INSERT INTO github_sources (installation_id,repository_id,org_id,workflow,ref,created_at) VALUES (?,?,?,?,?,0)",
    )
      .bind(
        String(INSTALLATION_ID),
        String(REPOSITORY_ID),
        "tenant",
        ".github/workflows/build.yaml",
        "refs/heads/main",
      )
      .run();
  });

  it("preserves a manifests path segment in a published package URI", () => {
    const parsed = webhookSchema.safeParse({
      action: "published",
      installation: { id: 1 },
      registry_package: {
        id: 1,
        name: "demo",
        namespace: "owner",
        package_type: "container",
        package_version: {
          id: 2,
          container_metadata: {
            tag: { name: "latest", digest: `sha256:${"b".repeat(64)}` },
            manifest: {
              digest: `sha256:${"b".repeat(64)}`,
              media_type: "application/vnd.oci.image.index.v1+json",
              uri: `repositories/owner/team/manifests/manifests/sha256:${"b".repeat(64)}`,
            },
          },
        },
      },
      repository: { id: 1, full_name: "owner/repo" },
      sender: { id: 1, login: "github-actions[bot]" },
    });

    expect(parsed.success).toBe(true);
    if (parsed.success)
      expect(parsed.data.registry_package.package_version.container_metadata.manifest.uri).toBe(
        "owner/team/manifests",
      );
  });

  it("rejects an SPDX predicate labeled as CycloneDX at the attestation boundary", () => {
    expect(
      statementSchema.safeParse({
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: "ghcr.io/owner/demo", digest: { sha256: "a".repeat(64) } }],
        predicateType: "https://cyclonedx.org/bom",
        predicate: { spdxVersion: "SPDX-2.3", packages: [] },
      }).success,
    ).toBe(false);
  });

  it("ingests both platform SBOMs for a published image index", async () => {
    const fixture = await githubWebhookFixture();
    const context = createExecutionContext();
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      context,
    );

    expect(response.status, await response.clone().text()).toBe(202);
    await waitOnExecutionContext(context);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(2);
    expect(
      await env.DB.prepare("SELECT status FROM github_deliveries").first<string>("status"),
    ).toBe("accepted");
  });
  it("detects and dispatches lodash 4.17.20 from a published image", async () => {
    const fixture = await githubWebhookFixture("vulnerable");
    const context = createExecutionContext();
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      context,
    );
    await waitOnExecutionContext(context);
    const keys = await generateKeyPair("RS256", { extractable: true });
    respond({
      method: "POST",
      url: `https://api.github.com/app/installations/${INSTALLATION_ID}/access_tokens`,
      status: 201,
      body: { token: "installation-token" },
    });
    respond({
      method: "POST",
      url: "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
      status: 204,
    });
    await env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 1)").run();
    await runScheduled(
      {
        ...env,
        ...fixture.bindings,
        DISPATCH_ENABLED: "true",
        GH_APP_ID: "1234",
        GH_APP_INSTALLATION_ID: String(INSTALLATION_ID),
        OSV_API_URL: "https://api.osv.test",
        OSV_BASE_URL: "https://osv.test",
        GH_APP_PRIVATE_KEY: await exportPKCS8(keys.privateKey),
      },
      2_000,
    );

    expect(response.status, await response.clone().text()).toBe(202);
    await expect(
      env.DB.prepare("SELECT COUNT(*) AS count FROM sboms WHERE backfill_status='complete'").first(
        "count",
      ),
    ).resolves.toBe(2);
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) AS count FROM findings WHERE vuln_id='GHSA-35jh-r3h4-6jhm'",
      ).first("count"),
    ).resolves.toBe(2);
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) AS count FROM dispatch_deliveries WHERE status='accepted'",
      ).first("count"),
    ).resolves.toBe(1);
  });

  it("ingests one SBOM per platform when attestations are repeated", async () => {
    const fixture = await githubWebhookFixture("duplicates");
    const context = createExecutionContext();
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      context,
    );
    await waitOnExecutionContext(context);

    expect(response.status, await response.clone().text()).toBe(202);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(2);
  });

  it("ignores unrelated manifests in a large referrer index", async () => {
    const fixture = await githubWebhookFixture("noisy-index");
    const context = createExecutionContext();
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      context,
    );
    await waitOnExecutionContext(context);

    expect(response.status, await response.clone().text()).toBe(202);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(2);
  });

  it("returns success without repeating ingestion when GitHub replays a delivery", async () => {
    const fixture = await githubWebhookFixture();
    const context = createExecutionContext();
    const first = await worker.fetch(fixture.request(), { ...env, ...fixture.bindings }, context);
    await waitOnExecutionContext(context);
    await env.DB.prepare("UPDATE sboms SET backfill_status='failed'").run();
    const replayContext = createExecutionContext();
    const replay = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      replayContext,
    );
    await waitOnExecutionContext(replayContext);

    expect(first.status, await first.clone().text()).toBe(202);
    expect(replay.status).toBe(200);
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM github_deliveries").first<number>("COUNT(*)"),
    ).toBe(1);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(2);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) FROM sboms WHERE backfill_status='complete'",
      ).first<number>("COUNT(*)"),
    ).toBe(2);
  });

  it("accepts concurrent copies of one delivery without duplicate state", async () => {
    const fixture = await githubWebhookFixture();
    const contexts = [createExecutionContext(), createExecutionContext()];
    const responses = await Promise.all(
      contexts.map((context) =>
        worker.fetch(fixture.request(), { ...env, ...fixture.bindings }, context),
      ),
    );
    await Promise.all(contexts.map(waitOnExecutionContext));

    expect(responses.map((response) => response.status).sort()).toEqual([200, 202]);
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM github_deliveries").first<number>("COUNT(*)"),
    ).toBe(1);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(2);
  });

  it("rejects changed predicate content for an existing image digest", async () => {
    const first = await githubWebhookFixture();
    const firstContext = createExecutionContext();
    const accepted = await worker.fetch(
      first.request(),
      { ...env, ...first.bindings },
      firstContext,
    );
    await waitOnExecutionContext(firstContext);
    const changed = await githubWebhookFixture("changed");
    const rejected = await worker.fetch(
      changed.request(),
      { ...env, ...changed.bindings },
      createExecutionContext(),
    );

    expect(accepted.status).toBe(202);
    expect(rejected.status).toBe(409);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(2);
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM components WHERE version='2.0.0'").first<number>(
        "COUNT(*)",
      ),
    ).toBe(0);
  });

  it.each([
    "signature",
    "event",
    "installation",
    "repository",
    "predicate",
    "subject",
  ] satisfies readonly FailureCase[])("fails closed for a wrong %s", async (failure) => {
    const fixture = await githubWebhookFixture(failure);
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      createExecutionContext(),
    );

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(0);
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM github_deliveries").first<number>("COUNT(*)"),
    ).toBe(0);
  });

  it.each(["ignored", "index-only", "unattested"] satisfies readonly FailureCase[])(
    "ignores %s package activity",
    async (failure) => {
      const fixture = await githubWebhookFixture(failure);
      const response = await worker.fetch(
        fixture.request(),
        { ...env, ...fixture.bindings },
        createExecutionContext(),
      );

      expect(response.status).toBe(204);
      expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(0);
    },
  );

  it("leaves no delivery receipt when GitHub fails transiently", async () => {
    const fixture = await githubWebhookFixture(undefined, 503);
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      createExecutionContext(),
    );

    expect(response.status, await response.clone().text()).toBe(502);
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM github_deliveries").first<number>("COUNT(*)"),
    ).toBe(0);
  });

  it("rejects a declared oversized body before buffering it", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/webhooks/github", {
        method: "POST",
        headers: { "content-length": "65537" },
        body: "{}",
      }),
      env,
      createExecutionContext(),
    );

    expect(response.status).toBe(413);
  });
});
