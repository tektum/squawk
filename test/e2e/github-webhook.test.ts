import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { enqueueIngestion } from "../../src/webhook-ingestion";
import {
  type FailureCase,
  githubWebhookFixture,
  INSTALLATION_ID,
  REPOSITORY_ID,
} from "../fixtures/github-webhook";

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

    expect(responses.map((response) => response.status)).toEqual([202, 202]);
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
  it("ignores deleted package activity", async () => {
    const fixture = await githubWebhookFixture("ignored");
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      createExecutionContext(),
    );

    expect(response.status).toBe(204);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(0);
  });

  it("ignores SPDX statements without platform identities", async () => {
    const fixture = await githubWebhookFixture("index-only");
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      createExecutionContext(),
    );

    expect(response.status).toBe(204);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(0);
  });

  it("persists an unattested image for scheduled retry", async () => {
    const visibility = { value: false };
    const fixture = await githubWebhookFixture(undefined, 200, 789, visibility);
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      createExecutionContext(),
    );

    expect(response.status, await response.clone().text()).toBe(202);
    expect(await response.json()).toEqual({ status: "pending" });
    expect(
      await env.DB.prepare("SELECT status FROM github_ingestion_jobs").first<string>("status"),
    ).toBe("pending");
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM github_deliveries").first<number>("COUNT(*)"),
    ).toBe(0);
  });

  it("keeps identical digests isolated by GitHub source", async () => {
    const fixture = await githubWebhookFixture("unattested");
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('peer','app','peer/repo','monitor.yaml',0)"),
      env.DB.prepare(
        "INSERT INTO github_sources (installation_id,repository_id,org_id,workflow,ref,created_at) VALUES ('999','999','peer','registry_package','',0)",
      ),
    ]);
    const first = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      createExecutionContext(),
    );
    const firstJob = await env.DB.prepare(
      "SELECT subject_digest FROM github_ingestion_jobs",
    ).first<{ readonly subject_digest: string }>();
    if (!firstJob) throw new Error("expected pending job");
    const event = {
      deliveryId: crypto.randomUUID(),
      deploymentId: "peer-deployment",
      image: "ghcr.io/owner/demo",
      installationId: "999",
      repositoryId: "999",
      subjectDigest: firstJob.subject_digest,
    };
    await enqueueIngestion({ ...env, ...fixture.bindings } as never, event);

    expect(first.status).toBe(202);
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM github_ingestion_jobs").first<number>("COUNT(*)"),
    ).toBe(2);
  });

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
