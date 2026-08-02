import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import {
  githubWebhookFixture,
  INSTALLATION_ID,
  type FailureCase,
  REPOSITORY_ID,
} from "../fixtures/github-webhook";

describe("GitHub deployment webhook", () => {
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

  it("ingests the repository attestation when the deployment wire contract is valid", async () => {
    const fixture = await githubWebhookFixture();
    const context = createExecutionContext();
    const response = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      context,
    );

    expect(response.status, await response.clone().text()).toBe(202);
    await waitOnExecutionContext(context);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(1);
    expect(
      await env.DB.prepare("SELECT status FROM github_deliveries").first<string>("status"),
    ).toBe("accepted");
  });

  it("returns success without repeating ingestion when GitHub replays a delivery", async () => {
    const fixture = await githubWebhookFixture();
    const context = createExecutionContext();
    const first = await worker.fetch(fixture.request(), { ...env, ...fixture.bindings }, context);
    await waitOnExecutionContext(context);
    const replay = await worker.fetch(
      fixture.request(),
      { ...env, ...fixture.bindings },
      createExecutionContext(),
    );

    expect(first.status, await first.clone().text()).toBe(202);
    expect(replay.status).toBe(200);
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM github_deliveries").first<number>("COUNT(*)"),
    ).toBe(1);
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
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(1);
  });

  it.each([
    "signature",
    "event",
    "action",
    "task",
    "repository",
    "installation",
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
