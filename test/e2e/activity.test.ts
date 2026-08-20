import { createExecutionContext, env } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordActivity } from "../../src/activity";
import worker from "../../src/index";

const digest = "a".repeat(64);

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO public_activity (event_sha256,kind,outcome,occurred_at) VALUES (?,'webhook','accepted',1000)",
    ).bind(digest),
    env.DB.prepare(
      "INSERT INTO public_activity (event_sha256,kind,outcome,occurred_at) VALUES (?,'cron','completed',2000)",
    ).bind("b".repeat(64)),
  ]);
});

describe("public activity history", () => {
  it("renders only public-safe event metadata without authentication", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/activity"),
      env,
      createExecutionContext(),
    );
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(html).toContain("Squawk activity");
    expect(html).toContain("Scheduled run");
    expect(html).toContain("Webhook");
    expect(html.indexOf("Scheduled run")).toBeLessThan(html.indexOf("Webhook"));
    expect(html).toContain("aaaaaaaaaaaa");
    expect(html).not.toContain(digest);
    expect(html).not.toMatch(/owner|repository|tenant|email|secret|payload value/i);
  });

  it("records webhook failures without persisting request content", async () => {
    const secret = "not-public";
    const response = await worker.fetch(
      new Request("https://squawk.test/webhooks/github", {
        method: "POST",
        headers: { "x-hub-signature-256": "sha256=invalid" },
        body: JSON.stringify({ secret }),
      }),
      { ...env, GH_WEBHOOK_SECRET: "test-secret" },
      createExecutionContext(),
    );

    expect(response.status).toBeGreaterThanOrEqual(400);
    await expect(
      env.DB.prepare(
        "SELECT kind,outcome,COUNT(*) AS count FROM public_activity WHERE occurred_at>2000 GROUP BY kind,outcome",
      ).first(),
    ).resolves.toMatchObject({ kind: "webhook", outcome: "failed", count: 1 });
    const stored = JSON.stringify(
      (await env.DB.prepare("SELECT * FROM public_activity WHERE occurred_at>2000").all()).results,
    );
    expect(stored).not.toContain(secret);
    expect(stored).not.toContain("invalid");
  });

  it("does not fail operations when activity storage is unavailable", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const database = {
      prepare: () => ({
        bind: () => ({ run: async () => Promise.reject(new Error("storage unavailable")) }),
      }),
    } as unknown as D1Database;

    await expect(recordActivity(database, "cron", "completed", 3000)).resolves.toBeUndefined();
    expect(error).toHaveBeenCalledWith("Public activity recording failed", {
      kind: "cron",
      outcome: "completed",
    });
    error.mockRestore();
  });
});
