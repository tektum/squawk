import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { exportPKCS8, generateKeyPair } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";
import { runScheduled } from "../../src/scheduled";
import { githubWebhookFixture, INSTALLATION_ID, REPOSITORY_ID } from "../fixtures/github-webhook";
import { respond } from "../http";

describe("vulnerable published image", () => {
  beforeEach(async () => {
    await env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)").run();
    await env.DB.prepare(
      "INSERT INTO github_sources (installation_id,repository_id,org_id,repository_full_name,dispatch_workflow,created_at) VALUES (?,?,?,?,?,0)",
    )
      .bind(String(INSTALLATION_ID), String(REPOSITORY_ID), "tenant", "owner/demo", "monitor.yaml")
      .run();
  });

  it("detects and dispatches lodash 4.17.20", async () => {
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
});
