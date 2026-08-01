import { env } from "cloudflare:test";
import { exportPKCS8, generateKeyPair } from "jose";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { dispatchPending } from "../../src/dispatch";
import { runScheduled } from "../../src/scheduled";
import { respond } from "../http";

describe("durable multi-platform dispatch", () => {
  beforeEach(async () => {
    await env.DB.prepare(
      "INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)",
    ).run();
    for (const [index, platform] of ["linux/amd64", "linux/arm64"].entries()) {
      const sbom = `sbom-${index}`;
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES (?,'tenant',?,?,?,?,'complete',0)",
        ).bind(
          sbom,
          `ghcr.io/x@sha256:${String(index + 1).repeat(64)}`,
          `ghcr.io/x@sha256:${"a".repeat(64)}`,
          platform,
          "b".repeat(64),
        ),
        env.DB.prepare(
          "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (?,?,?,?,?,?,1)",
        ).bind(index + 1, sbom, "demo", "npm", "1.5.0", "pkg:npm/demo@1.5.0"),
        env.DB.prepare("INSERT INTO findings VALUES ('tenant',?,'OSV-1',0,NULL)").bind(index + 1),
      ]);
    }
    await env.DB.prepare(
      "INSERT INTO vulnerabilities VALUES ('OSV-1','npm','demo','{}','high','summary','2026-01-01T00:00:00Z')",
    ).run();
  });

  it("sends one stable delivery and marks both findings", async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    const privateKey = await exportPKCS8(pair.privateKey);
    respond({
      method: "POST",
      url: "https://api.github.com/app/installations/123/access_tokens",
      status: 201,
      body: { token: "installation-token" },
    });
    respond({
      method: "POST",
      url: "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
      status: 204,
    });
    const dispatchEnv = {
      DB: env.DB,
      GH_APP_ID: "42",
      GH_APP_INSTALLATION_ID: "123",
      GH_APP_PRIVATE_KEY: privateKey,
    };

    expect(await dispatchPending(dispatchEnv, 1000)).toBe(1);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM dispatch_deliveries WHERE status='accepted'",
      ).first<number>("count"),
    ).toBe(1);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM findings WHERE dispatched_at IS NOT NULL",
      ).first<number>("count"),
    ).toBe(2);
    expect(await dispatchPending(dispatchEnv, 2000)).toBe(0);
  });

  it.each([429, 500])("keeps a %s GitHub dispatch retryable", async (status) => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    const privateKey = await exportPKCS8(pair.privateKey);
    respond({
      method: "POST",
      url: "https://api.github.com/app/installations/123/access_tokens",
      status: 201,
      body: { token: "installation-token" },
    });
    respond({
      method: "POST",
      url: "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
      status,
    });

    expect(
      await dispatchPending(
        {
          DB: env.DB,
          GH_APP_ID: "42",
          GH_APP_INSTALLATION_ID: "123",
          GH_APP_PRIVATE_KEY: privateKey,
        },
        1000,
      ),
    ).toBe(1);
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) AS count FROM dispatch_deliveries WHERE status='failed'",
      ).first<number>("count"),
    ).resolves.toBe(1);
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) AS count FROM findings WHERE dispatched_at IS NULL",
      ).first<number>("count"),
    ).resolves.toBe(2);
  });

  it("isolates a failing ecosystem and advances a peer fairly through runScheduled", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 1000)"),
      env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('PyPI', 1000)"),
      env.DB.prepare("INSERT INTO sync_cursors VALUES ('npm','2026-01-01T00:00:00Z','',NULL,NULL)"),
      env.DB.prepare(
        "INSERT INTO sync_cursors VALUES ('PyPI','2026-01-01T00:00:00Z','',NULL,NULL)",
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('peer','tenant',?,?, 'linux/amd64',?,'complete',0)",
      ).bind(
        `ghcr.io/x@sha256:${"c".repeat(64)}`,
        `ghcr.io/x@sha256:${"d".repeat(64)}`,
        "e".repeat(64),
      ),
      env.DB.prepare(
        "INSERT INTO components (sbom_id,package_name,ecosystem,version,purl,matchable) VALUES ('peer','demo','PyPI','1.5.0','pkg:pypi/demo@1.5.0',1)",
      ),
    ]);
    respond({ url: "https://osv.test/npm/modified_id.csv", status: 500 });
    respond({
      url: "https://osv.test/PyPI/modified_id.csv",
      status: 200,
      text: "modified,id\n2026-01-02T00:00:00Z,OSV-peer\n",
    });
    respond({
      url: "https://osv.test/PyPI/OSV-peer.json",
      status: 200,
      body: {
        id: "OSV-peer",
        modified: "2026-01-02T00:00:00Z",
        affected: [
          {
            package: { ecosystem: "PyPI", name: "demo" },
            ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
            versions: [],
          },
        ],
      },
    });

    await runScheduled(
      {
        ...env,
        OSV_BASE_URL: "https://osv.test",
        DISPATCH_ENABLED: "false",
        GH_APP_ID: "",
        GH_APP_INSTALLATION_ID: "",
        GH_APP_PRIVATE_KEY: "",
      },
      2_000,
    );

    await expect(
      env.DB.prepare("SELECT last_synced_at FROM sync_cursors WHERE ecosystem='PyPI'").first(
        "last_synced_at",
      ),
    ).resolves.toBe("2026-01-02T00:00:00Z");
    await expect(
      env.DB.prepare("SELECT last_synced_at FROM sync_cursors WHERE ecosystem='npm'").first(
        "last_synced_at",
      ),
    ).resolves.toBe("2026-01-01T00:00:00Z");
    expect(error).toHaveBeenCalledWith(
      "Scheduled OSV sync failed",
      expect.objectContaining({ ecosystem: "npm" }),
    );
    error.mockRestore();
  });
});
