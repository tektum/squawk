import { env } from "cloudflare:test";
import { exportPKCS8, generateKeyPair } from "jose";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { backfillSbom } from "../../src/backfill";
import { dispatchPending } from "../../src/dispatch";
import { respond } from "../http";

const dispatchEnv = async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  return {
    DB: env.DB,
    GH_APP_ID: "42",
    GH_APP_INSTALLATION_ID: "123",
    GH_APP_PRIVATE_KEY: await exportPKCS8(pair.privateKey),
  };
};

describe("security faults and scheduled SLOs", () => {
  beforeEach(async () => {
    await env.DB.prepare(
      "INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)",
    ).run();
  });

  it("retries an accepted-before-D1-crash delivery with its stable identity", async () => {
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('sbom','tenant',?,?, 'linux/amd64',?,'complete',0)",
      ).bind(
        `ghcr.io/x@sha256:${"a".repeat(64)}`,
        `ghcr.io/x@sha256:${"b".repeat(64)}`,
        "c".repeat(64),
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'sbom','demo','npm','1.5.0','pkg:npm/demo@1.5.0',1)",
      ),
      env.DB.prepare(
        "INSERT INTO vulnerabilities VALUES ('OSV-1','npm','demo','{}','high','summary','2026-01-01T00:00:00Z')",
      ),
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',1,'OSV-1',0,NULL)"),
    ]);
    const environment = await dispatchEnv();
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
    const batch = vi
      .spyOn(env.DB, "batch")
      .mockRejectedValueOnce(new Error("injected D1 accepted-state failure"));

    await expect(dispatchPending(environment, 1_000)).rejects.toThrow(
      "injected D1 accepted-state failure",
    );
    batch.mockRestore();
    const deliveryId = await env.DB.prepare(
      "SELECT delivery_id FROM dispatch_deliveries",
    ).first<string>("delivery_id");
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) AS count FROM dispatch_deliveries WHERE status='accepted'",
      ).first<number>("count"),
    ).resolves.toBe(0);
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) AS count FROM findings WHERE dispatched_at IS NULL",
      ).first<number>("count"),
    ).resolves.toBe(1);

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
    await expect(dispatchPending(environment, 2_000)).resolves.toBe(1);
    await expect(
      env.DB.prepare(
        "SELECT delivery_id FROM dispatch_deliveries WHERE status='accepted'",
      ).first<string>("delivery_id"),
    ).resolves.toBe(deliveryId);
  });

  it("meets the injected-clock component, backfill, detection, and dispatch SLOs", async () => {
    const createdAt = 1_000_000;
    const now = createdAt + 4_999;
    const modifiedAt = new Date(now - 21_599_999).toISOString();
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('pending','tenant',?,?, 'linux/amd64',?,'pending',?)",
      ).bind(
        `ghcr.io/x@sha256:${"d".repeat(64)}`,
        `ghcr.io/x@sha256:${"e".repeat(64)}`,
        "f".repeat(64),
        createdAt,
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'pending','demo','npm','1.5.0','pkg:npm/demo@1.5.0',1)",
      ),
    ]);
    respond({
      method: "POST",
      url: "https://osv.test/v1/querybatch",
      status: 200,
      body: {
        results: [
          {
            vulns: [
              {
                id: "OSV-SLO",
                modified: modifiedAt,
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
    await backfillSbom({
      database: env.DB,
      sbomId: "pending",
      osvBaseUrl: "https://osv.test",
      now,
    });
    const environment = await dispatchEnv();
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
    await expect(dispatchPending(environment, now)).resolves.toBe(1);
    const timestamps = await env.DB.prepare(
      "SELECT s.created_at,c.id AS component_id,f.detected_at,f.dispatched_at,v.modified_at FROM sboms s JOIN components c ON c.sbom_id=s.id JOIN findings f ON f.component_id=c.id JOIN vulnerabilities v ON v.id=f.vuln_id AND v.ecosystem=c.ecosystem AND v.package_name=c.package_name WHERE s.id='pending'",
    ).first<{
      readonly created_at: number;
      readonly component_id: number;
      readonly detected_at: number;
      readonly dispatched_at: number;
      readonly modified_at: string;
    }>();
    if (!timestamps) throw new Error("scheduled SLO fixture missing timestamps");

    expect(timestamps.component_id).toBe(1);
    expect(now - timestamps.created_at).toBeLessThan(5_000);
    expect(timestamps.detected_at - timestamps.created_at).toBeLessThan(60_000);
    expect(timestamps.detected_at - Date.parse(timestamps.modified_at)).toBeLessThan(
      6 * 60 * 60 * 1_000,
    );
    expect(timestamps.dispatched_at - timestamps.detected_at).toBeLessThan(4 * 60 * 60 * 1_000);
  });
});
