import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { backfillSbom } from "../../src/backfill";
import { TenantIdSchema } from "../../src/domain";
import { ingestSbom } from "../../src/repository";
import { parsePredicate, sbomInputSchema } from "../../src/sbom";
import { respond } from "../http";

describe("SBOM ingestion and historical backfill", () => {
  beforeEach(async () => {
    await env.DB.prepare(
      "INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)",
    ).run();
  });

  it("is atomic and idempotent and creates a historical finding", async () => {
    const predicate = {
      bomFormat: "CycloneDX",
      components: [{ name: "demo", version: "1.5.0", purl: "pkg:npm/demo@1.5.0" }],
    };
    const input = sbomInputSchema.parse({
      image_ref: `ghcr.io/demo@sha256:${"a".repeat(64)}`,
      logical_image_ref: `ghcr.io/demo@sha256:${"b".repeat(64)}`,
      platform: "linux/amd64",
      idempotency_key: "c".repeat(64),
      predicate,
    });
    const tenant = TenantIdSchema.parse("tenant");
    const created = await ingestSbom(
      env.DB,
      tenant,
      input,
      "d".repeat(64),
      parsePredicate(predicate),
    );
    expect(created.kind).toBe("created");
    expect(
      (await ingestSbom(env.DB, tenant, input, "d".repeat(64), parsePredicate(predicate))).kind,
    ).toBe("retry");
    expect(
      (await ingestSbom(env.DB, tenant, input, "e".repeat(64), parsePredicate(predicate))).kind,
    ).toBe("conflict");
    if (created.kind !== "created") throw new Error("expected new SBOM");
    respond({
      method: "POST",
      url: "https://osv.test/v1/querybatch",
      status: 200,
      body: {
        results: [
          {
            vulns: [
              {
                id: "OSV-OLD",
                modified: "2020-01-01T00:00:00Z",
                summary: "old advisory",
                severity: [{ type: "CVSS_V3", score: "high" }],
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
      sbomId: created.sbomId,
      osvBaseUrl: "https://osv.test",
      now: 1,
    });

    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM components").first("count")).toBe(1);
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM findings").first("count")).toBe(1);
    expect(
      await env.DB.prepare("SELECT backfill_status FROM sboms WHERE id=?")
        .bind(created.sbomId)
        .first("backfill_status"),
    ).toBe("complete");
  });
});
