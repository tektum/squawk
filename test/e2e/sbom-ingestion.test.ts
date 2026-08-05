import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { backfillSbom } from "../../src/backfill";
import { TenantIdSchema } from "../../src/domain";
import { ingestSbom, ingestSboms } from "../../src/repository";
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

  it("returns a retry when concurrent submissions race on the SBOM identity", async () => {
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
    const results = await Promise.all(
      Array.from({ length: 2 }, () =>
        ingestSbom(
          env.DB,
          TenantIdSchema.parse("tenant"),
          input,
          "d".repeat(64),
          parsePredicate(predicate),
        ),
      ),
    );

    expect(results.map((result) => result.kind).sort()).toEqual(["created", "retry"]);
  });

  it("rejects a conflicting platform before writing any platform in the batch", async () => {
    const predicate = {
      bomFormat: "CycloneDX",
      components: [{ name: "demo", version: "1.5.0", purl: "pkg:npm/demo@1.5.0" }],
    };
    const inputs = ["amd64", "arm64"].map((architecture) =>
      sbomInputSchema.parse({
        image_ref: `ghcr.io/demo@sha256:${architecture === "amd64" ? "a".repeat(64) : "b".repeat(64)}`,
        logical_image_ref: `ghcr.io/demo@sha256:${"c".repeat(64)}`,
        platform: `linux/${architecture}`,
        idempotency_key: `${architecture}-idempotency-key`.padEnd(32, "0"),
        predicate,
      }),
    );
    const arm64 = inputs[1];
    if (!arm64) throw new Error("expected arm64 fixture");
    await ingestSbom(
      env.DB,
      TenantIdSchema.parse("tenant"),
      arm64,
      "existing-predicate",
      parsePredicate(predicate),
    );

    const result = await ingestSboms(
      env.DB,
      TenantIdSchema.parse("tenant"),
      inputs.map((input) => ({
        input,
        predicateSha256: "new-predicate",
        components: parsePredicate(predicate),
      })),
    );

    expect(result.kind).toBe("conflict");
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(1);
  });

  it("rolls back the SBOM identity when component persistence fails", async () => {
    const predicate = {
      bomFormat: "CycloneDX",
      components: [{ name: "demo", version: "1", purl: "pkg:npm/demo@1" }],
    };
    const input = sbomInputSchema.parse({
      image_ref: `ghcr.io/demo@sha256:${"a".repeat(64)}`,
      logical_image_ref: `ghcr.io/demo@sha256:${"b".repeat(64)}`,
      platform: "linux/amd64",
      idempotency_key: "c".repeat(64),
      predicate,
    });
    const component = parsePredicate(predicate)[0];
    if (!component) throw new Error("expected component fixture");

    await expect(
      ingestSbom(env.DB, TenantIdSchema.parse("tenant"), input, "d".repeat(64), [
        component,
        component,
      ]),
    ).rejects.toThrow();
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(0);
  });

  it("completes without querying OSV when no components are matchable", async () => {
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('unmatchable','tenant','image','logical','linux/amd64','digest','pending',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (sbom_id,package_name,ecosystem,version,purl,matchable) VALUES ('unmatchable','image','unknown:oci','digest','pkg:oci/image@digest',0)",
      ),
    ]);

    await backfillSbom({
      database: env.DB,
      sbomId: "unmatchable",
      osvBaseUrl: "https://osv.test",
      now: 1,
    });

    expect(
      await env.DB.prepare("SELECT backfill_status FROM sboms WHERE id='unmatchable'").first(
        "backfill_status",
      ),
    ).toBe("complete");
  });

  it("reclaims a stale running backfill", async () => {
    await env.DB.prepare(
      "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,backfill_attempted_at,created_at) VALUES ('stale','tenant','image','logical','linux/amd64','digest','running',0,0)",
    ).run();
    respond({
      method: "POST",
      url: "https://osv.test/v1/querybatch",
      status: 200,
      body: { results: [] },
    });

    await backfillSbom({
      database: env.DB,
      sbomId: "stale",
      osvBaseUrl: "https://osv.test",
      now: 1_300_000,
    });

    expect(
      await env.DB.prepare("SELECT backfill_status FROM sboms WHERE id='stale'").first(
        "backfill_status",
      ),
    ).toBe("complete");
  });
});
