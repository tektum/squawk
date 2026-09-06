import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { reconcilePlatformRequests } from "../../src/attested-platforms";
import { sbomInputSchema } from "../../src/sbom";

const logical = `ghcr.io/owner/demo@sha256:${"a".repeat(64)}`;

describe("attested platform repair", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('old-amd','tenant',?,?,'linux/amd64','predicate-amd','complete',0)",
      ).bind(`ghcr.io/owner/demo@sha256:${"7".repeat(64)}`, logical),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('old-arm','tenant',?,?,'linux/amd64','predicate-arm','complete',0)",
      ).bind(`ghcr.io/owner/demo@sha256:${"8".repeat(64)}`, logical),
    ]);
  });

  it("maps legacy candidate rows to final index children by predicate identity", async () => {
    const requests = [
      {
        input: sbomInputSchema.parse({
          image_ref: `ghcr.io/owner/demo@sha256:${"1".repeat(64)}`,
          logical_image_ref: logical,
          platform: "linux/amd64",
          idempotency_key: "amd64".padEnd(32, "0"),
          predicate: {},
        }),
        predicateSha256: "predicate-amd",
        components: [],
      },
      {
        input: sbomInputSchema.parse({
          image_ref: `ghcr.io/owner/demo@sha256:${"2".repeat(64)}`,
          logical_image_ref: logical,
          platform: "linux/arm64",
          idempotency_key: "arm64".padEnd(32, "0"),
          predicate: {},
        }),
        predicateSha256: "predicate-arm",
        components: [],
      },
    ];

    await expect(reconcilePlatformRequests(env.DB, "tenant", logical, requests)).resolves.toEqual(
      requests,
    );
    const rows = await env.DB.prepare(
      "SELECT platform,image_ref FROM sboms ORDER BY platform",
    ).all();
    expect(rows.results).toEqual([
      {
        platform: "linux/amd64",
        image_ref: `ghcr.io/owner/demo@sha256:${"1".repeat(64)}`,
      },
      {
        platform: "linux/arm64",
        image_ref: `ghcr.io/owner/demo@sha256:${"2".repeat(64)}`,
      },
    ]);
  });
});
