import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { resolveAdvisory } from "../../src/advisory";
import { respond } from "../http";

const modified = "2026-09-06T00:00:00Z";

describe("distribution release advisory matching", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('noble','tenant','noble','logical','linux/amd64','digest','complete',0)",
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('jammy','tenant','jammy','logical-2','linux/amd64','digest','complete',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'noble','openssl','Ubuntu:24.04:LTS','3.0.13-0ubuntu3.15','purl',1)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (2,'jammy','openssl','Ubuntu:22.04:LTS','3.0.13-0ubuntu3.15','purl',1)",
      ),
    ]);
  });

  it("never applies one distribution release entry to another", async () => {
    advisory([{ introduced: "0" }, { fixed: "3.0.13-0ubuntu3.16" }]);
    await resolveAdvisory({
      database: env.DB,
      ecosystem: "Ubuntu",
      advisoryId: "USN-1",
      osvBaseUrl: "https://osv.test",
      now: 1,
    });

    await expect(
      env.DB.prepare("SELECT GROUP_CONCAT(component_id) AS ids FROM findings").first("ids"),
    ).resolves.toBe("1");
    await expect(
      env.DB.prepare("SELECT ecosystem FROM vulnerabilities").first("ecosystem"),
    ).resolves.toBe("Ubuntu:24.04:LTS");
  });

  it("removes a stale finding when a newer advisory no longer matches", async () => {
    advisory([{ introduced: "0" }, { fixed: "3.0.13-0ubuntu3.16" }]);
    await resolveAdvisory({
      database: env.DB,
      ecosystem: "Ubuntu",
      advisoryId: "USN-1",
      osvBaseUrl: "https://osv.test",
      now: 1,
    });
    advisory([{ introduced: "0" }, { fixed: "3.0.13-0ubuntu3.15" }]);
    await resolveAdvisory({
      database: env.DB,
      ecosystem: "Ubuntu",
      advisoryId: "USN-1",
      osvBaseUrl: "https://osv.test",
      now: 2,
    });

    await expect(env.DB.prepare("SELECT COUNT(*) FROM findings").first("COUNT(*)")).resolves.toBe(
      0,
    );
  });
});

function advisory(events: readonly { introduced?: string; fixed?: string }[]): void {
  respond({
    url: "https://osv.test/Ubuntu/USN-1.json",
    status: 200,
    body: {
      id: "USN-1",
      modified,
      affected: [
        {
          package: { ecosystem: "Ubuntu:24.04:LTS", name: "openssl" },
          ranges: [{ type: "ECOSYSTEM", events }],
          versions: [],
        },
      ],
    },
  });
}
