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

  it("applies a bare Debian entry to Debian releases but never Ubuntu", async () => {
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('d12','tenant','d12','logical-d12','linux/amd64','digest','complete',0)",
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('d13','tenant','d13','logical-d13','linux/amd64','digest','complete',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (3,'d12','openssl','Debian:12','1.0','purl',1)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (4,'d13','openssl','Debian:13','1.0','purl',1)",
      ),
    ]);
    respondAdvisory("Debian", "DEBIAN-1", [
      affected("Debian", [{ introduced: "0" }, { fixed: "2.0" }]),
    ]);

    await resolveAdvisory({
      database: env.DB,
      ecosystem: "Debian",
      advisoryId: "DEBIAN-1",
      osvBaseUrl: "https://osv.test",
      now: 1,
    });

    const findings = await env.DB.prepare(
      "SELECT component_id FROM findings ORDER BY component_id",
    ).all<{ component_id: number }>();
    expect(findings.results.map(({ component_id }) => component_id)).toEqual([3, 4]);
    const ecosystems = await env.DB.prepare(
      "SELECT ecosystem FROM vulnerabilities ORDER BY ecosystem",
    ).all<{ ecosystem: string }>();
    expect(ecosystems.results.map(({ ecosystem }) => ecosystem)).toEqual([
      "Debian:12",
      "Debian:13",
    ]);
  });

  it("ORs duplicate affected entries independent of their order", async () => {
    const noMatch = affected("Ubuntu:24.04:LTS", [
      { introduced: "0" },
      { fixed: "3.0.13-0ubuntu3.15" },
    ]);
    const match = affected("Ubuntu:24.04:LTS", [
      { introduced: "0" },
      { fixed: "3.0.13-0ubuntu3.16" },
    ]);
    for (const entries of [
      [match, noMatch],
      [noMatch, match],
    ]) {
      await env.DB.prepare("DELETE FROM findings").run();
      respondAdvisory("Ubuntu", "USN-1", entries);
      await resolveAdvisory({
        database: env.DB,
        ecosystem: "Ubuntu",
        advisoryId: "USN-1",
        osvBaseUrl: "https://osv.test",
        now: 1,
      });
      await expect(
        env.DB.prepare("SELECT GROUP_CONCAT(component_id) FROM findings").first(
          "GROUP_CONCAT(component_id)",
        ),
      ).resolves.toBe("1");
    }
  });
});

function advisory(events: readonly { introduced?: string; fixed?: string }[]): void {
  respondAdvisory("Ubuntu", "USN-1", [affected("Ubuntu:24.04:LTS", events)]);
}

function affected(ecosystem: string, events: readonly { introduced?: string; fixed?: string }[]) {
  return {
    package: { ecosystem, name: "openssl" },
    ranges: [{ type: "ECOSYSTEM", events }],
    versions: [],
  };
}

function respondAdvisory(ecosystem: string, id: string, entries: readonly unknown[]): void {
  respond({
    url: `https://osv.test/${ecosystem}/${id}.json`,
    status: 200,
    body: { id, modified, affected: entries },
  });
}
