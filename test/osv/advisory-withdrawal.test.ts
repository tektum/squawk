import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { processAdvisory, resolveAdvisory } from "../../src/advisory";
import { backfillSbom } from "../../src/backfill";
import { respond } from "../http";

const modified = "2026-09-07T02:02:00Z";
const withdrawn = "2026-09-07T02:04:00Z";
const affected = [
  {
    package: { ecosystem: "npm", name: "demo" },
    ranges: [{ type: "SEMVER", events: [{ introduced: "1" }, { fixed: "2" }] }],
    versions: [],
  },
];

describe("withdrawn OSV advisories", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('sbom','tenant','image','logical','linux/amd64','digest','pending',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'sbom','demo','npm','1.5.0','pkg:npm/demo@1.5.0',1)",
      ),
    ]);
  });

  it("clears stale advisory state while preserving unrelated advisories", async () => {
    advisoryResponse("OSV-1");
    await resolve("OSV-1", 1);
    advisoryResponse("OSV-2");
    await resolve("OSV-2", 2);
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (1,'OSV-1','stale error',1)",
      ),
      env.DB.prepare(
        "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (1,'OSV-2','unrelated error',2)",
      ),
    ]);

    advisoryResponse("OSV-1", { withdrawn });
    await resolve("OSV-1", 3);

    await expect(counts("OSV-1")).resolves.toEqual({
      findings: 0,
      matching_errors: 0,
      vulnerabilities: 0,
    });
    await expect(counts("OSV-2")).resolves.toEqual({
      findings: 1,
      matching_errors: 1,
      vulnerabilities: 1,
    });
  });

  it("does not create state for a withdrawn advisory on first ingestion", async () => {
    advisoryResponse("OSV-1", { withdrawn });
    await resolve("OSV-1", 1);

    await expect(counts("OSV-1")).resolves.toEqual({
      findings: 0,
      matching_errors: 0,
      vulnerabilities: 0,
    });
  });

  it.each([
    ["omitted", { omitAffected: true }],
    ["null", { affected: null }],
  ] as const)("clears stored state when withdrawn affected is %s", async (_label, options) => {
    advisoryResponse("OSV-1");
    await resolve("OSV-1", 1);
    advisoryResponse("OSV-1", { withdrawn, ...options });

    await resolve("OSV-1", 2);
    await expect(counts("OSV-1")).resolves.toEqual({
      findings: 0,
      matching_errors: 0,
      vulnerabilities: 0,
    });
  });

  it.each([
    ["omitted", { omitAffected: true }],
    ["null", { affected: null }],
  ] as const)(
    "rejects non-withdrawn affected that is %s without clearing state",
    async (_label, options) => {
      advisoryResponse("OSV-1");
      await resolve("OSV-1", 1);
      advisoryResponse("OSV-1", options);

      await expect(resolve("OSV-1", 2)).rejects.toThrow();
      await expect(counts("OSV-1")).resolves.toEqual({
        findings: 1,
        matching_errors: 0,
        vulnerabilities: 1,
      });
    },
  );

  it("fails closed on a malformed withdrawn timestamp", async () => {
    advisoryResponse("OSV-1");
    await resolve("OSV-1", 1);
    advisoryResponse("OSV-1", { withdrawn: "not-a-timestamp" });

    await expect(resolve("OSV-1", 2)).rejects.toThrow();
    await expect(counts("OSV-1")).resolves.toEqual({
      findings: 1,
      matching_errors: 0,
      vulnerabilities: 1,
    });
  });

  it("completes a queued withdrawn advisory without recreating findings", async () => {
    const jobId = "1".repeat(64);
    await env.DB.prepare(
      "INSERT INTO osv_advisory_jobs (job_id,ecosystem,advisory_id,modified_at,status) VALUES (?,'npm','OSV-Q',?,'pending')",
    )
      .bind(jobId, modified)
      .run();
    advisoryResponse("OSV-Q", { withdrawn });

    await processAdvisory({
      database: env.DB,
      message: { jobId },
      now: 1,
      osvBaseUrl: "https://osv.test",
    });

    await expect(
      env.DB.prepare("SELECT status FROM osv_advisory_jobs WHERE job_id=?")
        .bind(jobId)
        .first("status"),
    ).resolves.toBe("complete");
    await expect(counts("OSV-Q")).resolves.toEqual({
      findings: 0,
      matching_errors: 0,
      vulnerabilities: 0,
    });
  });

  it("completes a backfill withdrawn advisory without recreating findings", async () => {
    respond({
      method: "POST",
      url: "https://osv.test/v1/querybatch",
      status: 200,
      body: { results: [{ vulns: [{ id: "OSV-B", modified }] }] },
    });
    advisoryResponse("OSV-B", { withdrawn });

    await backfillSbom({
      database: env.DB,
      sbomId: "sbom",
      osvApiUrl: "https://osv.test",
      osvBaseUrl: "https://osv.test",
      now: 1,
    });

    await expect(
      env.DB.prepare("SELECT backfill_status FROM sboms WHERE id='sbom'").first("backfill_status"),
    ).resolves.toBe("complete");
    await expect(
      env.DB.prepare("SELECT status FROM osv_advisory_jobs WHERE advisory_id='OSV-B'").first(
        "status",
      ),
    ).resolves.toBe("complete");
    await expect(counts("OSV-B")).resolves.toEqual({
      findings: 0,
      matching_errors: 0,
      vulnerabilities: 0,
    });
  });
});

type AdvisoryResponseOptions = {
  readonly withdrawn?: string;
  readonly affected?: typeof affected | null;
  readonly omitAffected?: boolean;
};

function advisoryResponse(id: string, options: AdvisoryResponseOptions = {}): void {
  respond({
    url: `https://osv.test/npm/${id}.json`,
    status: 200,
    body: {
      id,
      modified,
      ...(options.withdrawn === undefined ? {} : { withdrawn: options.withdrawn }),
      ...(options.omitAffected
        ? {}
        : { affected: options.affected === undefined ? affected : options.affected }),
    },
  });
}

async function resolve(advisoryId: string, now: number): Promise<void> {
  await resolveAdvisory({
    database: env.DB,
    ecosystem: "npm",
    advisoryId,
    osvBaseUrl: "https://osv.test",
    now,
  });
}

async function counts(advisoryId: string) {
  return env.DB.prepare(
    `SELECT
      (SELECT COUNT(*) FROM findings WHERE vuln_id=?1) AS findings,
      (SELECT COUNT(*) FROM matching_errors WHERE vuln_id=?1) AS matching_errors,
      (SELECT COUNT(*) FROM vulnerabilities WHERE id=?1) AS vulnerabilities`,
  )
    .bind(advisoryId)
    .first();
}
