import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { reconciliationPlan } from "../../scripts/reconcile-ecosystems";
import { processAdvisory } from "../../src/advisory";
import { requeueAdvisoryJobs } from "../../src/sync";
import { respond } from "../http";

const wolfi = "pkg:apk/wolfi/ca-certificates-bundle@20260413-r0?arch=x86_64&distro=wolfi";
const alpine = "pkg:apk/alpine/busybox@1.37.0-r61?arch=x86_64&distro=alpine-3.21.3";

describe("ecosystem reconciliation plan", () => {
  it("restates components stored under the wrong ecosystem", () => {
    const plan = reconciliationPlan([
      { id: 1, purl: wolfi, ecosystem: "Alpine", matchable: 1, version: "20260413-r0" },
      { id: 2, purl: alpine, ecosystem: "Alpine", matchable: 1, version: "1.37.0-r61" },
    ]);

    expect(plan.updates).toHaveLength(2);
    expect(plan.updates[0]).toContain(
      "UPDATE components SET ecosystem='Wolfi',matchable=1,version='20260413-r0' WHERE id=1;",
    );
    expect(plan.updates[1]).toContain(
      "UPDATE components SET ecosystem='Alpine:v3.21',matchable=1,version='1.37.0-r61' WHERE id=2;",
    );
    expect(plan.updates[0]).toContain("DELETE FROM findings WHERE component_id=1");
  });

  it("restates a decorated version to the canonical purl version", () => {
    const plan = reconciliationPlan([
      {
        id: 5,
        purl: "pkg:golang/stdlib@1.26.5",
        ecosystem: "Go",
        matchable: 1,
        version: "go1.26.5",
      },
    ]);

    expect(plan.updates).toHaveLength(1);
    expect(plan.updates[0]).toContain(
      "UPDATE components SET ecosystem='Go',matchable=1,version='1.26.5' WHERE id=5;",
    );
  });

  it("requeues without deleting unrelated derived state", () => {
    const plan = reconciliationPlan([
      { id: 1, purl: wolfi, ecosystem: "Wolfi", matchable: 1, version: "20260413-r0" },
    ]);

    expect(plan.updates).toEqual([]);
    expect(plan.requeue).not.toContain("DELETE FROM vulnerabilities");
    expect(plan.requeue).not.toContain("DELETE FROM findings;");
    expect(plan.requeue).toContain("WHERE NOT EXISTS");
    expect(plan.requeue).toContain("UPDATE sboms SET backfill_status='pending'");
  });

  it("replays completed advisories that underpin retained active state", async () => {
    const oldJobId = "1".repeat(64);
    const pendingJobId = "2".repeat(64);
    const runningJobId = "3".repeat(64);
    const unrelatedJobId = "4".repeat(64);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('sbom','tenant','image','logical','linux/amd64','digest','complete',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'sbom','demo','npm','1.5.0','pkg:npm/demo@1.5.0',1)",
      ),
      env.DB.prepare(
        `INSERT INTO vulnerabilities (id,ecosystem,package_name,affected_ranges,modified_at) VALUES
          ('OSV-OLD','npm','demo','[]','2026-01-01T00:00:00Z'),
          ('OSV-PENDING','npm','demo','[]','2026-01-02T00:00:00Z'),
          ('OSV-RUNNING','npm','demo','[]','2026-01-03T00:00:00Z'),
          ('OSV-UNRELATED','npm','demo','[]','2026-01-04T00:00:00Z')`,
      ),
      env.DB.prepare(
        "INSERT INTO findings (org_id,component_id,vuln_id,detected_at) VALUES ('tenant',1,'OSV-OLD',1),('tenant',1,'OSV-PENDING',2)",
      ),
      env.DB.prepare(
        "INSERT INTO matching_errors (component_id,vuln_id,reason,created_at) VALUES (1,'OSV-OLD','old error',1),(1,'OSV-RUNNING','active error',2)",
      ),
      env.DB.prepare(
        `INSERT INTO osv_advisory_jobs (job_id,ecosystem,advisory_id,modified_at,status,attempted_at,error) VALUES
          (?,'npm','OSV-OLD','2026-01-01T00:00:00Z','complete',100,'old result'),
          (?,'npm','OSV-PENDING','2026-01-02T00:00:00Z','pending',500,'retry later'),
          (?,'npm','OSV-RUNNING','2026-01-03T00:00:00Z','running',900,'in progress'),
          (?,'npm','OSV-UNRELATED','2026-01-04T00:00:00Z','complete',400,NULL)`,
      ).bind(oldJobId, pendingJobId, runningJobId, unrelatedJobId),
    ]);

    const plan = reconciliationPlan([
      { id: 1, purl: "pkg:npm/demo@1.5.0", ecosystem: "npm", matchable: 1, version: "1.5.0" },
    ]);
    await env.DB.exec(plan.requeue.replaceAll("\n", " "));

    await expect(
      env.DB.prepare(
        "SELECT advisory_id,status,attempted_at,error FROM osv_advisory_jobs ORDER BY advisory_id",
      ).all(),
    ).resolves.toMatchObject({
      results: [
        { advisory_id: "OSV-OLD", status: "pending", attempted_at: null, error: null },
        { advisory_id: "OSV-PENDING", status: "pending", attempted_at: 500, error: "retry later" },
        { advisory_id: "OSV-RUNNING", status: "running", attempted_at: 900, error: "in progress" },
        { advisory_id: "OSV-UNRELATED", status: "complete", attempted_at: 400, error: null },
      ],
    });
    const queued: { jobId: string }[] = [];
    await requeueAdvisoryJobs({
      database: env.DB,
      now: 1_000,
      queue: {
        sendBatch: async (messages) => {
          queued.push(...Array.from(messages, (message) => message.body));
        },
      },
    });
    expect(queued).toEqual([{ jobId: oldJobId }, { jobId: pendingJobId }]);

    respond({
      url: "https://osv.test/npm/OSV-OLD.json",
      status: 200,
      body: {
        id: "OSV-OLD",
        modified: "2026-09-07T02:02:00Z",
        withdrawn: "2026-09-07T02:04:00Z",
      },
    });
    await processAdvisory({
      database: env.DB,
      message: { jobId: oldJobId },
      now: 2_000,
      osvBaseUrl: "https://osv.test",
    });

    await expect(
      env.DB.prepare(
        `SELECT
          (SELECT COUNT(*) FROM findings WHERE vuln_id='OSV-OLD') AS findings,
          (SELECT COUNT(*) FROM matching_errors WHERE vuln_id='OSV-OLD') AS matching_errors,
          (SELECT COUNT(*) FROM vulnerabilities WHERE id='OSV-OLD') AS vulnerabilities`,
      ).first(),
    ).resolves.toEqual({ findings: 0, matching_errors: 0, vulnerabilities: 0 });
    await expect(
      env.DB.prepare(
        `SELECT
          (SELECT COUNT(*) FROM findings WHERE vuln_id='OSV-PENDING') AS pending_finding,
          (SELECT COUNT(*) FROM matching_errors WHERE vuln_id='OSV-RUNNING') AS running_error,
          (SELECT COUNT(*) FROM vulnerabilities WHERE id='OSV-UNRELATED') AS unrelated_vulnerability`,
      ).first(),
    ).resolves.toEqual({ pending_finding: 1, running_error: 1, unrelated_vulnerability: 1 });
    await expect(
      env.DB.prepare("SELECT status FROM osv_advisory_jobs WHERE job_id=?")
        .bind(oldJobId)
        .first("status"),
    ).resolves.toBe("complete");
  });

  it("restates a component whose matchability changed", () => {
    const plan = reconciliationPlan([
      {
        id: 7,
        purl: "pkg:apk/alpine/busybox@1.37.0-r61",
        ecosystem: "Alpine",
        matchable: 1,
        version: "1.37.0-r61",
      },
    ]);

    expect(plan.updates).toHaveLength(1);
    expect(plan.updates[0]).toContain(
      "UPDATE components SET ecosystem='unknown:apk',matchable=0,version='1.37.0-r61' WHERE id=7;",
    );
  });

  it("repairs persisted Ubuntu identities before rebackfill", () => {
    const plan = reconciliationPlan([
      {
        id: 8,
        purl: "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.15?distro=ubuntu-24.04",
        ecosystem: "Debian",
        matchable: 1,
        version: "3.0.13-0ubuntu3.15",
      },
    ]);

    expect(plan.updates[0]).toContain("DELETE FROM findings WHERE component_id=8");
    expect(plan.updates[0]).toContain(
      "UPDATE components SET ecosystem='Ubuntu:24.04:LTS',matchable=1",
    );
  });
});
