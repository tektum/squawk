import { describe, expect, it } from "vitest";
import { reconciliationPlan } from "../../scripts/reconcile-ecosystems";

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
