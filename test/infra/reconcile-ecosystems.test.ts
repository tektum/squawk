import { describe, expect, it } from "vitest";
import { reconciliationPlan } from "../../scripts/reconcile-ecosystems";

const wolfi = "pkg:apk/wolfi/ca-certificates-bundle@20260413-r0?arch=x86_64&distro=wolfi";
const alpine = "pkg:apk/alpine/busybox@1.37.0-r61?arch=x86_64&distro=alpine-3.21.3";

describe("ecosystem reconciliation plan", () => {
  it("restates components stored under the wrong ecosystem", () => {
    const plan = reconciliationPlan([
      { id: 1, purl: wolfi, ecosystem: "Alpine", matchable: 1 },
      { id: 2, purl: alpine, ecosystem: "Alpine", matchable: 1 },
    ]);

    expect(plan.updates).toEqual([
      "UPDATE components SET ecosystem='Wolfi',matchable=1 WHERE id=1;",
      "UPDATE components SET ecosystem='Alpine:v3.21',matchable=1 WHERE id=2;",
    ]);
  });

  it("requeues re-backfill even when every component is already correct", () => {
    const plan = reconciliationPlan([{ id: 1, purl: wolfi, ecosystem: "Wolfi", matchable: 1 }]);

    expect(plan.updates).toEqual([]);
    expect(plan.requeue).toContain("UPDATE sboms SET backfill_status='pending'");
    expect(plan.requeue).toContain("DELETE FROM matching_errors");
  });

  it("restates a component whose matchability changed", () => {
    const plan = reconciliationPlan([
      {
        id: 7,
        purl: "pkg:apk/alpine/busybox@1.37.0-r61",
        ecosystem: "Alpine",
        matchable: 1,
      },
    ]);

    expect(plan.updates).toEqual([
      "UPDATE components SET ecosystem='unknown:apk',matchable=0 WHERE id=7;",
    ]);
  });
});
