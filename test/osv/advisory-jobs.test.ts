import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { ecosystemFamily, registerAdvisoryJobs } from "../../src/advisory-jobs";

const newer = { ecosystem: "Wolfi", advisoryId: "CGA-demo", modifiedAt: "2026-08-02T00:00:00Z" };
const older = { ecosystem: "Wolfi", advisoryId: "CGA-demo", modifiedAt: "2026-08-01T00:00:00Z" };

describe("advisory job registration", () => {
  it("reopens a completed job when OSV publishes a newer revision", async () => {
    const [first] = await registerAdvisoryJobs(env.DB, [older]);
    if (!first) throw new Error("expected a registered advisory");
    await env.DB.prepare("UPDATE osv_advisory_jobs SET status='complete' WHERE job_id=?")
      .bind(first.jobId)
      .run();

    const [second] = await registerAdvisoryJobs(env.DB, [newer]);

    expect(second?.modifiedAt).toBe(newer.modifiedAt);
    expect(second?.jobId).not.toBe(first.jobId);
    await expect(
      env.DB.prepare("SELECT status FROM osv_advisory_jobs WHERE advisory_id='CGA-demo'").first(
        "status",
      ),
    ).resolves.toBe("pending");
  });

  it("never lets an older revision displace the stored identity", async () => {
    const [current] = await registerAdvisoryJobs(env.DB, [newer]);
    if (!current) throw new Error("expected a registered advisory");
    await env.DB.prepare("UPDATE osv_advisory_jobs SET status='complete' WHERE job_id=?")
      .bind(current.jobId)
      .run();

    const [stale] = await registerAdvisoryJobs(env.DB, [older]);

    // The caller must receive the stored revision, not the one it offered, or it
    // would mark a job identity that no longer exists.
    expect(stale?.jobId).toBe(current.jobId);
    expect(stale?.modifiedAt).toBe(newer.modifiedAt);
    const row = await env.DB.prepare(
      "SELECT job_id,modified_at,status FROM osv_advisory_jobs WHERE advisory_id='CGA-demo'",
    ).first<{ job_id: string; modified_at: string; status: string }>();
    expect(row).toMatchObject({
      job_id: current.jobId,
      modified_at: newer.modifiedAt,
      status: "complete",
    });
  });

  it("keeps versioned ecosystems on their family feed", () => {
    expect(ecosystemFamily("Alpine:v3.21")).toBe("Alpine");
    expect(ecosystemFamily("Wolfi")).toBe("Wolfi");
  });
});
