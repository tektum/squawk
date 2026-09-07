import { env } from "cloudflare:test";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { backfillSbom } from "../../src/backfill";
import { server } from "../server";

const osvApiUrl = "https://osv.test";

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
    env.DB.prepare(
      "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('lease','tenant','image','logical','linux/amd64','digest','pending',0)",
    ),
    env.DB.prepare(
      "INSERT INTO components (sbom_id,package_name,ecosystem,version,purl,matchable) VALUES ('lease','demo','npm','1.0.0','pkg:npm/demo@1.0.0',1)",
    ),
  ]);
});

function holdQueryBatch(status: number) {
  let markStarted: () => void = () => undefined;
  let release: () => void = () => undefined;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  server.use(
    http.post(`${osvApiUrl}/v1/querybatch`, async () => {
      markStarted();
      await gate;
      return HttpResponse.json({ results: [{}] }, { status });
    }),
  );
  return { release, started };
}

async function backfillState() {
  return env.DB.prepare(
    "SELECT backfill_status,backfill_attempted_at,backfill_error FROM sboms WHERE id='lease'",
  ).first();
}

async function leaseIdentity() {
  return env.DB.prepare("SELECT backfill_lease_sha256 FROM sboms WHERE id='lease'").first<string>(
    "backfill_lease_sha256",
  );
}

async function scanActivityCount() {
  return env.DB.prepare(
    "SELECT COUNT(*) AS count FROM public_activity WHERE kind='scan'",
  ).first<number>("count");
}

describe("SBOM backfill lease ownership", () => {
  it("does not complete an SBOM reset to pending during its fetch", async () => {
    const request = holdQueryBatch(200);
    const backfill = backfillSbom({
      database: env.DB,
      sbomId: "lease",
      osvApiUrl,
      osvBaseUrl: osvApiUrl,
      now: 1_000,
    });
    await request.started;
    await env.DB.prepare(
      "UPDATE sboms SET backfill_status='pending',backfill_error=NULL,backfill_lease_sha256=NULL WHERE id='lease'",
    ).run();
    request.release();

    await expect(backfill).resolves.toBeUndefined();
    await expect(backfillState()).resolves.toEqual({
      backfill_status: "pending",
      backfill_attempted_at: 1_000,
      backfill_error: null,
    });
    await expect(scanActivityCount()).resolves.toBe(0);
  });

  it("does not fail a replacement lease claimed at the same timestamp", async () => {
    const staleRequest = holdQueryBatch(503);
    const staleBackfill = backfillSbom({
      database: env.DB,
      sbomId: "lease",
      osvApiUrl,
      osvBaseUrl: osvApiUrl,
      now: 1_000,
    });
    await staleRequest.started;
    const staleLease = await leaseIdentity();
    expect(staleLease).toMatch(/^[a-f0-9]{64}$/);
    await env.DB.prepare(
      "UPDATE sboms SET backfill_status='pending',backfill_error=NULL,backfill_lease_sha256=NULL WHERE id='lease'",
    ).run();
    const replacementRequest = holdQueryBatch(200);
    const replacementBackfill = backfillSbom({
      database: env.DB,
      sbomId: "lease",
      osvApiUrl,
      osvBaseUrl: osvApiUrl,
      now: 1_000,
    });
    await replacementRequest.started;
    const replacementLease = await leaseIdentity();
    expect(replacementLease).toMatch(/^[a-f0-9]{64}$/);
    expect(replacementLease).not.toBe(staleLease);
    staleRequest.release();

    await expect(staleBackfill).rejects.toThrow("OSV querybatch failed (503)");
    await expect(backfillState()).resolves.toEqual({
      backfill_status: "running",
      backfill_attempted_at: 1_000,
      backfill_error: null,
    });
    await expect(scanActivityCount()).resolves.toBe(0);
    replacementRequest.release();
    await expect(replacementBackfill).resolves.toBeUndefined();
    await expect(backfillState()).resolves.toEqual({
      backfill_status: "complete",
      backfill_attempted_at: 1_000,
      backfill_error: null,
    });
    await expect(leaseIdentity()).resolves.toBeNull();
    await expect(scanActivityCount()).resolves.toBe(1);
  });

  it("completes and records activity while it still owns the lease", async () => {
    server.use(http.post(`${osvApiUrl}/v1/querybatch`, () => HttpResponse.json({ results: [{}] })));

    await backfillSbom({
      database: env.DB,
      sbomId: "lease",
      osvApiUrl,
      osvBaseUrl: osvApiUrl,
      now: 3_000,
    });

    await expect(backfillState()).resolves.toEqual({
      backfill_status: "complete",
      backfill_attempted_at: 3_000,
      backfill_error: null,
    });
    await expect(leaseIdentity()).resolves.toBeNull();
    await expect(scanActivityCount()).resolves.toBe(1);
  });
});
