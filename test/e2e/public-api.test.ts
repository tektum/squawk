import { createExecutionContext, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";

const digest = `sha256:${"a".repeat(64)}`;
const reference = `ghcr.io/owner/demo@${digest}`;

/* The public surface discloses a finding only when the pipeline delivered it
   (`dispatched_at` set) and VEX has not adjudicated it `not_affected` or `fixed`. */
describe("public disclosure api", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('amd','tenant',?,?,'linux/amd64','digest','complete',10)",
      ).bind(reference, reference),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('arm','tenant',?,?,'linux/arm64','digest','complete',11)",
      ).bind(reference, reference),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at,retired_at) VALUES ('old','tenant','ghcr.io/owner/old@sha256:bbbb','ghcr.io/owner/old','linux/amd64','digest2','complete',5,6)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'amd','demo<script>','npm','1.2.3','pkg:npm/demo@1.2.3',1)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (2,'arm','demo<script>','npm','1.2.3','pkg:npm/demo@1.2.3',1)",
      ),
      env.DB.prepare(
        "INSERT INTO vulnerabilities VALUES ('OSV-1','npm','demo<script>','{}','high','summary one','2026-01-01T00:00:00Z')",
      ),
      env.DB.prepare(
        "INSERT INTO vulnerabilities VALUES ('OSV-2','npm','demo<script>','{}','low','summary two','2026-01-01T00:00:00Z')",
      ),
      // Disclosed: delivered downstream.
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',1,'OSV-1',1,5)"),
      // Undispatched: still inside the disclosure window.
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',2,'OSV-1',2,NULL)"),
      // Dispatched but adjudicated not affected: never disclosed.
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',1,'OSV-2',3,6)"),
      env.DB.prepare(
        "INSERT INTO vex_statements (org_id,package_name,ecosystem,vuln_id,status,justification,created_by_descope_user_id,created_at) VALUES ('tenant','demo<script>','npm','OSV-2','not_affected',NULL,'user',7)",
      ),
    ]);
  });

  it("serves the read-only console shell at the root", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/"),
      env,
      createExecutionContext(),
    );
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(html).toContain('data-project-id="');
    expect(html).toContain('src="/admin/app.js');
    expect(html).not.toContain("ghcr.io/owner");
  });

  it("aggregates only disclosed findings in the overview", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/public/overview"),
      env,
      createExecutionContext(),
    );
    const body = await response.json<{
      totals: {
        images: number;
        components: number;
        findings: number;
      };
      severity: Record<string, number>;
    }>();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("public");
    expect(body.totals.images).toBe(1);
    expect(body.totals.components).toBe(2);
    expect(body.totals.findings).toBe(1);
    expect(body.severity).toEqual({ high: 1 });
  });

  it("carries no pipeline internals in any payload", async () => {
    const responses = await Promise.all([
      worker.fetch(
        new Request("https://squawk.test/public/overview"),
        env,
        createExecutionContext(),
      ),
      worker.fetch(new Request("https://squawk.test/public/images"), env, createExecutionContext()),
      worker.fetch(
        new Request(`https://squawk.test/public/image?ref=${encodeURIComponent(reference)}`),
        env,
        createExecutionContext(),
      ),
    ]);
    for (const response of responses) {
      expect(response.status).toBe(200);
      const text = await response.text();
      for (const secret of [
        "backfill_error",
        "undispatched",
        "matching_errors",
        "installation_id",
        "sync_cursors",
        "delivery",
      ]) {
        expect(text).not.toContain(secret);
      }
    }
  });

  it("lists active images with disclosed finding counts only", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/public/images"),
      env,
      createExecutionContext(),
    );
    const body = await response.json<{
      images: {
        image_ref: string;
        platforms: string;
        components: number;
        findings: number;
        status: string;
      }[];
    }>();

    expect(body.images.length).toBe(1);
    expect(body.images[0]?.image_ref).toBe(reference);
    expect(body.images[0]?.platforms).toBe("linux/amd64,linux/arm64");
    expect(body.images[0]?.components).toBe(2);
    expect(body.images[0]?.findings).toBe(1);
    expect(body.images[0]?.status).toBe("indexed");
  });

  it("discloses a delivered finding once across platforms", async () => {
    const response = await worker.fetch(
      new Request(`https://squawk.test/public/image?ref=${encodeURIComponent(reference)}`),
      env,
      createExecutionContext(),
    );
    const body = await response.json<{
      platforms: { platform: string }[];
      components: { purl: string }[];
      findings: { vuln_id: string; detected_at: number }[];
    }>();

    expect(body.platforms.map((platform) => platform.platform)).toEqual([
      "linux/amd64",
      "linux/arm64",
    ]);
    expect(body.components.map((component) => component.purl)).toEqual(["pkg:npm/demo@1.2.3"]);
    expect(body.findings).toHaveLength(1);
    expect(body.findings[0]).toMatchObject({ vuln_id: "OSV-1", detected_at: 1 });
  });

  it("answers an unknown reference with 404", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/public/image?ref=ghcr.io/nope"),
      env,
      createExecutionContext(),
    );
    expect(response.status).toBe(404);
  });
});
