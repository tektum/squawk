import { createExecutionContext, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../../src/index";

const digest = `sha256:${"a".repeat(64)}`;

describe("public inventory", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)"),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('amd','tenant',?,?, 'linux/amd64','digest','complete',1)",
      ).bind(`ghcr.io/owner/demo@${digest}`, `ghcr.io/owner/demo@${digest}`),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('arm','tenant',?,?, 'linux/arm64','digest','complete',1)",
      ).bind(`ghcr.io/owner/demo@${digest}`, `ghcr.io/owner/demo@${digest}`),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (1,'amd','demo<script>','npm','1.2.3','pkg:npm/demo@1.2.3',1)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (2,'arm','demo<script>','npm','1.2.3','pkg:npm/demo@1.2.3',1)",
      ),
      env.DB.prepare(
        "INSERT INTO vulnerabilities VALUES ('OSV-1','npm','demo<script>','{}','high','summary','2026-01-01T00:00:00Z')",
      ),
      env.DB.prepare("INSERT INTO findings VALUES ('tenant',1,'OSV-1',1,NULL)"),
    ]);
  });

  it("renders aggregated public image and package inventory", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/"),
      env,
      createExecutionContext(),
    );
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(html).toContain("Squawk inventory");
    expect(html).toContain("ghcr.io/owner/demo@");
    expect(html).toContain("linux/amd64 · linux/arm64");
    expect(html).toContain("demo&lt;script&gt;");
    expect(html).not.toContain("demo<script>");
    expect(html).toContain(">1</strong><span>findings");
  });

  it("filters without requiring authentication", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/?q=does-not-exist"),
      env,
      createExecutionContext(),
    );
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(html).toContain("No images match this filter.");
    expect(html).toContain("No packages match this filter.");
  });
});
