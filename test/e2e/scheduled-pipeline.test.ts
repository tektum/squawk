import { env } from "cloudflare:test";
import { exportPKCS8, generateKeyPair } from "jose";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { dispatchPending } from "../../src/dispatch";
import { runScheduled } from "../../src/scheduled";
import { githubWebhookFixture, INSTALLATION_ID, REPOSITORY_ID } from "../fixtures/github-webhook";
import { respond } from "../http";

describe("durable multi-platform dispatch", () => {
  beforeEach(async () => {
    await env.DB.prepare(
      "INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)",
    ).run();
    for (const [index, platform] of ["linux/amd64", "linux/arm64"].entries()) {
      const sbom = `sbom-${index}`;
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES (?,'tenant',?,?,?,?,'complete',0)",
        ).bind(
          sbom,
          `ghcr.io/x@sha256:${String(index + 1).repeat(64)}`,
          `ghcr.io/x@sha256:${"a".repeat(64)}`,
          platform,
          "b".repeat(64),
        ),
        env.DB.prepare(
          "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (?,?,?,?,?,?,1)",
        ).bind(index + 1, sbom, "demo", "npm", "1.5.0", "pkg:npm/demo@1.5.0"),
        env.DB.prepare("INSERT INTO findings VALUES ('tenant',?,'OSV-1',0,NULL)").bind(index + 1),
      ]);
    }
    await env.DB.prepare(
      "INSERT INTO vulnerabilities VALUES ('OSV-1','npm','demo','{}','high','summary','2026-01-01T00:00:00Z')",
    ).run();
  });

  it("sends one stable delivery and marks both findings", async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    const privateKey = await exportPKCS8(pair.privateKey);
    respond({
      method: "POST",
      url: "https://api.github.com/app/installations/123/access_tokens",
      status: 201,
      body: { token: "installation-token" },
    });
    respond({
      method: "POST",
      url: "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
      status: 204,
    });
    const dispatchEnv = {
      DB: env.DB,
      GH_APP_ID: "42",
      GH_APP_INSTALLATION_ID: "123",
      GH_APP_PRIVATE_KEY: privateKey,
    };

    expect(await dispatchPending(dispatchEnv, 1000)).toBe(1);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM dispatch_deliveries WHERE status='accepted'",
      ).first<number>("count"),
    ).toBe(1);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM findings WHERE dispatched_at IS NOT NULL",
      ).first<number>("count"),
    ).toBe(2);
    expect(await dispatchPending(dispatchEnv, 2000)).toBe(0);
  });

  it.each([429, 500])("keeps a %s GitHub dispatch retryable", async (status) => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    const privateKey = await exportPKCS8(pair.privateKey);
    respond({
      method: "POST",
      url: "https://api.github.com/app/installations/123/access_tokens",
      status: 201,
      body: { token: "installation-token" },
    });
    respond({
      method: "POST",
      url: "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
      status,
    });

    expect(
      await dispatchPending(
        {
          DB: env.DB,
          GH_APP_ID: "42",
          GH_APP_INSTALLATION_ID: "123",
          GH_APP_PRIVATE_KEY: privateKey,
        },
        1000,
      ),
    ).toBe(1);
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) AS count FROM dispatch_deliveries WHERE status='failed'",
      ).first<number>("count"),
    ).resolves.toBe(1);
    await expect(
      env.DB.prepare(
        "SELECT COUNT(*) AS count FROM findings WHERE dispatched_at IS NULL",
      ).first<number>("count"),
    ).resolves.toBe(2);
  });

  it("isolates a failing ecosystem and advances a peer fairly through runScheduled", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 1000)"),
      env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('PyPI', 1000)"),
      env.DB.prepare("INSERT INTO sync_cursors VALUES ('npm','2026-01-01T00:00:00Z','',NULL,NULL)"),
      env.DB.prepare(
        "INSERT INTO sync_cursors VALUES ('PyPI','2026-01-01T00:00:00Z','',NULL,NULL)",
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('peer','tenant',?,?, 'linux/amd64',?,'complete',0)",
      ).bind(
        `ghcr.io/x@sha256:${"c".repeat(64)}`,
        `ghcr.io/x@sha256:${"d".repeat(64)}`,
        "e".repeat(64),
      ),
      env.DB.prepare(
        "INSERT INTO components (sbom_id,package_name,ecosystem,version,purl,matchable) VALUES ('peer','demo','PyPI','1.5.0','pkg:pypi/demo@1.5.0',1)",
      ),
    ]);
    respond({ url: "https://osv.test/npm/modified_id.csv", status: 500 });
    respond({
      url: "https://osv.test/PyPI/modified_id.csv",
      status: 200,
      text: "modified,id\n2026-01-02T00:00:00Z,OSV-peer\n",
    });
    respond({
      url: "https://osv.test/PyPI/OSV-peer.json",
      status: 200,
      body: {
        id: "OSV-peer",
        modified: "2026-01-02T00:00:00Z",
        affected: [
          {
            package: { ecosystem: "PyPI", name: "demo" },
            ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
            versions: [],
          },
        ],
      },
    });

    await runScheduled(
      {
        ...env,
        OSV_API_URL: "https://api.osv.test",
        OSV_BASE_URL: "https://osv.test",
        OSV_ADVISORY_JOBS: { sendBatch: async () => undefined } as unknown as Queue,
        DISPATCH_ENABLED: "false",
        GH_APP_ID: "",
        GH_APP_INSTALLATION_ID: "",
        GH_APP_PRIVATE_KEY: "",
      },
      2_000,
    );

    await expect(
      env.DB.prepare("SELECT last_synced_at FROM sync_cursors WHERE ecosystem='PyPI'").first(
        "last_synced_at",
      ),
    ).resolves.toBe("2026-01-02T00:00:00Z");
    await expect(
      env.DB.prepare("SELECT last_synced_at FROM sync_cursors WHERE ecosystem='npm'").first(
        "last_synced_at",
      ),
    ).resolves.toBe("2026-01-01T00:00:00Z");
    expect(error).toHaveBeenCalledWith(
      "Scheduled OSV discovery failed",
      expect.objectContaining({ ecosystem: "npm" }),
    );
    error.mockRestore();
  });
});

describe("delayed GitHub attestation ingestion", () => {
  beforeEach(async () => {
    await env.DB.prepare(
      "INSERT INTO orgs VALUES ('tenant','app','owner/repo','monitor.yaml',0)",
    ).run();
    await env.DB.prepare(
      "INSERT INTO github_sources (installation_id,repository_id,org_id,workflow,ref,created_at) VALUES (?,?,?,?,?,0)",
    )
      .bind(String(INSTALLATION_ID), String(REPOSITORY_ID), "tenant", "registry_package", "")
      .run();
  });

  it("ingests a pending image once attestations become visible", async () => {
    const visibility = { value: false };
    const fixture = await githubWebhookFixture(undefined, 200, 789, visibility);
    await env.DB.prepare(
      "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,delivery_id,deployment_id,status,created_at) VALUES (?,?,?,?,?,?,'pending',0)",
    )
      .bind(
        `sha256:${"b".repeat(64)}`,
        String(INSTALLATION_ID),
        String(REPOSITORY_ID),
        `ghcr.io/owner/demo@sha256:${"b".repeat(64)}`,
        crypto.randomUUID(),
        "789",
      )
      .run();
    visibility.value = true;

    await env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 2000)").run();
    await runScheduled(
      {
        ...env,
        ...fixture.bindings,
        GH_APP_ID: "",
        GH_APP_INSTALLATION_ID: "",
        GH_APP_PRIVATE_KEY: "",
        OSV_API_URL: "https://api.osv.test",
        OSV_BASE_URL: "https://osv.test",
        OSV_ADVISORY_JOBS: { sendBatch: async () => undefined } as unknown as Queue,
      },
      2_000,
    );

    const pending = await env.DB.prepare(
      "SELECT status,error,attempted_at FROM github_ingestion_jobs",
    ).first();
    expect(pending, JSON.stringify(pending)).toBeNull();
    expect(
      await env.DB.prepare("SELECT COUNT(*) FROM github_deliveries").first<number>("COUNT(*)"),
    ).toBe(1);
    expect(await env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)")).toBe(2);
  });

  it("continues large attestation indexes within the subrequest budget", async () => {
    const fixture = await githubWebhookFixture("many-attestations");
    await env.DB.prepare(
      "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,created_at) VALUES (?,?,?,?, 'pending',0)",
    )
      .bind(
        `sha256:${"b".repeat(64)}`,
        String(INSTALLATION_ID),
        String(REPOSITORY_ID),
        `ghcr.io/owner/demo@sha256:${"b".repeat(64)}`,
      )
      .run();
    await env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 2000)").run();

    await runScheduled(
      {
        ...env,
        ...fixture.bindings,
        GH_APP_ID: "",
        GH_APP_INSTALLATION_ID: "",
        GH_APP_PRIVATE_KEY: "",
        OSV_API_URL: "https://api.osv.test",
        OSV_BASE_URL: "https://osv.test",
        OSV_ADVISORY_JOBS: { sendBatch: async () => undefined } as unknown as Queue,
      },
      2_000,
    );

    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM github_ingestion_jobs").first<number>("COUNT(*)"),
    ).resolves.toBe(0);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)"),
    ).resolves.toBe(1);
  });

  it("finds SPDX bundles after unrelated empty referrers", async () => {
    const fixture = await githubWebhookFixture("mixed-referrers");
    await env.DB.prepare(
      "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,created_at) VALUES (?,?,?,?, 'pending',0)",
    )
      .bind(
        `sha256:${"b".repeat(64)}`,
        String(INSTALLATION_ID),
        String(REPOSITORY_ID),
        `ghcr.io/owner/demo@sha256:${"b".repeat(64)}`,
      )
      .run();
    await env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 2000)").run();
    const bindings = {
      ...env,
      ...fixture.bindings,
      GH_APP_ID: "",
      GH_APP_INSTALLATION_ID: "",
      GH_APP_PRIVATE_KEY: "",
      OSV_API_URL: "https://api.osv.test",
      OSV_BASE_URL: "https://osv.test",
      OSV_ADVISORY_JOBS: { sendBatch: async () => undefined } as unknown as Queue,
    };

    // Cron runs are hours apart, so each pass must clear the ingestion retry delay.
    for (let pass = 0; pass < 4; pass += 1)
      await runScheduled(bindings, 2_000 + pass * 4 * 3_600_000);

    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM github_ingestion_jobs").first<number>("COUNT(*)"),
    ).resolves.toBe(0);
    await expect(
      env.DB.prepare("SELECT COUNT(*) FROM sboms").first<number>("COUNT(*)"),
    ).resolves.toBe(2);
  });

  it("keeps processing the queue when one job yields an unusable predicate", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const fixture = await githubWebhookFixture("predicate");
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,attempted_at,created_at) VALUES (?,?,?,?, 'failed',?,0)",
      ).bind(
        `sha256:${"b".repeat(64)}`,
        String(INSTALLATION_ID),
        String(REPOSITORY_ID),
        `ghcr.io/owner/demo@sha256:${"b".repeat(64)}`,
        1_000,
      ),
      env.DB.prepare(
        "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,attempted_at,created_at) VALUES (?,?,?,?, 'pending',NULL,1)",
      ).bind(
        `sha256:${"f".repeat(64)}`,
        String(INSTALLATION_ID),
        String(REPOSITORY_ID),
        `ghcr.io/owner/demo@sha256:${"f".repeat(64)}`,
      ),
    ]);
    await env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 2000)").run();

    await runScheduled(
      {
        ...env,
        ...fixture.bindings,
        GH_APP_ID: "",
        GH_APP_INSTALLATION_ID: "",
        GH_APP_PRIVATE_KEY: "",
        OSV_API_URL: "https://api.osv.test",
        OSV_BASE_URL: "https://osv.test",
        OSV_ADVISORY_JOBS: { sendBatch: async () => undefined } as unknown as Queue,
      },
      2_000_000,
    );

    const failed = await env.DB.prepare(
      "SELECT error FROM github_ingestion_jobs WHERE subject_digest=?",
    )
      .bind(`sha256:${"b".repeat(64)}`)
      .first<{ readonly error: string | null }>();
    expect(failed?.error).toMatch(/ZodError: \[/);
    await expect(
      env.DB.prepare("SELECT attempted_at FROM github_ingestion_jobs WHERE subject_digest=?")
        .bind(`sha256:${"f".repeat(64)}`)
        .first<number>("attempted_at"),
    ).resolves.toBe(2_000_000);
    expect(error).toHaveBeenCalledWith(
      "Scheduled GitHub ingestion failed",
      expect.objectContaining({
        subjectDigest: `sha256:${"b".repeat(64)}`,
      }),
    );
    error.mockRestore();
  });

  it("matches an already-ingested image even when ingestion consumes its budget", async () => {
    const fixture = await githubWebhookFixture("many-attestations");
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,created_at) VALUES (?,?,?,?, 'pending',0)",
      ).bind(
        `sha256:${"b".repeat(64)}`,
        String(INSTALLATION_ID),
        String(REPOSITORY_ID),
        `ghcr.io/owner/demo@sha256:${"b".repeat(64)}`,
      ),
      env.DB.prepare(
        "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at) VALUES ('starved','tenant','image','logical','linux/amd64','digest','pending',0)",
      ),
      env.DB.prepare(
        "INSERT INTO components (id,sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (77,'starved','demo','npm','1.5.0','pkg:npm/demo@1.5.0',1)",
      ),
      env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 2000)"),
    ]);

    await runScheduled(
      {
        ...env,
        ...fixture.bindings,
        GH_APP_ID: "",
        GH_APP_INSTALLATION_ID: "",
        GH_APP_PRIVATE_KEY: "",
        OSV_API_URL: "https://api.osv.test",
        OSV_BASE_URL: "https://osv.test",
        OSV_ADVISORY_JOBS: { sendBatch: async () => undefined } as unknown as Queue,
      },
      2_000,
    );

    await expect(
      env.DB.prepare("SELECT backfill_status FROM sboms WHERE id='starved'").first(
        "backfill_status",
      ),
    ).resolves.toBe("complete");
  });

  it("processes never-attempted jobs before retrying pending peers", async () => {
    const fixture = await githubWebhookFixture("unattested");
    const rows = Array.from({ length: 11 }, (_, index) =>
      env.DB.prepare(
        "INSERT INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,attempted_at,created_at) VALUES (?,?,?,?, 'pending',?,?)",
      ).bind(
        `sha256:${index.toString(16).padStart(64, "0")}`,
        String(INSTALLATION_ID),
        String(REPOSITORY_ID),
        `ghcr.io/owner/demo@sha256:${index.toString(16).padStart(64, "0")}`,
        index < 10 ? 1_000 : null,
        index,
      ),
    );
    await env.DB.batch(rows);
    await env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 2000)").run();

    await runScheduled(
      {
        ...env,
        ...fixture.bindings,
        GH_APP_ID: "",
        GH_APP_INSTALLATION_ID: "",
        GH_APP_PRIVATE_KEY: "",
        OSV_API_URL: "https://api.osv.test",
        OSV_BASE_URL: "https://osv.test",
        OSV_ADVISORY_JOBS: { sendBatch: async () => undefined } as unknown as Queue,
      },
      2_000_000,
    );

    await expect(
      env.DB.prepare("SELECT attempted_at FROM github_ingestion_jobs WHERE created_at=10").first(
        "attempted_at",
      ),
    ).resolves.toBe(2_000_000);
  });
});
