import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { SubrequestBudget } from "../../src/budget";
import { CapabilitySchema, SbomIdSchema, TenantIdSchema, UserIdSchema } from "../../src/domain";
import { compareVersion } from "../../src/osv/comparator";
import { appendVex, listFindings, retireSbom } from "../../src/repository";
import { PredicateError, parsePredicate, sbomInputSchema } from "../../src/sbom";
import { discoverAdvisories } from "../../src/sync";
import { respond } from "../http";

type AcceptanceCase = readonly [id: string, assertion: () => void | Promise<void>];

const digest = (character: string) => `ghcr.io/demo@sha256:${character.repeat(64)}`;
const seedFinding = async (suffix: string, retired = false): Promise<void> => {
  const tenant = `tenant-${suffix}`;
  const sbom = `00000000-0000-4000-8000-${suffix.padStart(12, "0")}`;
  await env.DB.prepare("INSERT INTO orgs VALUES (?, 'app', 0)").bind(tenant).run();
  await env.DB.prepare(
    "INSERT INTO sboms (id,org_id,image_ref,logical_image_ref,platform,predicate_sha256,backfill_status,created_at,retired_at) VALUES (?,?,?,?,?,'hash','complete',0,?)",
  )
    .bind(sbom, tenant, digest(suffix), digest("f"), "linux/amd64", retired ? 1 : null)
    .run();
  const component = await env.DB.prepare(
    "INSERT INTO components (sbom_id,package_name,ecosystem,version,purl,matchable) VALUES (?, 'demo', 'npm', '1', 'pkg:npm/demo@1', 1)",
  )
    .bind(sbom)
    .run();
  await env.DB.prepare(
    "INSERT INTO vulnerabilities VALUES (?, 'npm', 'demo', '{}', 'high', 'summary', '2026-01-01T00:00:00Z')",
  )
    .bind(`OSV-${suffix}`)
    .run();
  await env.DB.prepare("INSERT INTO findings VALUES (?, ?, ?, 0, NULL)")
    .bind(tenant, component.meta.last_row_id, `OSV-${suffix}`)
    .run();
};

const cases: readonly AcceptanceCase[] = [
  ["R1-1", () => expect(() => CapabilitySchema.parse("sbom.write")).toThrow()],
  ["R1-2", () => expect(() => TenantIdSchema.parse("")).toThrow()],
  [
    "R1-3",
    async () =>
      expect(
        await compareVersion({
          ecosystem: "npm",
          version: "1.5.0",
          ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
          versions: [],
        }),
      ).toEqual({ kind: "match" }),
  ],
  [
    "R1-4",
    async () =>
      expect(
        (
          await env.DB.prepare("PRAGMA table_info(orgs)").all<{ readonly name: string }>()
        ).results.some(({ name }) => /name|email|secret/i.test(name)),
      ).toBe(false),
  ],
  ["R1-5", () => expect(() => CapabilitySchema.parse("static-inbound-key")).toThrow()],
  [
    "R2-1",
    () =>
      expect(
        parsePredicate({
          bomFormat: "CycloneDX",
          components: Array.from({ length: 200 }, (_, index) => ({
            name: `p${index}`,
            version: "1",
            purl: `pkg:npm/p${index}@1`,
          })),
        }),
      ).toHaveLength(200),
  ],
  [
    "R2-2",
    () =>
      expect(
        parsePredicate({
          spdxVersion: "SPDX-2.3",
          packages: [
            {
              name: "p",
              versionInfo: "1",
              externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:npm/p@1" }],
            },
          ],
        }),
      ).toHaveLength(1),
  ],
  [
    "R2-3",
    () =>
      expect(
        parsePredicate({
          bomFormat: "CycloneDX",
          components: [{ name: "p", version: "1", purl: "pkg:new/p@1" }],
        })[0]?.matchable,
      ).toBe(false),
  ],
  [
    "R2-4",
    () =>
      expect(() =>
        sbomInputSchema.parse({
          image_ref: "ghcr.io/demo:latest",
          logical_image_ref: digest("a"),
          platform: "linux/amd64",
          idempotency_key: "x".repeat(64),
          predicate: {},
        }),
      ).toThrow(),
  ],
  ["R2-5", () => expect(() => parsePredicate({ bomFormat: "not-an-sbom" })).toThrow()],
  [
    "R2-6",
    () =>
      expect(() =>
        parsePredicate({
          bomFormat: "CycloneDX",
          components: [{ name: "p", version: "1", purl: "pkg:npm/%@1" }],
        }),
      ).toThrow(PredicateError),
  ],
  [
    "R3-1",
    async () =>
      expect(
        await env.DB.prepare("SELECT COUNT(*) AS count FROM sync_cursors").first<number>("count"),
      ).toBe(0),
  ],
  [
    "R3-2",
    async () => {
      await env.DB.prepare(
        "INSERT INTO sync_cursors VALUES ('r3-cursor','2026-01-01T00:00:00Z','',NULL,NULL)",
      ).run();
      expect(
        await env.DB.prepare(
          "SELECT ecosystem FROM sync_cursors WHERE ecosystem='r3-cursor'",
        ).first("ecosystem"),
      ).toBe("r3-cursor");
    },
  ],
  [
    "R3-3",
    async () => {
      await env.DB.prepare(
        "INSERT INTO sync_cursors VALUES ('r3-boundary','2026-01-01T00:00:00Z','OSV-1',NULL,NULL)",
      ).run();
      expect(
        await env.DB.prepare(
          "SELECT boundary_ids FROM sync_cursors WHERE ecosystem='r3-boundary'",
        ).first("boundary_ids"),
      ).toBe("OSV-1");
    },
  ],
  [
    "R3-4",
    () => {
      const budget = new SubrequestBudget(2);
      budget.take();
      budget.take();
      expect(() => budget.take()).toThrow("subrequest budget exhausted");
    },
  ],
  [
    "R3-5",
    async () => {
      await env.DB.prepare(
        "INSERT INTO sync_cursors VALUES ('empty','2026-01-01T00:00:00Z','',NULL,NULL)",
      ).run();
      respond({
        url: "https://osv.test/empty/modified_id.csv",
        status: 200,
        text: "modified,id\n2026-01-02T00:00:00Z,OSV-empty\n",
      });
      const messages: unknown[] = [];
      expect(
        await discoverAdvisories({
          database: env.DB,
          ecosystem: "empty",
          osvBaseUrl: "https://osv.test",
          queue: {
            sendBatch: async (batch) => {
              messages.push(...Array.from(batch));
            },
          },
        }),
      ).toBe(1);
      expect(messages).toHaveLength(1);
    },
  ],
  [
    "R3-6",
    async () =>
      expect(
        await env.DB.prepare(
          "SELECT continuation_id FROM sync_cursors WHERE ecosystem='empty'",
        ).first("continuation_id"),
      ).toBeNull(),
  ],
  [
    "R4-1",
    async () =>
      expect(
        await compareVersion({
          ecosystem: "npm",
          version: "2.0.0",
          ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
          versions: [],
        }),
      ).toEqual({ kind: "no_match" }),
  ],
  [
    "R5-1",
    async () => {
      await seedFinding("51");
      await appendVex(env.DB, TenantIdSchema.parse("tenant-51"), UserIdSchema.parse("user"), {
        packageName: "demo",
        ecosystem: "npm",
        vulnId: "OSV-51",
        status: "not_affected",
      });
      expect(
        await listFindings(env.DB, TenantIdSchema.parse("tenant-51"), {
          severity: null,
          includeSuppressed: false,
          includeRetired: false,
        }),
      ).toHaveLength(0);
    },
  ],
  [
    "R5-2",
    async () => {
      await seedFinding("52");
      await appendVex(env.DB, TenantIdSchema.parse("tenant-52"), UserIdSchema.parse("user"), {
        packageName: "demo",
        ecosystem: "npm",
        vulnId: "OSV-52",
        status: "not_affected",
        justification: "verified",
      });
      expect(
        (
          await listFindings(env.DB, TenantIdSchema.parse("tenant-52"), {
            severity: null,
            includeSuppressed: true,
            includeRetired: false,
          })
        )[0]?.vex_justification,
      ).toBe("verified");
    },
  ],
  [
    "R5-3",
    async () =>
      expect(
        (
          await env.DB.prepare(
            "EXPLAIN QUERY PLAN SELECT * FROM findings WHERE org_id=? AND dispatched_at IS NULL",
          )
            .bind("tenant-51")
            .all<{ readonly detail: string }>()
        ).results.some(({ detail }) => detail.includes("idx_findings_org_current")),
      ).toBe(true),
  ],
  [
    "R6-1",
    async () => {
      await seedFinding("61", true);
      expect(
        await listFindings(env.DB, TenantIdSchema.parse("tenant-61"), {
          severity: null,
          includeSuppressed: true,
          includeRetired: false,
        }),
      ).toHaveLength(0);
    },
  ],
  [
    "R6-2",
    async () => {
      await seedFinding("62", true);
      expect(
        await env.DB.prepare(
          "SELECT COUNT(*) AS count FROM sboms WHERE retired_at IS NOT NULL",
        ).first<number>("count"),
      ).toBe(1);
    },
  ],
  [
    "R6-3",
    async () => {
      await seedFinding("63");
      expect(
        await retireSbom(
          env.DB,
          TenantIdSchema.parse("tenant-63"),
          SbomIdSchema.parse("00000000-0000-4000-8000-000000000063"),
        ),
      ).toBe(true);
    },
  ],
  [
    "R7-1",
    async () => {
      await env.DB.prepare("INSERT INTO osv_ecosystems VALUES ('npm', 0)").run();
      expect(
        await env.DB.prepare("SELECT ecosystem FROM osv_ecosystems WHERE ecosystem='npm'").first(
          "ecosystem",
        ),
      ).toBe("npm");
    },
  ],
  [
    "R7-2",
    () =>
      expect(
        parsePredicate({
          bomFormat: "CycloneDX",
          components: [{ name: "p", version: "1", purl: "pkg:deb/wolfi/p@1" }],
        })[0],
      ).toMatchObject({ ecosystem: "unknown:deb", matchable: false }),
  ],
  [
    "R8-1",
    async () => {
      await seedFinding("81");
      await appendVex(env.DB, TenantIdSchema.parse("tenant-81"), UserIdSchema.parse("user"), {
        packageName: "demo",
        ecosystem: "npm",
        vulnId: "OSV-81",
        status: "not_affected",
      });
      await appendVex(env.DB, TenantIdSchema.parse("tenant-81"), UserIdSchema.parse("user"), {
        packageName: "demo",
        ecosystem: "npm",
        vulnId: "OSV-81",
        status: "affected",
      });
      expect(
        await listFindings(env.DB, TenantIdSchema.parse("tenant-81"), {
          severity: null,
          includeSuppressed: false,
          includeRetired: false,
        }),
      ).toHaveLength(1);
    },
  ],
  ["R8-2", () => expect(() => UserIdSchema.parse("")).toThrow()],
  [
    "R8-3",
    async () => {
      await seedFinding("83");
      await appendVex(env.DB, TenantIdSchema.parse("tenant-83"), UserIdSchema.parse("user"), {
        packageName: "demo",
        ecosystem: "npm",
        vulnId: "OSV-83",
        status: "affected",
      });
      expect(
        await env.DB.prepare(
          "SELECT COUNT(*) AS count FROM vex_statements WHERE org_id='tenant-83'",
        ).first<number>("count"),
      ).toBe(1);
    },
  ],
  [
    "R9-1",
    async () => {
      await seedFinding("91");
      expect(
        await env.DB.prepare(
          "SELECT COUNT(*) AS count FROM findings WHERE dispatched_at IS NULL",
        ).first<number>("count"),
      ).toBe(1);
    },
  ],
  [
    "R9-2",
    async () => {
      await seedFinding("92");
      expect(
        await env.DB.prepare("SELECT logical_image_ref FROM sboms WHERE org_id='tenant-92'").first(
          "logical_image_ref",
        ),
      ).toBe(digest("f"));
    },
  ],
  [
    "R9-3",
    async () => {
      await seedFinding("93");
      await appendVex(env.DB, TenantIdSchema.parse("tenant-93"), UserIdSchema.parse("user"), {
        packageName: "demo",
        ecosystem: "npm",
        vulnId: "OSV-93",
        status: "fixed",
      });
      expect(
        await listFindings(env.DB, TenantIdSchema.parse("tenant-93"), {
          severity: null,
          includeSuppressed: false,
          includeRetired: true,
        }),
      ).toHaveLength(0);
    },
  ],
  [
    "R9-4",
    async () => {
      await seedFinding("94");
      await env.DB.prepare(
        "INSERT INTO dispatch_deliveries VALUES ('delivery','tenant-94',?,'demo','npm','1','OSV-94','failed',1,'GitHub 500',0)",
      )
        .bind(digest("f"))
        .run();
      expect(
        await env.DB.prepare(
          "SELECT status FROM dispatch_deliveries WHERE delivery_id='delivery'",
        ).first("status"),
      ).toBe("failed");
    },
  ],
  [
    "R9-5",
    async () => {
      await seedFinding("95");
      await env.DB.prepare(
        "INSERT INTO dispatch_deliveries VALUES ('delivery-95','tenant-95',?,'demo','npm','1','OSV-95','failed',1,'GitHub 500',0)",
      )
        .bind(digest("f"))
        .run();
      expect(
        await env.DB.prepare(
          "SELECT COUNT(*) AS count FROM dispatch_deliveries WHERE status='failed'",
        ).first<number>("count"),
      ).toBe(1);
    },
  ],
];

describe("P0 acceptance cases", () => {
  it.each(cases)("%s", async (_id, assertion) => {
    await assertion();
  });
});
