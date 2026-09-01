import type { FixtureImage, Origin } from "./origin";
import type { LocalWorker } from "./harness";
import { query } from "./harness";

export type Check = { readonly name: string; readonly ok: boolean; readonly detail: string };
export type RecordCheck = (name: string, ok: boolean, detail: string) => void;

type CountRow = { readonly count: number };
type FindingRow = {
  readonly vuln_id: string;
  readonly package_name: string;
  readonly version: string;
};

export function createReporter(): {
  readonly checks: Check[];
  readonly record: RecordCheck;
} {
  const checks: Check[] = [];
  const record: RecordCheck = (name, ok, detail) => {
    checks.push({ name, ok, detail });
    console.log(`${ok ? "  ok  " : " FAIL "} ${name}${detail ? ` - ${detail}` : ""}`);
  };
  return { checks, record };
}

/** Asserts the complete observable contract for one catalog image. */
export function checkImage(
  scenario: "vulnerable" | "clean",
  image: FixtureImage,
  config: string,
  workspace: string,
  record: RecordCheck,
): void {
  const sboms = query<CountRow>(
    config,
    workspace,
    `SELECT COUNT(*) AS count FROM sboms WHERE logical_image_ref='${image.image}@${image.indexDigest}'`,
  );
  record(
    `${scenario}: one SBOM per platform`,
    sboms[0]?.count === image.platforms.length,
    `${String(sboms[0]?.count)} of ${image.platforms.length}`,
  );

  const findings = query<FindingRow>(
    config,
    workspace,
    `SELECT f.vuln_id AS vuln_id, c.package_name AS package_name, c.version AS version
     FROM findings f JOIN components c ON c.id=f.component_id JOIN sboms s ON s.id=c.sbom_id
     WHERE s.logical_image_ref='${image.image}@${image.indexDigest}'
     GROUP BY f.vuln_id, c.package_name, c.version ORDER BY f.vuln_id`,
  );
  const triple = (packageName: string, version: string, vulnId: string) =>
    `${packageName}\u0000${version}\u0000${vulnId}`;
  const found = new Set(findings.map((row) => triple(row.package_name, row.version, row.vuln_id)));
  const expected = new Set(
    image.expectedFindings.map((finding) =>
      triple(finding.packageName, finding.version, finding.vulnId),
    ),
  );
  const missing = [...expected].filter((finding) => !found.has(finding));
  const unexpected = [...found].filter((finding) => !expected.has(finding));
  record(
    `${scenario}: package/version/advisory triples match the real data`,
    missing.length === 0 && unexpected.length === 0,
    expected.size === 0
      ? `no findings expected, ${found.size} produced`
      : `${found.size} of ${expected.size}${missing.length ? `, missing ${missing.length}` : ""}${
          unexpected.length ? `, unexpected ${unexpected.length}` : ""
        }`,
  );
}

/** Prints the durable state and captured logs only when an assertion failed. */
export async function printDiagnostics(
  checks: readonly Check[],
  config: string,
  workspace: string,
  origin: Origin,
  worker: LocalWorker,
): Promise<void> {
  if (checks.every((check) => check.ok)) return;
  console.log("\n--- diagnostics ---");
  for (const [label, sql] of [
    [
      "ingestion jobs",
      "SELECT status, next_descriptor, saw_spdx, substr(logical_image_ref,1,60) AS image, error FROM github_ingestion_jobs",
    ],
    ["sboms", "SELECT platform, backfill_status, substr(image_ref,1,64) AS image_ref FROM sboms"],
    [
      "findings per package",
      "SELECT c.package_name, c.version, COUNT(*) AS findings FROM findings f JOIN components c ON c.id=f.component_id GROUP BY 1,2 ORDER BY 1",
    ],
    ["advisory jobs", "SELECT status, COUNT(*) AS count FROM osv_advisory_jobs GROUP BY status"],
    ["vulnerabilities", "SELECT id, package_name FROM vulnerabilities ORDER BY id"],
    ["activity", "SELECT kind, outcome, COUNT(*) AS count FROM public_activity GROUP BY 1,2"],
  ] as const) {
    const rows = query(config, workspace, sql);
    console.log(`${label}: ${rows.length === 0 ? "(none)" : ""}`);
    for (const row of rows) console.log(`  ${JSON.stringify(row)}`);
  }
  console.log("\n--- origin requests ---");
  for (const line of origin.requests.slice(0, 40)) console.log(`  ${line}`);
  console.log("\n--- worker log tail ---");
  const logText = await Bun.file(worker.logPath)
    .text()
    .catch(() => "");
  console.log(
    logText
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .slice(-25)
      .join("\n"),
  );
}
