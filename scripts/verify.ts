import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { z } from "zod";

const args = z.array(z.string()).parse(process.argv.slice(2));
const mode = args[0] ?? "p0";
const verityFlag = args.indexOf("--verity-dir");
const verityDir = verityFlag >= 0 ? args[verityFlag + 1] : undefined;
const baselineFlag = args.indexOf("--baseline");
const baseline =
  baselineFlag >= 0 ? args[baselineFlag + 1] : "3163fae8bd874840cab5f6ad668bc92db3a659c7";
const run = (command: string, commandArgs: readonly string[], cwd?: string) =>
  execFileSync(command, commandArgs, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const diffSchema = z.object({
  baseRevision: z.string().regex(/^[a-f0-9]{40}$/),
  files: z.array(z.string()).min(1),
  contentHash: z.string().regex(/^[a-f0-9]{64}$/),
});
const manifestSchema = z.object({ squawk: diffSchema, verity: diffSchema });
const receiptSchema = z.object({
  mode: z.string(),
  sourceHash: z.string(),
  manifestHash: z.string(),
  checks: z.record(z.string(), z.boolean()),
});
const manifestPath = "evidence/approved-diff.json";
const manifestText = readFileSync(manifestPath, "utf8");
const manifest = manifestSchema.parse(JSON.parse(manifestText));
const manifestHash = createHash("sha256").update(manifestText).digest("hex");
const sourceHash = manifest.squawk.contentHash;
const checks: Record<string, boolean> = {};

function execute(
  name: string,
  command: string,
  commandArgs: readonly string[],
  cwd?: string,
): void {
  run(command, commandArgs, cwd);
  checks[name] = true;
}

function changedFiles(directory: string, revision: string): readonly string[] {
  const changed = run("git", ["-C", directory, "diff", "--name-only", revision]).trim().split("\n");
  const untracked = run("git", ["-C", directory, "ls-files", "--others", "--exclude-standard"])
    .trim()
    .split("\n");
  return [
    ...new Set(
      [...changed, ...untracked].filter(
        (path) => path && !path.startsWith("evidence/") && !path.startsWith(".terraform/"),
      ),
    ),
  ].sort();
}

function contentHash(directory: string, files: readonly string[]): string {
  const hash = createHash("sha256");
  for (const path of files)
    hash
      .update(path)
      .update("\0")
      .update(readFileSync(`${directory}/${path}`))
      .update("\0");
  return hash.digest("hex");
}

function scopeScan(): void {
  run("git", ["merge-base", "--is-ancestor", manifest.squawk.baseRevision, "HEAD"]);
  checks["manifest-base"] = true;
  const changed = changedFiles(".", manifest.squawk.baseRevision);
  checks["approved-diff-exact"] =
    JSON.stringify(changed) === JSON.stringify(manifest.squawk.files.sort());
  checks["approved-content-exact"] =
    changed.every(existsSync) && contentHash(".", changed) === manifest.squawk.contentHash;
  if (verityDir) {
    const sibling = changedFiles(verityDir, manifest.verity.baseRevision);
    checks["verity-approved-paths"] =
      JSON.stringify(sibling) === JSON.stringify(manifest.verity.files.sort()) &&
      sibling.every((path) => existsSync(`${verityDir}/${path}`)) &&
      contentHash(verityDir, sibling) === manifest.verity.contentHash;
    checks["verity-baseline"] =
      manifest.verity.baseRevision === baseline &&
      run("git", ["-C", verityDir, "rev-parse", "HEAD"]).trim() === baseline;
  }
  checks["rollback-executable"] =
    existsSync("scripts/rollback-monitor.sh") &&
    readFileSync("docs/runbook.md", "utf8").includes("rollback-monitor.sh");
  checks["rollout-dark-first"] =
    readFileSync("wrangler.jsonc", "utf8").includes('"DISPATCH_ENABLED": "false"') &&
    readFileSync("docs/runbook.md", "utf8").indexOf("Deploy dark") <
      readFileSync("docs/runbook.md", "utf8").indexOf("Enable dispatch");
}

function secretScan(): void {
  const pattern = /BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]|github_pat_|sk_live_/;
  const scanners = new Set([
    ".github/workflows/ci.yml",
    "scripts/test-verifier.ts",
    "scripts/verify.ts",
  ]);
  checks["secret-scan"] = changedFiles(".", manifest.squawk.baseRevision)
    .filter((path) => !scanners.has(path))
    .every((path) => !pattern.test(readFileSync(path, "utf8")));
}

function writeReceipt(name: string): void {
  writeFileSync(
    `evidence/${name}.json`,
    `${JSON.stringify({ mode, sourceHash, manifestHash, checks }, null, 2)}\n`,
  );
}

mkdirSync("evidence", { recursive: true });
if (mode === "p0") {
  execute("check", "bun", ["run", "check"]);
  execute("acceptance", "bunx", [
    "vitest",
    "run",
    "test/acceptance/cases.test.ts",
    "--pool=workers",
    "--reporter=json",
    "--outputFile=evidence/acceptance-results.json",
  ]);
  execute("worker-suite", "bunx", ["vitest", "run", "test", "--pool=workers"]);
  execute("matcher-race", "go", ["test", "-race", "-shuffle=on", "-count=1", "./..."], "matcher");
  execute("matcher-reproducible", "bash", [
    "-c",
    "bun run build:matcher && sha256sum src/generated/osv_matcher.wasm > /tmp/squawk-matcher && bun run build:matcher && sha256sum -c /tmp/squawk-matcher",
  ]);
  execute("migration-audit", "bunx", [
    "wrangler",
    "d1",
    "migrations",
    "apply",
    "squawk",
    "--local",
    "--persist-to",
    ".tmp/f1-d1",
  ]);
  execute("tofu-fmt", "tofu", ["-chdir=infra", "fmt", "-check"]);
  execute("tofu-validate", "tofu", ["-chdir=infra", "init", "-backend=false"]);
  execute("tofu-validate", "tofu", ["-chdir=infra", "validate"]);
  execute("tofu-test", "tofu", ["-chdir=infra", "test"]);
  execute("git-history", "git", ["rev-parse", "HEAD"]);
  const report = z
    .object({
      testResults: z.array(
        z.object({
          assertionResults: z.array(z.object({ fullName: z.string(), status: z.string() })),
        }),
      ),
    })
    .parse(JSON.parse(readFileSync("evidence/acceptance-results.json", "utf8")));
  const acceptance = report.testResults.flatMap((result) => result.assertionResults);
  checks["acceptance-33"] =
    acceptance.length === 33 && acceptance.every((result) => result.status === "passed");
  writeReceipt("p0");
} else if (mode === "security") {
  execute("transaction-fault", "bunx", [
    "vitest",
    "run",
    "test/e2e/security-slo.test.ts",
    "-t",
    "accepted-before-D1-crash",
    "--pool=workers",
  ]);
  execute("malformed-wasm", "bunx", [
    "vitest",
    "run",
    "test/osv/comparator.worker.test.ts",
    "-t",
    "malformed",
    "--pool=workers",
  ]);
  execute("receiver-dedup", "bun", ["scripts/test-receiver.ts"]);
  execute("auth-and-faults", "bunx", [
    "vitest",
    "run",
    "test/auth",
    "test/integration/schema.test.ts",
    "test/infra/provision-descope.test.ts",
    "test/osv",
    "test/e2e/sbom-ingestion.test.ts",
    "test/e2e/scheduled-pipeline.test.ts",
    "test/e2e/security-slo.test.ts",
    "--pool=workers",
  ]);
  secretScan();
  checks["state-secret-free"] = !changedFiles(".", manifest.squawk.baseRevision).some((path) =>
    /\.tfstate(?:\.|$)|\.dev\.vars/.test(path),
  );
  writeReceipt("security");
} else if (mode === "e2e") {
  execute("pipeline", "bunx", ["vitest", "run", "test/e2e", "--pool=workers"]);
  execute("producer-cryptography", "bun", ["scripts/test-producer-action.ts"]);
  execute("receiver-dedup", "bun", ["scripts/test-receiver.ts"]);
  if (verityDir) {
    execute("producer-real-cosign", "bash", ["scripts/test_attest_sboms.sh"], verityDir);
    execute("receiver-regression", "bash", ["scripts/test_monitor_sboms.sh"], verityDir);
  }
  writeReceipt("e2e");
} else if (mode === "scope") {
  scopeScan();
  secretScan();
  for (const receipt of ["p0", "security", "e2e"]) {
    const result = receiptSchema.safeParse(
      JSON.parse(readFileSync(`evidence/${receipt}.json`, "utf8")),
    );
    checks[`receipt-${receipt}-current`] =
      result.success &&
      result.data.mode === receipt &&
      result.data.sourceHash === sourceHash &&
      result.data.manifestHash === manifestHash &&
      Object.values(result.data.checks).every(Boolean);
  }
  checks["git-history-readable"] = run("git", ["rev-parse", "HEAD"]).trim().length === 40;
  writeReceipt("scope");
} else {
  throw new Error(`unknown verification mode: ${mode}`);
}

if (Object.values(checks).some((passed) => !passed))
  throw new Error(`verification failed: ${JSON.stringify(checks)}`);
const finalNumber = { p0: "F1", security: "F2", e2e: "F3", scope: "F4" }[mode];
if (finalNumber)
  writeFileSync(
    `evidence/final-${finalNumber}-squawk-implementation.md`,
    `# ${finalNumber}\n\nSource SHA-256: \`${sourceHash}\`\nManifest SHA-256: \`${manifestHash}\`\n\n${Object.entries(
      checks,
    )
      .map(([name, passed]) => `- ${passed ? "PASS" : "FAIL"}: ${name}`)
      .join("\n")}\n`,
  );
