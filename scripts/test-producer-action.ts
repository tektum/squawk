import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { webhookSchema } from "../src/webhook-contract";

const producer = "../verity-images-squawk";
const action = readFileSync(`${producer}/.github/actions/publish-image/action.yaml`, "utf8");
const workflow = readFileSync(`${producer}/.github/workflows/build.yaml`, "utf8");
const directory = mkdtempSync(join(tmpdir(), "squawk-producer-"));
const curl = join(directory, "curl");
const deployments = join(directory, "deployments.jsonl");
writeFileSync(curl, `#!/bin/bash\ncat >> "$DEPLOYMENTS"\nprintf '\\n' >> "$DEPLOYMENTS"\n`);
chmodSync(curl, 0o755);
const contract = spawnSync(
  "bash",
  [
    `${producer}/scripts/notify_squawk.sh`,
    "ghcr.io/owner/demo",
    `sha256:${"b".repeat(64)}`,
    `sha256:${"a".repeat(64)}`,
    `sha256:${"c".repeat(64)}`,
  ],
  {
    encoding: "utf8",
    env: {
      ...process.env,
      DEPLOYMENTS: deployments,
      GITHUB_REPOSITORY: "owner/repo",
      GITHUB_SHA: "1".repeat(40),
      GITHUB_TOKEN: "token",
      PATH: `${directory}:${process.env.PATH}`,
    },
  },
);

if (contract.status !== 0)
  throw new Error(`producer deployment contract failed: ${contract.stdout}${contract.stderr}`);
const payloads = readFileSync(deployments, "utf8")
  .trim()
  .split("\n")
  .filter((line) => line.length > 0)
  .map((line, index) =>
    webhookSchema.parse({
      action: "created",
      deployment: { ...JSON.parse(line), id: index + 1, sha: "1".repeat(40) },
      installation: { id: 456 },
      repository: { id: 123, full_name: "owner/repo" },
      sender: { id: 41898282, login: "github-actions[bot]" },
    }),
  );
rmSync(directory, { force: true, recursive: true });
if (payloads.length !== 2)
  throw new Error("producer did not emit two webhook-compatible deployments");
if (
  action.match(/actions\/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d/g)?.length !== 2 ||
  !action.includes("scripts/notify_squawk.sh") ||
  !workflow.includes("      deployments: write\n      id-token: write\n")
)
  throw new Error("producer is missing pinned platform attestations or deployment permission");
for (const legacy of ["SQUAWK_URL", "SQUAWK_AUDIENCE", "DESCOPE_TOKEN_URL", "/v1/sboms"])
  if (action.includes(legacy)) throw new Error(`legacy producer credential remains: ${legacy}`);

console.log(
  "producer action: two pinned GitHub SBOM attestations and two webhook-compatible deployments",
);
