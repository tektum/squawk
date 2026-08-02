import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const producer = "../verity-images-squawk";
const action = readFileSync(`${producer}/.github/actions/publish-image/action.yaml`, "utf8");
const workflow = readFileSync(`${producer}/.github/workflows/build.yaml`, "utf8");
const contract = spawnSync("bash", [`${producer}/scripts/test_notify_squawk.sh`], {
  encoding: "utf8",
});

if (contract.status !== 0)
  throw new Error(`producer deployment contract failed: ${contract.stdout}${contract.stderr}`);
if (
  action.match(/actions\/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d/g)?.length !== 2 ||
  !action.includes("scripts/notify_squawk.sh") ||
  !workflow.includes("      deployments: write\n")
)
  throw new Error("producer is missing pinned platform attestations or deployment permission");
for (const legacy of ["SQUAWK_URL", "SQUAWK_AUDIENCE", "DESCOPE_TOKEN_URL", "/v1/sboms"])
  if (action.includes(legacy)) throw new Error(`legacy producer credential remains: ${legacy}`);

console.log(
  "producer action: two pinned GitHub SBOM attestations and two credential-free deployments",
);
