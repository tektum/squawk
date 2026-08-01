import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { z } from "zod";

const actionPath = `${process.env.VERITY_DIR ?? "../verity-images-squawk"}/.github/actions/publish-image/action.yaml`;
const action = readFileSync(actionPath, "utf8");
const section = action.match(
  / {4}- name: Submit verified platform predicates to Squawk[\s\S]*?\n {4}- name:/,
)?.[0];
if (!section) throw new Error("Squawk publish step not found");
const run = section.match(/ {6}run: \|\n([\s\S]*?)\n {4}- name:/)?.[1];
if (!run) throw new Error("Squawk publish shell not found");
const script = run
  .split("\n")
  .map((line) => line.slice(8))
  .join("\n");

function fixture(failCycloneDx: boolean): {
  readonly status: number;
  readonly requests: readonly unknown[];
  readonly output: string;
} {
  const directory = mkdtempSync(join(tmpdir(), "squawk-action-"));
  const bin = join(directory, "bin");
  Bun.spawnSync(["mkdir", bin]);
  const requestLog = join(directory, "requests.jsonl");
  const commands: Record<string, string> = {
    cosign: `#!/bin/bash
type=; while [[ $# -gt 0 ]]; do [[ $1 == --type ]] && type=$2; shift; done
[[ $type != cyclonedx || ${failCycloneDx ? "true" : "false"} != true ]] || exit 1
for arch in amd64 arm64; do
  if [[ $type == spdxjson ]]; then predicate=$(jq -nc --arg arch "$arch" '{name:("demo-verity-platform-" + $arch),spdxVersion:"SPDX-2.3",packages:[{name:"demo",versionInfo:"1",externalRefs:[{referenceType:"purl",referenceLocator:"pkg:npm/demo@1"}]}]}'); else predicate=$(jq -nc --arg arch "$arch" '{name:("demo-verity-platform-" + $arch),bomFormat:"CycloneDX",components:[{name:"demo",version:"1",purl:"pkg:npm/demo@1"}]}'); fi
  statement=$(jq -nc --argjson predicate "$predicate" '{predicate:$predicate}')
  jq -nc --arg payload "$(printf %s "$statement" | base64 -w0)" '{payload:$payload}'
done`,
    docker: `#!/bin/bash
printf '%s' '{"manifests":[{"digest":"sha256:${"1".repeat(64)}","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:${"2".repeat(64)}","platform":{"os":"linux","architecture":"arm64"}}]}'`,
    curl: `#!/bin/bash
body=; for ((i=1;i<=$#;i++)); do [[ \${!i} == --data-binary ]] && { j=$((i+1)); body=\${!j}; }; done
if [[ $* == *ACTIONS* || $* == *audience=* ]]; then printf '%s' '{"value":"github-oidc"}'; elif [[ $* == *https://descope.test/token* ]]; then printf '%s' '{"access_token":"descope-token"}'; else [[ $body == @- ]] && cat >> "$REQUEST_LOG"; printf '\n' >> "$REQUEST_LOG"; printf '%s' '{}'; fi`,
  };
  for (const [name, content] of Object.entries(commands)) {
    const path = join(bin, name);
    writeFileSync(path, content);
    chmodSync(path, 0o755);
  }
  writeFileSync(requestLog, "");
  const result = spawnSync("bash", ["-c", script], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      REQUEST_LOG: requestLog,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token",
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://actions.test/token?source=ACTIONS",
      DESCOPE_TOKEN_URL: "https://descope.test/token",
      DIGEST: `sha256:${"a".repeat(64)}`,
      GITHUB_SHA: "commit",
      SQUAWK_AUDIENCE: "squawk-audience",
      SQUAWK_URL: "https://squawk.test",
      TARGET: "ghcr.io/tektum/demo",
    },
  });
  const requests = readFileSync(requestLog, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  rmSync(directory, { recursive: true, force: true });
  return { status: result.status ?? 1, requests, output: `${result.stdout}${result.stderr}` };
}

const happy = fixture(false);
if (happy.status !== 0 || happy.requests.length !== 2)
  throw new Error(`happy action failed: ${happy.output}`);
const predicates = happy.requests.map(
  (request) => z.object({ predicate: z.record(z.string(), z.unknown()) }).parse(request).predicate,
);
if (
  predicates.length !== 2 ||
  !predicates.every((predicate) => predicate.bomFormat === "CycloneDX")
)
  throw new Error("two verified CycloneDX platform predicates were not submitted");
if (happy.output.includes("descope-token") || happy.output.includes("github-oidc"))
  throw new Error("token leaked to output");
const tampered = fixture(true);
if (tampered.status === 0 || tampered.requests.length !== 0)
  throw new Error("missing signed CycloneDX predicate was accepted");
console.log(
  "producer action: SPDX + CycloneDX submitted; tampered/missing signature rejected; no token output",
);
