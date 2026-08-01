import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const directory = mkdtempSync(join(tmpdir(), "squawk-receiver-"));
const gh = join(directory, "gh");
const log = join(directory, "gh.log");
writeFileSync(
  gh,
  `#!/bin/bash
printf '%s\n' "$*" >> "$GH_LOG"
if [[ $1 == api ]]; then printf '%s\n' "$GH_RESPONSE"; fi`,
);
chmodSync(gh, 0o755);
const digest = `sha256:${"a".repeat(64)}`;
const delivery = "b".repeat(64);
const payload = JSON.stringify({
  schema_version: 1,
  delivery_id: delivery,
  logical_image_ref: `ghcr.io/x@${digest}`,
  package_name: "demo",
  ecosystem: "npm",
  version: "1",
  vuln_id: "OSV-1",
  severity: "high",
  platforms: [
    { platform: "linux/amd64", image_ref: `ghcr.io/x@${digest}` },
    { platform: "linux/arm64", image_ref: `ghcr.io/x@${digest}` },
  ],
});
const run = (body: string, response: string) => {
  const payloadPath = join(directory, "payload.json");
  writeFileSync(payloadPath, body);
  return spawnSync(
    "bash",
    [
      `${process.env.VERITY_DIR ?? "../verity-images-squawk"}/scripts/monitor_sboms.sh`,
      "--squawk-payload",
      payloadPath,
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH}`,
        GH_LOG: log,
        GH_RESPONSE: response,
        GITHUB_REPOSITORY: "owner/repo",
        RUN_URL: "https://run.test",
      },
    },
  );
};
writeFileSync(log, "");
if (run(payload, "[[]]").status !== 0) throw new Error("valid delivery failed");
const existing = `[[{"number":7,"title":"issue","state":"OPEN","body":"<!-- squawk-delivery:${delivery} -->","user":{"login":"github-actions[bot]"}}]]`;
if (run(payload, existing).status !== 0) throw new Error("duplicate delivery failed");
const commands = readFileSync(log, "utf8");
if (
  (commands.match(/issue create/g) ?? []).length !== 1 ||
  (commands.match(/issue edit/g) ?? []).length !== 1
)
  throw new Error("delivery dedup contract failed");
if (run('{"schema_version":2}', "[[]]").status === 0)
  throw new Error("invalid schema was accepted");
rmSync(directory, { recursive: true, force: true });
console.log("receiver: one create, duplicate edit, two platforms, invalid schema rejected");
