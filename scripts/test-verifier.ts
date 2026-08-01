import { appendFileSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const verify = (mode: string) =>
  spawnSync(
    "bun",
    [
      "scripts/verify.ts",
      mode,
      "--verity-dir",
      "../verity-images-squawk",
      "--baseline",
      "3163fae8bd874840cab5f6ad668bc92db3a659c7",
    ],
    { encoding: "utf8" },
  );
const original = readFileSync("src/domain.ts");
let receiptsRestored = false;
try {
  writeFileSync("oracle-unknown.txt", "unexpected");
  if (verify("scope").status === 0) throw new Error("scope accepted an unknown file");
  rmSync("oracle-unknown.txt");
  writeFileSync(
    "src/oracle-pat.ts",
    `export const leaked = "${"gh"}p_abcdefghijklmnopqrstuvwxyz0123456789"\n`,
  );
  if (verify("security").status === 0) throw new Error("security accepted a PAT");
  rmSync("src/oracle-pat.ts");
  appendFileSync("src/domain.ts", "\n");
  if (verify("scope").status === 0) throw new Error("scope accepted a stale receipt");
  writeFileSync("src/domain.ts", original);
  if (verify("scope").status === 0)
    throw new Error("scope accepted receipts invalidated by source drift");
} finally {
  rmSync("oracle-unknown.txt", { force: true });
  rmSync("src/oracle-pat.ts", { force: true });
  writeFileSync("src/domain.ts", original);
  receiptsRestored = verify("security").status === 0 && verify("scope").status === 0;
}
if (!receiptsRestored) throw new Error("verifier cleanup could not restore current receipts");
console.log("verifier: unknown file, PAT, and stale receipts rejected");
