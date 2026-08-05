import { createHmac } from "node:crypto";
import { z } from "zod";

const organization = "tektum";
const repository = "tektum/verity-images";
const repositoryId = 1_316_006_990;
const installationId = 151_159_455;
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const candidateSchema = z.array(
  z.object({
    package_id: z.number().int().positive(),
    package_name: z.string().min(1),
    package_version_id: z.number().int().positive(),
    tag: z.string().min(1),
    digest: digestSchema,
  }),
);
const applyEnvironmentSchema = z.object({
  GH_WEBHOOK_SECRET: z.string().min(1),
  SQUAWK_WEBHOOK_URL: z
    .string()
    .url()
    .default("https://squawk-staging.omerc.workers.dev/webhooks/github"),
});

class BackfillError extends Error {
  readonly name = "BackfillError";
}

const apply =
  z.union([z.tuple([]), z.tuple([z.literal("--apply")])]).parse(process.argv.slice(2)).length === 1;
const candidates = candidateSchema.parse(
  JSON.parse(await Bun.file(new URL("./backfill-verity-images.json", import.meta.url)).text()),
);

console.log(`${candidates.length} historical tagged indexes${apply ? "" : " (dry run)"}`);
if (!apply) process.exit(0);

const environment = applyEnvironmentSchema.parse(process.env);
for (const [index, candidate] of candidates.entries()) {
  const body = JSON.stringify({
    action: "updated",
    installation: { id: installationId },
    registry_package: {
      id: candidate.package_id,
      name: candidate.package_name,
      namespace: organization,
      package_type: "container",
      package_version: {
        id: candidate.package_version_id,
        container_metadata: {
          tag: { name: candidate.tag, digest: candidate.digest },
          manifest: {
            digest: candidate.digest,
            media_type: "application/vnd.oci.image.index.v1+json",
            uri: `repositories/${organization}/${candidate.package_name}/manifests/${candidate.digest}`,
          },
        },
      },
    },
    repository: { id: repositoryId, full_name: repository },
    sender: { id: 41_898_282, login: "github-actions[bot]" },
  });
  const response = await fetch(environment.SQUAWK_WEBHOOK_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-github-delivery": crypto.randomUUID(),
      "x-github-event": "registry_package",
      "x-hub-signature-256": `sha256=${createHmac("sha256", environment.GH_WEBHOOK_SECRET).update(body).digest("hex")}`,
    },
    body,
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok)
    throw new BackfillError(
      `${candidate.package_name}@${candidate.digest}: HTTP ${response.status}`,
    );
  console.log(`${index + 1}/${candidates.length} ${candidate.package_name} ${response.status}`);
}
