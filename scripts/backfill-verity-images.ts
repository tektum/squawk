import { createHmac } from "node:crypto";
import { z } from "zod";

const organization = "tektum";
const repository = "tektum/verity-images";
const repositoryId = 1_316_006_990;
const installationId = 151_159_455;
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const packageSchema = z.object({
  id: z.number().int().positive(),
  name: z.string().min(1),
  repository: z.object({ id: z.number().int().positive(), full_name: z.string() }).nullable(),
});
const versionSchema = z.object({
  id: z.number().int().positive(),
  name: digestSchema,
  metadata: z.object({
    container: z.object({ tags: z.array(z.string().min(1)) }),
  }),
});
const applyEnvironmentSchema = z.object({
  GH_WEBHOOK_SECRET: z.string().min(32),
  SQUAWK_WEBHOOK_URL: z
    .string()
    .url()
    .default("https://squawk-staging.omerc.workers.dev/webhooks/github"),
});

class BackfillError extends Error {
  readonly name = "BackfillError";
}

function github(path: string): unknown {
  const result = Bun.spawnSync(["gh", "api", "--paginate", path]);
  if (result.exitCode !== 0) throw new BackfillError(result.stderr.toString());
  return JSON.parse(result.stdout.toString());
}

const apply =
  z.union([z.tuple([]), z.tuple([z.literal("--apply")])]).parse(process.argv.slice(2)).length === 1;
const packages = z
  .array(packageSchema)
  .parse(github(`orgs/${organization}/packages?package_type=container&per_page=100`))
  .filter((pkg) => pkg.repository?.id === repositoryId && pkg.repository.full_name === repository);
const candidates = packages
  .flatMap((pkg) =>
    z
      .array(versionSchema)
      .parse(
        github(
          `orgs/${organization}/packages/container/${encodeURIComponent(pkg.name)}/versions?per_page=100`,
        ),
      )
      .flatMap((version) => {
        const tag = version.metadata.container.tags
          .filter((value) => !value.startsWith("sha256-"))
          .sort()[0];
        return tag ? [{ package: pkg, tag, version }] : [];
      }),
  )
  .sort((left, right) =>
    `${left.package.name}\0${left.version.name}`.localeCompare(
      `${right.package.name}\0${right.version.name}`,
    ),
  );

console.log(`${candidates.length} historical tagged indexes${apply ? "" : " (dry run)"}`);
if (!apply) process.exit(0);

const environment = applyEnvironmentSchema.parse(process.env);
for (const [index, candidate] of candidates.entries()) {
  const body = JSON.stringify({
    action: "updated",
    installation: { id: installationId },
    registry_package: {
      id: candidate.package.id,
      name: candidate.package.name,
      namespace: organization,
      package_type: "container",
      package_version: {
        id: candidate.version.id,
        container_metadata: {
          tag: { name: candidate.tag, digest: candidate.version.name },
          manifest: {
            digest: candidate.version.name,
            media_type: "application/vnd.oci.image.index.v1+json",
            uri: `repositories/${organization}/${candidate.package.name}/manifests/${candidate.version.name}`,
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
      `${candidate.package.name}@${candidate.version.name}: HTTP ${response.status}`,
    );
  console.log(`${index + 1}/${candidates.length} ${candidate.package.name} ${response.status}`);
}
