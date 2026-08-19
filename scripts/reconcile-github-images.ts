import { z } from "zod";

const inputSchema = z.tuple([
  z.string().min(1),
  z.string().url(),
  z.string().regex(/^\d+$/),
  z.string().regex(/^\d+$/),
]);
const catalogSchema = z.object({
  images: z.array(
    z.object({
      digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
      registry: z.string().regex(/^ghcr\.io\/[a-z0-9._/-]+$/),
    }),
  ),
});

function quote(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

const [database, catalogUrl, installationId, repositoryId] = inputSchema.parse(
  process.argv.slice(2),
);
const response = await fetch(catalogUrl, { signal: AbortSignal.timeout(10_000) });
if (!response.ok) throw new Error(`catalog unavailable (${response.status})`);
const catalog = catalogSchema.parse(await response.json());
const images = catalog.images.filter(
  (image, index, all) => all.findIndex((candidate) => candidate.digest === image.digest) === index,
);
for (let offset = 0; offset < images.length; offset += 20) {
  const sql = images
    .slice(offset, offset + 20)
    .map(({ digest, registry }) => {
      const values = [digest, installationId, repositoryId, `${registry}@${digest}`, "pending"].map(
        quote,
      );
      return `INSERT OR IGNORE INTO github_ingestion_jobs (subject_digest,installation_id,repository_id,logical_image_ref,status,created_at) VALUES (${values.join(",")},unixepoch()*1000)`;
    })
    .join(";");
  const result = Bun.spawn(
    ["bun", "run", "wrangler", "d1", "execute", database, "--remote", "--command", sql],
    { stdin: "inherit", stdout: "inherit", stderr: "inherit" },
  );
  if ((await result.exited) !== 0) process.exit(1);
}
console.log(`Queued ${images.length} immutable image digests for reconciliation.`);
