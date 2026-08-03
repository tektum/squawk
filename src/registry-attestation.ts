import { z } from "zod";
import { statementSchema, WebhookError } from "./webhook-contract";

const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const descriptorSchema = z.object({
  digest: digestSchema,
  mediaType: z.string().min(1),
});
const indexSchema = z.object({ manifests: z.array(descriptorSchema).max(20) });
const artifactManifestSchema = z.object({
  artifactType: z.literal("application/vnd.dev.sigstore.bundle.v0.3+json"),
  layers: z
    .array(
      z.object({
        digest: digestSchema,
        mediaType: z.literal("application/vnd.dev.sigstore.bundle.v0.3+json"),
      }),
    )
    .min(1)
    .max(4),
});
const bundleSchema = z.object({
  mediaType: z.literal("application/vnd.dev.sigstore.bundle.v0.3+json"),
  dsseEnvelope: z.object({
    payload: z.string().min(1),
    payloadType: z.literal("application/vnd.in-toto+json"),
    signatures: z.array(z.object({ sig: z.string().min(1) })).min(1),
  }),
});
const tokenSchema = z.object({ token: z.string().min(1) });

async function registryJson(url: URL, token: string, accept: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: { accept, authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new WebhookError(502, `registry failed (${response.status})`);
  return response.json();
}

export async function statementsForImage(image: string, digest: string) {
  const imagePath = image.slice("ghcr.io/".length);
  const tokenUrl = new URL("https://ghcr.io/token");
  tokenUrl.searchParams.set("scope", `repository:${imagePath}:pull`);
  tokenUrl.searchParams.set("service", "ghcr.io");
  const tokenResponse = await fetch(tokenUrl, { signal: AbortSignal.timeout(10_000) });
  if (!tokenResponse.ok) throw new WebhookError(502, "registry token unavailable");
  const { token } = tokenSchema.parse(await tokenResponse.json());
  const base = `https://ghcr.io/v2/${imagePath}`;
  const rawIndex = await registryJson(
    new URL(`${base}/manifests/sha256-${digest.slice("sha256:".length)}`),
    token,
    "application/vnd.oci.image.index.v1+json",
  );
  if (!rawIndex) return [];
  const statements: z.infer<typeof statementSchema>[] = [];
  let sawStatement = false;
  for (const descriptor of indexSchema.parse(rawIndex).manifests) {
    const rawManifest = await registryJson(
      new URL(`${base}/manifests/${descriptor.digest}`),
      token,
      "application/vnd.oci.image.manifest.v1+json",
    );
    const manifest = artifactManifestSchema.safeParse(rawManifest);
    if (!manifest.success) continue;
    for (const layer of manifest.data.layers) {
      const rawBundle = await registryJson(
        new URL(`${base}/blobs/${layer.digest}`),
        token,
        "application/vnd.dev.sigstore.bundle.v0.3+json",
      );
      const bundle = bundleSchema.safeParse(rawBundle);
      if (!bundle.success) continue;
      const bytes = Uint8Array.from(atob(bundle.data.dsseEnvelope.payload), (character) =>
        character.charCodeAt(0),
      );
      const statement = statementSchema.safeParse(JSON.parse(new TextDecoder().decode(bytes)));
      if (statement.success) sawStatement = true;
      if (
        statement.success &&
        statement.data.subject.some(
          (subject) =>
            subject.name.toLowerCase() === image && subject.digest.sha256 === digest.slice(7),
        )
      )
        statements.push(statement.data);
    }
  }
  if (sawStatement && statements.length === 0)
    throw new WebhookError(400, "matching statement not found");
  return statements;
}
