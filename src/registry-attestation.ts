import { z } from "zod";
import type { SubrequestBudget } from "./budget";
import { statementSchema, WebhookError } from "./webhook-contract";

const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json";
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const descriptorSchema = z.object({
  artifactType: z.string().optional(),
  digest: digestSchema,
  mediaType: z.string().min(1),
});
const indexSchema = z.object({ manifests: z.array(descriptorSchema).max(500) });
const artifactManifestSchema = z.object({
  artifactType: z.literal(bundleMediaType),
  layers: z
    .array(z.object({ digest: digestSchema, mediaType: z.literal(bundleMediaType) }))
    .min(1)
    .max(4),
});
const bundleSchema = z.object({
  mediaType: z.literal(bundleMediaType),
  dsseEnvelope: z.object({
    payload: z.string().min(1),
    payloadType: z.literal("application/vnd.in-toto+json"),
    signatures: z.array(z.object({ sig: z.string().min(1) })).min(1),
  }),
});
const tokenSchema = z.object({ token: z.string().min(1) });

async function registryJson(url: URL, token: string, accept: string, budget?: SubrequestBudget) {
  budget?.take();
  const response = await fetch(url, {
    headers: { accept, authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new WebhookError(502, `registry failed (${response.status})`);
  return response.json();
}

export async function statementsForImage(
  image: string,
  digest: string,
  budget?: SubrequestBudget,
  startDescriptor = 0,
): Promise<{
  readonly complete: boolean;
  readonly nextDescriptor: number;
  readonly statements: readonly z.infer<typeof statementSchema>[];
}> {
  const imagePath = image.slice("ghcr.io/".length);
  const tokenUrl = new URL("https://ghcr.io/token");
  tokenUrl.searchParams.set("scope", `repository:${imagePath}:pull`);
  tokenUrl.searchParams.set("service", "ghcr.io");
  budget?.take();
  const tokenResponse = await fetch(tokenUrl, { signal: AbortSignal.timeout(10_000) });
  if (!tokenResponse.ok) throw new WebhookError(502, "registry token unavailable");
  const { token } = tokenSchema.parse(await tokenResponse.json());
  const base = `https://ghcr.io/v2/${imagePath}`;
  const rawIndex = await registryJson(
    new URL(`${base}/manifests/sha256-${digest.slice("sha256:".length)}`),
    token,
    "application/vnd.oci.image.index.v1+json",
    budget,
  );
  if (!rawIndex) return { complete: false, nextDescriptor: startDescriptor, statements: [] };
  const descriptors = indexSchema
    .parse(rawIndex)
    .manifests.filter(
      (descriptor) =>
        descriptor.artifactType === bundleMediaType ||
        descriptor.artifactType === "application/vnd.oci.empty.v1+json",
    );
  const requestLimit = budget ? Math.max(0, budget.remaining - 2) : Number.MAX_SAFE_INTEGER;
  let requests = 0;
  let nextDescriptor = startDescriptor;
  const statements: z.infer<typeof statementSchema>[] = [];
  let sawStatement = false;
  while (nextDescriptor < descriptors.length && requests < requestLimit) {
    const descriptor = descriptors[nextDescriptor];
    if (!descriptor) break;
    if (requests + 1 > requestLimit) break;
    const rawManifest = await registryJson(
      new URL(`${base}/manifests/${descriptor.digest}`),
      token,
      "application/vnd.oci.image.manifest.v1+json",
      budget,
    );
    requests += 1;
    const manifest = artifactManifestSchema.safeParse(rawManifest);
    if (!manifest.success) {
      nextDescriptor += 1;
      continue;
    }
    if (requests + manifest.data.layers.length > requestLimit) break;
    for (const layer of manifest.data.layers) {
      const rawBundle = await registryJson(
        new URL(`${base}/blobs/${layer.digest}`),
        token,
        bundleMediaType,
        budget,
      );
      requests += 1;
      const bundle = bundleSchema.safeParse(rawBundle);
      if (!bundle.success) continue;
      const bytes = Uint8Array.from(atob(bundle.data.dsseEnvelope.payload), (character) =>
        character.charCodeAt(0),
      );
      const decoded = JSON.parse(new TextDecoder().decode(bytes));
      const statement = statementSchema.safeParse(decoded);
      if (decoded?.predicateType === "https://spdx.dev/Document") sawStatement = true;
      if (
        statement.success &&
        statement.data.subject.some(
          (subject) =>
            subject.name.toLowerCase() === image && subject.digest.sha256 === digest.slice(7),
        )
      )
        statements.push(statement.data);
    }
    nextDescriptor += 1;
  }
  if (sawStatement && statements.length === 0)
    throw new WebhookError(400, "matching statement not found");
  return {
    complete: nextDescriptor >= descriptors.length,
    nextDescriptor,
    statements,
  };
}
