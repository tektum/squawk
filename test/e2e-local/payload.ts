import type { FixtureImage } from "./origin";

export type PublishedSource = {
  readonly installationId: string;
  readonly repositoryId: string;
};

/**
 * Builds the `registry_package.published` body GitHub sends when a multi-platform image
 * index is pushed to GHCR. The shape is what `webhookSchema` in src/webhook-contract.ts
 * accepts, so a drift in either direction fails the local run rather than a mock.
 */
export function publishedPayload(image: FixtureImage, source: PublishedSource): unknown {
  const [namespace, name] = image.image.slice("ghcr.io/".length).split("/");
  if (!namespace || !name) throw new Error(`unexpected image reference ${image.image}`);
  // GitHub gives every package version its own id, and Squawk rejects a second delivery
  // that reuses one for different content as a delivery collision. Deriving both ids
  // from the immutable digest keeps them distinct per image and stable across runs.
  const identity = Number.parseInt(image.indexDigest.slice("sha256:".length, 19), 16);
  return {
    action: "published",
    installation: { id: Number(source.installationId) },
    registry_package: {
      id: identity,
      name,
      namespace,
      package_type: "container",
      package_version: {
        id: identity + 1,
        container_metadata: {
          tag: { name: "latest", digest: image.indexDigest },
          manifest: {
            digest: image.indexDigest,
            media_type: "application/vnd.oci.image.index.v1+json",
            uri: `repositories/${namespace}/${name}/manifests/${image.indexDigest}`,
          },
        },
      },
    },
    repository: {
      id: Number(source.repositoryId),
      full_name: `${namespace}/verity-images`,
    },
    sender: { id: 1, login: namespace },
  };
}
