import { HttpResponse, http } from "msw";
import { describe, expect, it } from "vitest";
import { sha256 } from "../../src/digest";
import { statementsForImage } from "../../src/registry-attestation";
import { respond } from "../http";
import { server } from "../server";

const digest = `sha256:${"a".repeat(64)}`;
const ociIndexMediaType = "application/vnd.oci.image.index.v1+json";
const dockerIndexMediaType = "application/vnd.docker.distribution.manifest.list.v2+json";
const ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
const dockerManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json";
const amd64Digest = `sha256:${"b".repeat(64)}`;
const arm64Digest = `sha256:${"c".repeat(64)}`;

async function loadSubjectIndex(index: unknown) {
  const bytes = JSON.stringify(index);
  const indexDigest = `sha256:${await sha256(bytes)}`;
  let accept: string | null = null;
  respond({
    url: "https://registry.test/token?scope=repository%3Aowner%2Fdemo%3Apull&service=ghcr.io",
    status: 200,
    body: { token: "registry-token" },
  });
  server.use(
    http.get(`https://registry.test/v2/owner/demo/manifests/${indexDigest}`, ({ request }) => {
      accept = request.headers.get("accept");
      return new HttpResponse(bytes, { status: 200 });
    }),
  );
  respond({
    url: `https://registry.test/v2/owner/demo/manifests/sha256-${indexDigest.slice(7)}`,
    status: 404,
  });

  const result = await statementsForImage(
    "ghcr.io/owner/demo",
    indexDigest,
    undefined,
    0,
    "https://registry.test",
  );
  return { accept, result };
}

describe("registry subject identity", () => {
  it("rejects mismatched final index bytes on a custom registry endpoint", async () => {
    respond({
      url: "https://registry.test/token?scope=repository%3Aowner%2Fdemo%3Apull&service=ghcr.io",
      status: 200,
      body: { token: "registry-token" },
    });
    respond({
      url: `https://registry.test/v2/owner/demo/manifests/${digest}`,
      status: 200,
      body: {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        manifests: [],
      },
    });

    await expect(
      statementsForImage("ghcr.io/owner/demo", digest, undefined, 0, "https://registry.test"),
    ).rejects.toThrow("subject index digest mismatch");
  });

  it("accepts the published Docker manifest-list and image-manifest shape", async () => {
    const { accept, result } = await loadSubjectIndex({
      schemaVersion: 2,
      mediaType: dockerIndexMediaType,
      manifests: [
        {
          mediaType: dockerManifestMediaType,
          size: 527,
          digest: "sha256:22f54f6971c30fd956826523e8e2864f33e943259e3313cbdf3d1a95d310832e",
          platform: { architecture: "amd64", os: "linux" },
        },
        {
          mediaType: dockerManifestMediaType,
          size: 527,
          digest: "sha256:4f4319d66df354366147c6560d06448b8594022d7bdd3b80489c5e83245a7315",
          platform: { architecture: "arm64", os: "linux" },
        },
      ],
    });

    expect(accept).toBe(`${ociIndexMediaType}, ${dockerIndexMediaType}`);
    expect([...result.platforms]).toEqual([
      ["linux/amd64", "sha256:22f54f6971c30fd956826523e8e2864f33e943259e3313cbdf3d1a95d310832e"],
      ["linux/arm64", "sha256:4f4319d66df354366147c6560d06448b8594022d7bdd3b80489c5e83245a7315"],
    ]);
  });

  it("accepts mixed standard image-manifest leaf forms", async () => {
    const { result } = await loadSubjectIndex({
      schemaVersion: 2,
      mediaType: ociIndexMediaType,
      manifests: [
        {
          digest: amd64Digest,
          mediaType: ociManifestMediaType,
          platform: { os: "linux", architecture: "amd64" },
        },
        {
          digest: arm64Digest,
          mediaType: dockerManifestMediaType,
          platform: { os: "linux", architecture: "arm64" },
        },
      ],
    });

    expect([...result.platforms]).toEqual([
      ["linux/amd64", amd64Digest],
      ["linux/arm64", arm64Digest],
    ]);
  });

  it("keeps a missing supported platform absent", async () => {
    const { result } = await loadSubjectIndex({
      schemaVersion: 2,
      mediaType: dockerIndexMediaType,
      manifests: [
        {
          digest: amd64Digest,
          mediaType: dockerManifestMediaType,
          platform: { os: "linux", architecture: "amd64" },
        },
        {
          digest: arm64Digest,
          mediaType: dockerManifestMediaType,
          platform: { os: "linux", architecture: "s390x" },
        },
      ],
    });

    expect([...result.platforms]).toEqual([["linux/amd64", amd64Digest]]);
    expect(result.platforms.has("linux/arm64")).toBe(false);
  });

  it("rejects duplicate normalized platform descriptors", async () => {
    await expect(
      loadSubjectIndex({
        schemaVersion: 2,
        mediaType: dockerIndexMediaType,
        manifests: [
          {
            digest: amd64Digest,
            mediaType: dockerManifestMediaType,
            platform: { os: "linux", architecture: "amd64" },
          },
          {
            digest: arm64Digest,
            mediaType: ociManifestMediaType,
            platform: { os: "linux", architecture: "x86_64" },
          },
        ],
      }),
    ).rejects.toThrow("conflicting platform descriptors");
  });

  it.each([
    ["OCI artifact manifest", "application/vnd.oci.artifact.manifest.v1+json"],
    ["Sigstore bundle", "application/vnd.dev.sigstore.bundle.v0.3+json"],
    ["nested OCI index", ociIndexMediaType],
    ["nested Docker manifest list", dockerIndexMediaType],
    ["unknown media type", "application/vnd.example.unknown+json"],
  ] as const)("rejects a platform descriptor using %s", async (_name, mediaType) => {
    await expect(
      loadSubjectIndex({
        schemaVersion: 2,
        mediaType: dockerIndexMediaType,
        manifests: [
          {
            digest: amd64Digest,
            mediaType,
            platform: { os: "linux", architecture: "amd64" },
          },
        ],
      }),
    ).rejects.toThrow();
  });

  it("rejects an unknown subject index media type", async () => {
    await expect(
      loadSubjectIndex({
        schemaVersion: 2,
        mediaType: "application/vnd.example.index+json",
        manifests: [],
      }),
    ).rejects.toThrow();
  });
});
