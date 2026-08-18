import { describe, expect, it } from "vitest";
import { statementSchema, webhookSchema } from "../../src/webhook-contract";

describe("GitHub webhook contract", () => {
  it("preserves a manifests path segment in a published package URI", () => {
    const parsed = webhookSchema.safeParse({
      action: "published",
      installation: { id: 1 },
      registry_package: {
        id: 1,
        name: "demo",
        namespace: "owner",
        package_type: "container",
        package_version: {
          id: 2,
          container_metadata: {
            tag: { name: "latest", digest: `sha256:${"b".repeat(64)}` },
            manifest: {
              digest: `sha256:${"b".repeat(64)}`,
              media_type: "application/vnd.oci.image.index.v1+json",
              uri: `repositories/owner/team/manifests/manifests/sha256:${"b".repeat(64)}`,
            },
          },
        },
      },
      repository: { id: 1, full_name: "owner/repo" },
      sender: { id: 1, login: "github-actions[bot]" },
    });

    expect(parsed.success).toBe(true);
    if (parsed.success)
      expect(parsed.data.registry_package.package_version.container_metadata.manifest.uri).toBe(
        "owner/team/manifests",
      );
  });

  it("rejects an SPDX predicate labeled as CycloneDX at the attestation boundary", () => {
    expect(
      statementSchema.safeParse({
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: "ghcr.io/owner/demo", digest: { sha256: "a".repeat(64) } }],
        predicateType: "https://cyclonedx.org/bom",
        predicate: { spdxVersion: "SPDX-2.3", packages: [] },
      }).success,
    ).toBe(false);
  });
});
