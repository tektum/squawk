import { describe, expect, it } from "vitest";
import { statementsForImage } from "../../src/registry-attestation";
import { respond } from "../http";

const digest = `sha256:${"a".repeat(64)}`;

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
});
