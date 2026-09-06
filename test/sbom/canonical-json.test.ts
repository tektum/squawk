import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../src/canonical-json";
import { sha256 } from "../../src/digest";

describe("canonical checkpoint JSON", () => {
  it("sorts object keys recursively without reordering arrays", async () => {
    const canonical = canonicalJson({
      revision: 1,
      source: { repository_id: "9", installation_id: "1" },
      kind: "inventory_snapshot",
      findings: [],
      checkpoint_id: "a",
    });

    expect(canonical).toBe(
      '{"checkpoint_id":"a","findings":[],"kind":"inventory_snapshot","revision":1,"source":{"installation_id":"1","repository_id":"9"}}',
    );
    await expect(sha256(canonical)).resolves.toBe(
      "ae7a64643c3dbd8b8058b953df74787815593df62ded43f682a9280527e61c47",
    );
  });
});
