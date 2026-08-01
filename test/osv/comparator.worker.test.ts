import { describe, expect, it, vi } from "vitest";
import { compareVersion } from "../../src/osv/comparator";

describe("OSV SCALIBR Wasm comparator", () => {
  it("fails closed when the Wasm module is malformed", async () => {
    const instantiate = vi
      .spyOn(WebAssembly, "instantiate")
      .mockRejectedValueOnce(new WebAssembly.CompileError("malformed wasm"));

    await expect(
      compareVersion({ ecosystem: "npm", version: "1.5.0", ranges: [], versions: [] }),
    ).resolves.toMatchObject({ kind: "error", reason: "malformed wasm" });

    instantiate.mockRestore();
  });

  it("matches a Debian epoch inside its affected interval", async () => {
    await expect(
      compareVersion({
        ecosystem: "Debian",
        version: "1:2.0-1",
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1:1.0-1" }, { fixed: "1:3.0-1" }] }],
        versions: [],
      }),
    ).resolves.toEqual({ kind: "match" });
  });

  it("does not match a fixed Alpine revision", async () => {
    await expect(
      compareVersion({
        ecosystem: "Alpine",
        version: "1.2.3-r3",
        ranges: [
          { type: "ECOSYSTEM", events: [{ introduced: "1.2.3-r0" }, { fixed: "1.2.3-r2" }] },
        ],
        versions: [],
      }),
    ).resolves.toEqual({ kind: "no_match" });
  });

  it.each([
    ["Maven", "1.5.0", "1.0.0", "2.0.0"],
    ["PyPI", "1.5.0", "1.0.0", "2.0.0"],
    ["RubyGems", "1.5.0", "1.0.0", "2.0.0"],
    ["NuGet", "1.5.0", "1.0.0", "2.0.0"],
  ])(
    "matches %s ranges and respects event boundaries in workerd",
    async (ecosystem, version, introduced, fixed) => {
      await expect(
        compareVersion({
          ecosystem,
          version,
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced }, { fixed }] }],
          versions: [],
        }),
      ).resolves.toEqual({ kind: "match" });
      await expect(
        compareVersion({
          ecosystem,
          version: fixed,
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced }, { fixed }] }],
          versions: [],
        }),
      ).resolves.toEqual({ kind: "no_match" });
    },
  );

  it("returns explicit errors without false matches", async () => {
    await expect(
      compareVersion({ ecosystem: "Unknown", version: "1", ranges: [], versions: [] }),
    ).resolves.toMatchObject({ kind: "unsupported" });
    await expect(
      compareVersion({
        ecosystem: "npm",
        version: "1.0.0",
        ranges: [{ type: "GIT", events: [] }],
        versions: [],
      }),
    ).resolves.toMatchObject({ kind: "unsupported" });
  });
});
