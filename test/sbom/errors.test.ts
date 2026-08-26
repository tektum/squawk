import { describe, expect, it } from "vitest";
import { z } from "zod";
import { describeError, safeIssues } from "../../src/error-detail";
import { PredicateError, parsePredicate } from "../../src/sbom";

const secret = "internal-private-package-name";

describe("predicate failure reporting", () => {
  it("keeps external purl content out of predicate errors", () => {
    const thrown = (() => {
      try {
        parsePredicate({
          bomFormat: "CycloneDX",
          components: [{ name: "p", version: "1", purl: `pkg:npm/${secret}%@1` }],
        });
        return null;
      } catch (error) {
        return error;
      }
    })();

    expect(thrown).toBeInstanceOf(PredicateError);
    expect((thrown as PredicateError).message).toBe(
      "invalid SBOM predicate: purl has invalid percent encoding",
    );
    expect((thrown as PredicateError).message).not.toContain(secret);
    expect(describeError(thrown)).not.toContain(secret);
  });

  it("keeps external purl content out of unparsable purl errors", () => {
    expect(() =>
      parsePredicate({
        spdxVersion: "SPDX-2.3",
        packages: [
          {
            name: "p",
            versionInfo: "1",
            externalRefs: [{ referenceType: "purl", referenceLocator: `pkg:${secret}` }],
          },
        ],
      }),
    ).toThrow(/^invalid SBOM predicate: (unparsable purl|purl missing package type or name)$/);
  });
});

describe("error redaction", () => {
  it("drops validation input from described errors", () => {
    const error = Object.assign(new Error("boom"), {
      name: "ZodError",
      issues: [
        { code: "custom", path: ["packages", 0, "purl"], message: "bad purl", input: secret },
      ],
    });

    const described = describeError(error);

    expect(described).not.toContain(secret);
    expect(described).toContain("custom");
    expect(described).toContain("packages.0.purl");
  });

  it("keeps structural detail from real Zod issues", () => {
    const parsed = z.object({ packages: z.array(z.string()).min(1) }).safeParse({ packages: [] });

    const described = describeError(parsed.error);

    expect(described).toContain("ZodError");
    expect(described).toContain("too_small");
    expect(described).toContain("packages");
  });

  it("describes non-Error throws without echoing their content", () => {
    expect(describeError({ leaked: secret })).toBe("unknown error (object)");
    expect(describeError(secret)).toBe("unknown error (string)");
  });

  it("ignores non-object issues", () => {
    expect(safeIssues([null, "text", 7])).toEqual([{}, {}, {}]);
  });
});
