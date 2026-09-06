import { describe, expect, it } from "vitest";
import { imageIdentityFromPredicate, parsePredicate } from "../../src/sbom";

describe("SBOM predicate parser", () => {
  it("derives platform from attested runtime package architecture", () => {
    expect(
      imageIdentityFromPredicate({
        spdxVersion: "SPDX-2.3",
        packages: [
          {
            name: "libc6",
            versionInfo: "2.39-0ubuntu8",
            externalRefs: [
              {
                referenceType: "purl",
                referenceLocator:
                  "pkg:deb/ubuntu/libc6@2.39-0ubuntu8?arch=amd64&distro=ubuntu-24.04",
              },
            ],
          },
          {
            SPDXID: "SPDXRef-DocumentRoot-Image",
            name: "local/verity-busybox",
            versionInfo: "latest-amd64",
            primaryPackagePurpose: "CONTAINER",
            externalRefs: [
              {
                referenceType: "purl",
                referenceLocator: `pkg:oci/local%2Fverity-busybox@sha256%3A${"a".repeat(64)}?arch=amd64`,
              },
            ],
          },
        ],
      }),
    ).toEqual({ platform: "linux/amd64" });
  });

  it("does not derive a platform identity from an index SPDX document", () => {
    expect(
      imageIdentityFromPredicate({
        spdxVersion: "SPDX-2.3",
        documentDescribes: ["SPDXRef-Index"],
        packages: [
          {
            SPDXID: "SPDXRef-Index",
            name: "index",
            versionInfo: "latest",
            primaryPackagePurpose: "CONTAINER",
            externalRefs: [
              {
                referenceType: "purl",
                referenceLocator: `pkg:oci/example@sha256:${"a".repeat(64)}?mediaType=application%2Fvnd.oci.image.index.v1%2Bjson`,
              },
            ],
          },
        ],
      }),
    ).toBeNull();
  });

  it("retains each CycloneDX component with its own ecosystem", () => {
    const components = parsePredicate({
      bomFormat: "CycloneDX",
      components: [
        {
          name: "openssl",
          version: "3.0.0",
          purl: "pkg:deb/debian/openssl@3.0.0?distro=debian-12",
        },
        { name: "hono", version: "4.0.0", purl: "pkg:npm/hono@4.0.0" },
        { name: "zod", version: "4.0.0", purl: "pkg:pypi/zod@4.0.0" },
        { name: "demo", version: "1.0.0", purl: "pkg:maven/org.example/demo@1.0.0" },
        { name: "demo", version: "1.0.0", purl: "pkg:gem/demo@1.0.0" },
        { name: "Demo", version: "1.0.0", purl: "pkg:nuget/Demo@1.0.0" },
      ],
    });

    expect(components.map((component) => component.ecosystem)).toEqual([
      "Debian:12",
      "npm",
      "PyPI",
      "Maven",
      "RubyGems",
      "NuGet",
    ]);
  });

  it("keeps an unknown PURL non-matchable", () => {
    const [component] = parsePredicate({
      bomFormat: "CycloneDX",
      components: [{ name: "example", version: "1.0.0", purl: "pkg:unknown/example@1.0.0" }],
    });

    expect(component).toMatchObject({ ecosystem: "unknown:unknown", matchable: false });
  });

  it("maps apk distributions to their own OSV ecosystems", () => {
    const components = parsePredicate({
      bomFormat: "CycloneDX",
      components: [
        {
          name: "ca-certificates-bundle",
          version: "20260413-r0",
          purl: "pkg:apk/wolfi/ca-certificates-bundle@20260413-r0?arch=x86_64&distro=wolfi",
        },
        {
          name: "glibc",
          version: "2.41-r0",
          purl: "pkg:apk/chainguard/glibc@2.41-r0?arch=x86_64&distro=chainguard",
        },
        {
          name: "busybox",
          version: "1.37.0-r61",
          purl: "pkg:apk/alpine/busybox@1.37.0-r61?arch=x86_64&distro=alpine-3.21.3",
        },
      ],
    });

    expect(components.map((component) => component.ecosystem)).toEqual([
      "Wolfi",
      "Chainguard",
      "Alpine:v3.21",
    ]);
    expect(components.every((component) => component.matchable)).toBe(true);
  });

  it("keeps an Alpine package without a release non-matchable", () => {
    const [component] = parsePredicate({
      bomFormat: "CycloneDX",
      components: [
        { name: "busybox", version: "1.37.0-r61", purl: "pkg:apk/alpine/busybox@1.37.0-r61" },
      ],
    });

    expect(component).toMatchObject({ ecosystem: "unknown:apk", matchable: false });
  });

  it("pins Debian packages to their release when the distro qualifier carries one", () => {
    const components = parsePredicate({
      bomFormat: "CycloneDX",
      components: [
        {
          name: "openssl",
          version: "3.0.11-1",
          purl: "pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12",
        },
        {
          name: "zlib1g",
          version: "1.2.13",
          purl: "pkg:deb/debian/zlib1g@1.2.13?distro=debian-trixie",
        },
      ],
    });

    expect(components.map((component) => component.ecosystem)).toEqual(["Debian:12", "Debian:13"]);
  });

  it("keeps Ubuntu and unknown deb distributions out of Debian", () => {
    const components = parsePredicate({
      bomFormat: "CycloneDX",
      components: [
        {
          name: "openssl",
          version: "3.0.13-0ubuntu3.15",
          purl: "pkg:deb/%75buntu/openssl@3.0.13-0ubuntu3.15?arch=amd64&distro=ubuntu%2D24.04",
        },
        {
          name: "libcap2",
          version: "1:2.66-5ubuntu2.4",
          purl: "pkg:deb/ubuntu/libcap2@1%3A2.66-5ubuntu2.4?distro=ubuntu-noble",
        },
        { name: "mystery", version: "1", purl: "pkg:deb/vendor/mystery@1?distro=debian-12" },
        { name: "unqualified", version: "1", purl: "pkg:deb/debian/unqualified@1" },
      ],
    });

    expect(components.map(({ ecosystem, matchable }) => ({ ecosystem, matchable }))).toEqual([
      { ecosystem: "Ubuntu:24.04:LTS", matchable: true },
      { ecosystem: "Ubuntu:24.04:LTS", matchable: true },
      { ecosystem: "unknown:deb", matchable: false },
      { ecosystem: "unsupported:deb:debian", matchable: false },
    ]);
  });

  it("ignores a stale container architecture in favor of package evidence", () => {
    expect(
      imageIdentityFromPredicate({
        spdxVersion: "SPDX-2.3",
        documentDescribes: ["SPDXRef-Container"],
        packages: [
          {
            SPDXID: "SPDXRef-Container",
            name: "image",
            versionInfo: "candidate",
            primaryPackagePurpose: "CONTAINER",
            externalRefs: [
              {
                referenceType: "purl",
                referenceLocator: `pkg:oci/image@sha256%3A${"a".repeat(64)}?arch=amd64`,
              },
            ],
          },
          {
            name: "openssl",
            versionInfo: "3.0.13-0ubuntu3.15",
            externalRefs: [
              {
                referenceType: "purl",
                referenceLocator:
                  "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.15?arch=arm64&distro=ubuntu-24.04",
              },
            ],
          },
        ],
      }),
    ).toEqual({ platform: "linux/arm64" });
  });

  it("prefers the canonical purl version over a decorated SPDX versionInfo", () => {
    const [component] = parsePredicate({
      spdxVersion: "SPDX-2.3",
      packages: [
        {
          name: "stdlib",
          versionInfo: "go1.26.5",
          externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:golang/stdlib@1.26.5" }],
        },
      ],
    });

    expect(component).toMatchObject({ ecosystem: "Go", version: "1.26.5", matchable: true });
  });

  it("accepts a PURL without a version and uses the document version", () => {
    const [component] = parsePredicate({
      bomFormat: "CycloneDX",
      components: [{ name: "example", version: "1.0.0", purl: "pkg:npm/example" }],
    });

    expect(component).toMatchObject({
      ecosystem: "npm",
      packageName: "example",
      version: "1.0.0",
      matchable: true,
    });
  });

  it("rejects invalid percent encoding outside the package name", () => {
    expect(() =>
      parsePredicate({
        bomFormat: "CycloneDX",
        components: [{ name: "example", version: "1.0.0", purl: "pkg:npm/%ZZ/example@1.0.0" }],
      }),
    ).toThrow("invalid SBOM predicate: purl has invalid percent encoding");
  });

  it("parses exactly 200 mixed CycloneDX components", () => {
    const ecosystems = ["deb", "npm", "pypi"] as const;
    const components = parsePredicate({
      bomFormat: "CycloneDX",
      components: Array.from({ length: 200 }, (_, index) => ({
        name: `package-${index}`,
        version: `1.0.${index}`,
        purl:
          ecosystems[index % ecosystems.length] === "deb"
            ? `pkg:deb/debian/package-${index}@1.0.${index}?distro=debian-12`
            : `pkg:${ecosystems[index % ecosystems.length]}/package-${index}@1.0.${index}`,
      })),
    });

    expect(components).toHaveLength(200);
    expect(new Set(components.map((component) => component.ecosystem))).toEqual(
      new Set(["Debian:12", "npm", "PyPI"]),
    );
  });

  it("parses SPDX packages and rejects over-limit or duplicate input", () => {
    const packages = Array.from({ length: 200 }, (_, index) => ({
      name: `package-${index}`,
      versionInfo: `1.0.${index}`,
      externalRefs: [
        { referenceType: "purl", referenceLocator: `pkg:npm/package-${index}@1.0.${index}` },
      ],
    }));

    expect(parsePredicate({ spdxVersion: "SPDX-2.3", packages })).toHaveLength(200);
    expect(() =>
      parsePredicate({ spdxVersion: "SPDX-2.3", packages: [...packages, packages[0]] }),
    ).toThrow();
    expect(() =>
      parsePredicate({
        bomFormat: "CycloneDX",
        components: [
          { name: "same", version: "1", purl: "pkg:npm/same@1" },
          { name: "same", version: "1", purl: "pkg:npm/same@1" },
        ],
      }),
    ).toThrow();
  });

  it("keeps the PURL when SPDX includes other external references", () => {
    const [component] = parsePredicate({
      spdxVersion: "SPDX-2.3",
      packages: [
        {
          name: "demo",
          versionInfo: "1.0.0",
          externalRefs: [
            {
              referenceType: "cpe23Type",
              referenceLocator: "cpe:2.3:a:example:demo:1.0.0:*:*:*:*:*:*:*",
            },
            { referenceType: "purl", referenceLocator: "pkg:npm/demo@1.0.0" },
          ],
        },
      ],
    });

    expect(component).toMatchObject({ packageName: "demo", ecosystem: "npm" });
  });

  it("skips SPDX packages without PURLs", () => {
    const components = parsePredicate({
      spdxVersion: "SPDX-2.3",
      packages: [
        { name: "unidentified", versionInfo: "1" },
        {
          name: "demo",
          versionInfo: "1.0.0",
          externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:npm/demo@1.0.0" }],
        },
      ],
    });

    expect(components).toEqual([
      {
        packageName: "demo",
        ecosystem: "npm",
        matchable: true,
        version: "1.0.0",
        purl: "pkg:npm/demo@1.0.0",
      },
    ]);
  });
});
