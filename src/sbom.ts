import { z } from "zod";
import type { Component } from "./domain";

/**
 * Reasons are fixed codes: predicate content is attacker-controlled and these
 * messages get logged and persisted, so no external value may appear in them.
 * Failing images stay identifiable by their immutable subject digest.
 */
type PredicateFailure =
  | "unparsable purl"
  | "purl missing package type or name"
  | "purl has invalid percent encoding"
  | "no package components found"
  | "duplicate package identity";

export class PredicateError extends Error {
  constructor(reason: PredicateFailure) {
    super(`invalid SBOM predicate: ${reason}`);
    this.name = "PredicateError";
  }
}

const maxComponents = 200;
const purlSchema = z.string().startsWith("pkg:");
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const platformSchema = z.enum(["linux/amd64", "linux/arm64"]);
export const cyclonedxPredicateSchema = z.object({
  bomFormat: z.literal("CycloneDX"),
  components: z
    .array(z.object({ name: z.string().min(1), version: z.string().min(1), purl: purlSchema }))
    .min(1)
    .max(maxComponents),
});
const spdxPackageSchema = z.object({
  SPDXID: z.string().min(1).optional(),
  name: z.string().min(1),
  primaryPackagePurpose: z.string().optional(),
  versionInfo: z.string().min(1),
  externalRefs: z
    .array(z.object({ referenceType: z.string().min(1), referenceLocator: z.string().min(1) }))
    .default([]),
});
const spdxSchema = z.object({
  spdxVersion: z.string().min(1),
  documentDescribes: z.array(z.string().min(1)).optional(),
  packages: z.array(spdxPackageSchema).min(1).max(maxComponents),
});

export const sbomInputSchema = z.object({
  image_ref: z.string().regex(/@sha256:[a-f0-9]{64}$/),
  logical_image_ref: z.string().regex(/@sha256:[a-f0-9]{64}$/),
  platform: z.string().regex(/^linux\/(amd64|arm64)$/),
  idempotency_key: z.string().min(32).max(128),
  predicate: z.unknown(),
});
export type SbomInput = z.infer<typeof sbomInputSchema>;

export function imageIdentityFromPredicate(predicate: unknown) {
  const spdx = spdxSchema.parse(predicate);
  const described = spdx.packages.find(
    (candidate) => candidate.SPDXID && spdx.documentDescribes?.includes(candidate.SPDXID),
  );
  const containers = spdx.packages.filter(
    (candidate) => candidate.primaryPackagePurpose === "CONTAINER",
  );
  const image = described ?? (containers.length === 1 ? containers[0] : undefined);
  const rawPurl = image?.externalRefs.find(
    (candidate) => candidate.referenceType === "purl",
  )?.referenceLocator;
  const purl = decodeURIComponent(rawPurl ?? "");
  const digest = /@sha256:([a-f0-9]{64})/.exec(purl)?.[1];
  const qualifiers = new URLSearchParams(purl.split("?")[1] ?? "");
  const arch = qualifiers.get("arch");
  if (!arch) return null;
  return {
    imageDigest: digestSchema.parse(`sha256:${digest}`),
    platform: platformSchema.parse(`${qualifiers.get("os") ?? "linux"}/${arch}`),
  };
}

const languageEcosystems: Readonly<Record<string, string>> = {
  golang: "Go",
  maven: "Maven",
  npm: "npm",
  nuget: "NuGet",
  pypi: "PyPI",
  gem: "RubyGems",
  cargo: "crates.io",
};
/** OSV tracks apk distributions separately: Wolfi and Chainguard are not Alpine. */
const apkEcosystems: Readonly<Record<string, string>> = {
  chainguard: "Chainguard",
  wolfi: "Wolfi",
};
const alpineRelease = /(?:^|-)(\d+\.\d+)/;
const debianRelease = /(?:^|-)(\d+)/;

function ecosystemFor(
  purlType: string,
  namespace: string | undefined,
  distro: string | undefined,
): { readonly ecosystem: string; readonly matchable: boolean } {
  const language = languageEcosystems[purlType];
  if (language) return { ecosystem: language, matchable: true };
  const distribution = namespace?.toLowerCase();
  if (purlType === "apk") {
    const rolling = distribution === undefined ? undefined : apkEcosystems[distribution];
    if (rolling) return { ecosystem: rolling, matchable: true };
    const release = distribution === "alpine" ? alpineRelease.exec(distro ?? "")?.[1] : undefined;
    // OSV publishes Alpine advisories per release and answers nothing for a bare
    // "Alpine" ecosystem, so an unresolved release must not look matchable.
    return release
      ? { ecosystem: `Alpine:v${release}`, matchable: true }
      : { ecosystem: "unknown:apk", matchable: false };
  }
  if (purlType === "deb") {
    const release = distribution === "debian" ? debianRelease.exec(distro ?? "")?.[1] : undefined;
    return { ecosystem: release ? `Debian:${release}` : "Debian", matchable: true };
  }
  return { ecosystem: `unknown:${purlType}`, matchable: false };
}

export function parsePurl(purl: string): {
  readonly packageName: string;
  readonly ecosystem: string;
  readonly matchable: boolean;
  readonly version: string | undefined;
} {
  const match = /^pkg:([^/?#]+)\/([^?#]+)/.exec(purl);
  if (!match) throw new PredicateError("unparsable purl");
  const [, purlType, pathWithVersion] = match;
  if (!purlType || !pathWithVersion) throw new PredicateError("unparsable purl");
  // A purl version is optional; without one the document's own version is used.
  const separator = pathWithVersion.lastIndexOf("@");
  if (separator === 0) throw new PredicateError("purl missing package type or name");
  const packagePath = separator < 0 ? pathWithVersion : pathWithVersion.slice(0, separator);
  const segments = packagePath.split("/");
  const rawPackageName = segments.at(-1);
  if (!rawPackageName) throw new PredicateError("purl missing package type or name");
  let packageName: string;
  let purlVersion: string;
  try {
    packageName = decodeURIComponent(rawPackageName);
    purlVersion = separator < 0 ? "" : decodeURIComponent(pathWithVersion.slice(separator + 1));
  } catch {
    throw new PredicateError("purl has invalid percent encoding");
  }
  const qualifiers = new URLSearchParams(purl.split("#")[0]?.split("?")[1] ?? "");
  return {
    packageName,
    // The purl carries the canonical version OSV ranges against; SPDX versionInfo
    // may be decorated (Go reports "go1.26.5"), which OSV cannot range-check.
    version: purlVersion === "" ? undefined : purlVersion,
    ...ecosystemFor(purlType, segments.at(-2), qualifiers.get("distro") ?? undefined),
  };
}

function componentFrom(purl: string, version: string): Component {
  const { version: purlVersion, ...parsed } = parsePurl(purl);
  return { ...parsed, version: purlVersion ?? version, purl };
}

export function parsePredicate(predicate: unknown): readonly Component[] {
  const cyclonedx = cyclonedxPredicateSchema.safeParse(predicate);
  const components = cyclonedx.success
    ? cyclonedx.data.components.map((component) => componentFrom(component.purl, component.version))
    : spdxSchema.parse(predicate).packages.flatMap((pkg) => {
        const reference = pkg.externalRefs.find((candidate) => candidate.referenceType === "purl");
        return reference
          ? [componentFrom(purlSchema.parse(reference.referenceLocator), pkg.versionInfo)]
          : [];
      });
  if (components.length === 0) throw new PredicateError("no package components found");
  const identities = new Set(
    components.map((component) => `${component.purl}\u0000${component.version}`),
  );
  if (identities.size !== components.length) throw new PredicateError("duplicate package identity");
  return components;
}
