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
  | "duplicate package identity"
  | "conflicting image identity";

export class PredicateError extends Error {
  constructor(reason: PredicateFailure) {
    super(`invalid SBOM predicate: ${reason}`);
    this.name = "PredicateError";
  }
}

const maxComponents = 200;
const purlSchema = z.string().startsWith("pkg:");
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
  const described = new Set(spdx.documentDescribes ?? []);
  const describedContainers = spdx.packages.filter(
    (candidate) =>
      candidate.primaryPackagePurpose === "CONTAINER" &&
      (described.size === 0 || (candidate.SPDXID !== undefined && described.has(candidate.SPDXID))),
  );
  if (describedContainers.length !== 1) return null;
  const architectures = new Set<"amd64" | "arm64">();
  const containerPurl = describedContainers[0]?.externalRefs.find(
    (candidate) => candidate.referenceType === "purl",
  )?.referenceLocator;
  if (
    containerPurl &&
    purlFields(containerPurl).qualifiers.get("mediatype")?.includes("image.index")
  )
    return null;
  for (const pkg of spdx.packages) {
    if (pkg.primaryPackagePurpose === "CONTAINER") continue;
    const rawPurl = pkg.externalRefs.find(
      (candidate) => candidate.referenceType === "purl",
    )?.referenceLocator;
    if (!rawPurl) continue;
    const architecture = purlFields(rawPurl).qualifiers.get("arch");
    if (architecture === "amd64" || architecture === "x86_64") architectures.add("amd64");
    if (architecture === "arm64" || architecture === "aarch64") architectures.add("arm64");
  }
  if (architectures.size > 1) throw new PredicateError("conflicting image identity");
  const architecture = architectures.values().next().value;
  return architecture ? { platform: platformSchema.parse(`linux/${architecture}`) } : null;
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
const alpineRelease = /(?:^|-)(\d+\.\d+)(?:\.|$)/;
const debianReleases: Readonly<Record<string, string>> = {
  buster: "10",
  bullseye: "11",
  bookworm: "12",
  trixie: "13",
  forky: "14",
};
const ubuntuReleases: Readonly<Record<string, string>> = {
  xenial: "16.04",
  bionic: "18.04",
  focal: "20.04",
  jammy: "22.04",
  noble: "24.04",
  questing: "25.10",
  resolute: "26.04",
};
const ubuntuEcosystems: Readonly<Record<string, true>> = {
  "16.04": true,
  "18.04": true,
  "20.04": true,
  "22.04": true,
  "24.04": true,
  "25.10": true,
  "26.04": true,
};
function releaseFromDistro(
  distribution: "debian" | "ubuntu",
  distro: string | undefined,
): string | undefined {
  const normalized = distro?.toLowerCase();
  if (!normalized) return undefined;
  const parts = normalized.split(/[/:]/).at(-1)?.split("-") ?? [];
  if (parts[0] === distribution) parts.shift();
  if (parts.length !== 1) return undefined;
  const value = parts[0];
  if (!value) return undefined;
  if (distribution === "debian")
    return debianReleases[value] ?? /^(?:10|11|12|13|14)$/.exec(value)?.[0];
  const release =
    ubuntuReleases[value] ??
    /^(?:16\.04|18\.04|20\.04|22\.04|24\.04|25\.10|26\.04)$/.exec(value)?.[0];
  return release && ubuntuEcosystems[release] ? release : undefined;
}

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
    return release
      ? { ecosystem: `Alpine:v${release}`, matchable: true }
      : { ecosystem: "unknown:apk", matchable: false };
  }
  if (purlType === "deb") {
    if (distribution !== "debian" && distribution !== "ubuntu")
      return { ecosystem: "unknown:deb", matchable: false };
    const release = releaseFromDistro(distribution, distro);
    if (!release) return { ecosystem: `unsupported:deb:${distribution}`, matchable: false };
    return {
      ecosystem:
        distribution === "debian"
          ? `Debian:${release}`
          : `Ubuntu:${release}${release.endsWith(".04") ? ":LTS" : ""}`,
      matchable: true,
    };
  }
  return { ecosystem: `unknown:${purlType}`, matchable: false };
}

/**
 * Parses a package URL into package identity and ecosystem metadata.
 *
 * @param purl - The package URL to parse
 * @returns The decoded package name, ecosystem, matchability, and optional version
 * @throws `PredicateError` if the package URL is malformed or contains invalid percent encoding
 */
type PurlFields = {
  readonly type: string;
  readonly namespace: string | undefined;
  readonly name: string;
  readonly version: string | undefined;
  readonly qualifiers: ReadonlyMap<string, string>;
};

function decoded(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new PredicateError("purl has invalid percent encoding");
  }
}

function purlFields(purl: string): PurlFields {
  if (!purl.startsWith("pkg:")) throw new PredicateError("unparsable purl");
  const withoutFragment = purl.split("#", 1)[0] ?? "";
  const [coordinates = "", rawQuery] = withoutFragment.split("?", 2);
  const slash = coordinates.indexOf("/", 4);
  if (slash < 5) throw new PredicateError("unparsable purl");
  const type = decoded(coordinates.slice(4, slash)).toLowerCase();
  const pathWithVersion = coordinates.slice(slash + 1);
  const separator = pathWithVersion.lastIndexOf("@");
  if (separator === 0) throw new PredicateError("purl missing package type or name");
  const packagePath = separator < 0 ? pathWithVersion : pathWithVersion.slice(0, separator);
  const segments = packagePath.split("/").map(decoded);
  const name = segments.pop();
  if (!type || !name) throw new PredicateError("purl missing package type or name");
  const qualifiers = new Map<string, string>();
  for (const pair of rawQuery?.split("&") ?? []) {
    if (!pair) continue;
    const equals = pair.indexOf("=");
    if (equals <= 0) throw new PredicateError("unparsable purl");
    const key = decoded(pair.slice(0, equals)).toLowerCase();
    if (qualifiers.has(key)) throw new PredicateError("unparsable purl");
    qualifiers.set(key, decoded(pair.slice(equals + 1)).toLowerCase());
  }
  return {
    type,
    namespace: segments.length > 0 ? segments.join("/") : undefined,
    name,
    version: separator < 0 ? undefined : decoded(pathWithVersion.slice(separator + 1)),
    qualifiers,
  };
}

export function parsePurl(purl: string): {
  readonly packageName: string;
  readonly ecosystem: string;
  readonly matchable: boolean;
  readonly version: string | undefined;
} {
  const parsed = purlFields(purl);
  return {
    packageName: parsed.name,
    version: parsed.version,
    ...ecosystemFor(parsed.type, parsed.namespace, parsed.qualifiers.get("distro")),
  };
}

/**
 * Creates a component from a package URL and fallback version.
 *
 * @param purl - The package URL identifying the component
 * @param version - The version to use when the package URL does not specify one
 * @returns The component represented by the package URL and resolved version
 */
function componentFrom(purl: string, version: string): Component {
  const { version: purlVersion, ...parsed } = parsePurl(purl);
  return { ...parsed, version: purlVersion ?? version, purl };
}

/**
 * Parses a CycloneDX or SPDX predicate into package components.
 *
 * @param predicate - The predicate containing CycloneDX components or SPDX packages.
 * @returns The parsed package components.
 * @throws PredicateError If the predicate contains no package components or duplicate package identities.
 */
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
