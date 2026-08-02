import { z } from "zod";
import type { Component } from "./domain";

const maxComponents = 200;
const purlSchema = z.string().startsWith("pkg:");
export const cyclonedxPredicateSchema = z.object({
  bomFormat: z.literal("CycloneDX"),
  components: z
    .array(z.object({ name: z.string().min(1), version: z.string().min(1), purl: purlSchema }))
    .min(1)
    .max(maxComponents),
});
const spdxSchema = z.object({
  spdxVersion: z.string().min(1),
  packages: z
    .array(
      z.object({
        name: z.string().min(1),
        versionInfo: z.string().min(1),
        externalRefs: z
          .array(
            z.object({ referenceType: z.string().min(1), referenceLocator: z.string().min(1) }),
          )
          .min(1),
      }),
    )
    .min(1)
    .max(maxComponents),
});

export const sbomInputSchema = z.object({
  image_ref: z.string().regex(/@sha256:[a-f0-9]{64}$/),
  logical_image_ref: z.string().regex(/@sha256:[a-f0-9]{64}$/),
  platform: z.string().regex(/^linux\/(amd64|arm64)$/),
  idempotency_key: z.string().min(32).max(128),
  predicate: z.unknown(),
});
export type SbomInput = z.infer<typeof sbomInputSchema>;

const purlEcosystems: Readonly<Record<string, string>> = {
  apk: "Alpine",
  deb: "Debian",
  golang: "Go",
  maven: "Maven",
  npm: "npm",
  nuget: "NuGet",
  pypi: "PyPI",
  gem: "RubyGems",
  cargo: "crates.io",
};

function parsePurl(purl: string): {
  readonly packageName: string;
  readonly ecosystem: string;
  readonly matchable: boolean;
} {
  const match = /^pkg:([^/]+)\/(.+)@/.exec(purl);
  if (!match) throw new z.ZodError([]);
  const [, purlType, packagePath] = match;
  const rawPackageName = packagePath?.split("/").at(-1);
  if (!purlType || !rawPackageName) throw new z.ZodError([]);
  const packageName = decodeURIComponent(rawPackageName);
  const ecosystem = purlEcosystems[purlType];
  return ecosystem
    ? { packageName, ecosystem, matchable: true }
    : { packageName, ecosystem: `unknown:${purlType}`, matchable: false };
}

function componentFrom(purl: string, version: string): Component {
  const parsed = parsePurl(purl);
  return { ...parsed, version, purl };
}

export function parsePredicate(predicate: unknown): readonly Component[] {
  const cyclonedx = cyclonedxPredicateSchema.safeParse(predicate);
  const components = cyclonedx.success
    ? cyclonedx.data.components.map((component) => componentFrom(component.purl, component.version))
    : spdxSchema.parse(predicate).packages.map((pkg) => {
        const reference = pkg.externalRefs.find((candidate) => candidate.referenceType === "purl");
        if (!reference) throw new z.ZodError([]);
        return componentFrom(purlSchema.parse(reference.referenceLocator), pkg.versionInfo);
      });
  const identities = new Set(
    components.map((component) => `${component.purl}\u0000${component.version}`),
  );
  if (identities.size !== components.length) throw new z.ZodError([]);
  return components;
}
