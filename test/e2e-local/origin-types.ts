import { z } from "zod";

/** Optional fields accept an explicit `undefined` so callers can build options dynamically. */
export type OriginOptions = {
  readonly hostname: string;
  readonly port?: number | undefined;
  readonly fixturesDir: string;
  readonly installationToken?: string | undefined;
  readonly repositoryFullName?: string | undefined;
};

export type HandlerOptions = {
  readonly fixtures: LoadedFixtures;
  readonly installationToken?: string | undefined;
  readonly repositoryFullName?: string | undefined;
};

export type DispatchRecord = {
  readonly owner: string;
  readonly repo: string;
  readonly workflow: string;
  readonly ref: string;
  readonly payload: unknown;
};

export type OriginState = {
  readonly dispatches: readonly DispatchRecord[];
  readonly requests: readonly string[];
  reset(): void;
};

export type OriginHandler = {
  readonly handle: (request: Request) => Promise<Response>;
  readonly state: OriginState;
};

export type Origin = OriginState & {
  readonly url: string;
  stop(): Promise<void>;
};

export const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json";
export const manifestMediaType = "application/vnd.oci.image.manifest.v1+json";
export const indexMediaType = "application/vnd.oci.image.index.v1+json";

const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);

export const vulnSchema = z.object({ id: z.string().min(1), modified: z.string().min(1) });
/** `images.json` carries exactly the two scenarios the end-to-end run drives. */
const imageSchema = z.object({
  name: z.string().min(1),
  image: z.string().startsWith("ghcr.io/"),
  indexDigest: digestSchema,
  platforms: z
    .array(
      z.object({
        platform: z.string().min(1),
        manifestDigest: digestSchema,
        spdx: z.string().min(1),
      }),
    )
    .min(1),
  expectedFindings: z.array(
    z.object({
      packageName: z.string(),
      ecosystem: z.string(),
      version: z.string(),
      vulnId: z.string(),
      severity: z.string().nullish(),
    }),
  ),
});
export const imagesSchema = z.object({ vulnerable: imageSchema, clean: imageSchema });
export const queryTableSchema = z.record(z.string(), z.array(vulnSchema));
export const queryRequestSchema = z.object({
  queries: z.array(
    z.object({
      package: z.object({ name: z.string(), ecosystem: z.string() }),
      version: z.string().optional(),
    }),
  ),
});
export const dispatchBodySchema = z.object({
  ref: z.string(),
  inputs: z.object({ payload: z.string() }),
});

export type FixtureImage = z.infer<typeof imageSchema>;
export type FixtureImages = z.infer<typeof imagesSchema>;
export type VulnerabilityRef = z.infer<typeof vulnSchema>;

export type LoadedFixtures = {
  readonly images: FixtureImages;
  /** SPDX documents keyed by their `images.json` relative path. */
  readonly spdx: Readonly<Record<string, unknown>>;
  /** Raw advisory documents keyed by advisory id, served byte-for-byte. */
  readonly advisories: Readonly<Record<string, string>>;
  readonly queries: Readonly<Record<string, readonly VulnerabilityRef[]>>;
};

export type Registry = {
  readonly manifests: ReadonlyMap<string, Uint8Array<ArrayBuffer>>;
  readonly blobs: ReadonlyMap<string, Uint8Array<ArrayBuffer>>;
};

/** Ecosystem, and its family, to advisory id to modified timestamp. */
export type Feeds = ReadonlyMap<string, ReadonlyMap<string, string>>;

export type GitHubState = {
  readonly token: string;
  readonly fullName: string;
  readonly log: DispatchRecord[];
};

export type OsvState = LoadedFixtures & { readonly feeds: Feeds };

/** A route either answers or declines, letting the next surface try the path. */
export type Routed = Response | undefined;
