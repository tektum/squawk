import { readdirSync, readFileSync } from "node:fs";
import {
  bundleMediaType,
  dispatchBodySchema,
  type DispatchRecord,
  type Feeds,
  type GitHubState,
  type HandlerOptions,
  imagesSchema,
  indexMediaType,
  type LoadedFixtures,
  manifestMediaType,
  type Origin,
  type OriginHandler,
  type OriginOptions,
  type OsvState,
  queryRequestSchema,
  queryTableSchema,
  type Registry,
  type Routed,
} from "./origin-types";

export type * from "./origin-types";

const accessTokenPattern = /^\/app\/installations\/[^/]+\/access_tokens$/;
const repositoryPattern = /^\/repositories\/[^/]+$/;
const dispatchPattern = /^\/repos\/([^/]+)\/([^/]+)\/actions\/workflows\/([^/]+)\/dispatches$/;
const encoder = new TextEncoder();

/** Node and Workers disagree on TextEncoder's buffer type; this buffer is never shared. */
function jsonBytes(value: unknown): Uint8Array<ArrayBuffer> {
  return encoder.encode(JSON.stringify(value)) as Uint8Array<ArrayBuffer>;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000)
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(binary);
}

async function digestOf(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return `sha256:${Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function problem(status: number, error: string, path: string): Response {
  return Response.json({ error, path }, { status });
}

function text(value: string, contentType: string): Response {
  return new Response(value, { headers: { "content-type": contentType } });
}

/** The only place that touches the filesystem, so `createOriginHandler` stays portable. */
export function loadFixtures(fixturesDir: string): LoadedFixtures {
  const read = (relative: string) => readFileSync(`${fixturesDir}/${relative}`, "utf8");
  const images = imagesSchema.parse(JSON.parse(read("images.json")));
  const spdx: Record<string, unknown> = {};
  for (const image of Object.values(images))
    for (const platform of image.platforms) spdx[platform.spdx] = JSON.parse(read(platform.spdx));
  const advisories: Record<string, string> = {};
  for (const entry of readdirSync(`${fixturesDir}/osv`))
    if (entry.endsWith(".json") && entry !== "querybatch.json")
      advisories[entry.slice(0, -".json".length)] = read(`osv/${entry}`);
  return {
    images,
    spdx,
    advisories,
    queries: queryTableSchema.parse(JSON.parse(read("osv/querybatch.json"))),
  };
}

/**
 * Synthesises the GHCR referrers index, bundle manifests, and bundle blobs for
 * every fixture image. Every emitted digest is the real hash of the exact bytes
 * the manifest and blob routes then serve.
 */
async function buildRegistry(fixtures: LoadedFixtures): Promise<Registry> {
  const manifests = new Map<string, Uint8Array<ArrayBuffer>>();
  const blobs = new Map<string, Uint8Array<ArrayBuffer>>();
  for (const image of Object.values(fixtures.images)) {
    const imagePath = image.image.slice("ghcr.io/".length);
    const descriptors: unknown[] = [];
    for (const platform of image.platforms) {
      const blob = jsonBytes({
        mediaType: bundleMediaType,
        dsseEnvelope: {
          payload: toBase64(
            jsonBytes({
              _type: "https://in-toto.io/Statement/v1",
              // The index digest is the webhook's subject; the platform manifest
              // digest is what this per-platform attestation actually attests to.
              subject: [
                { name: image.image, digest: { sha256: image.indexDigest.slice(7) } },
                { name: image.image, digest: { sha256: platform.manifestDigest.slice(7) } },
              ],
              predicateType: "https://spdx.dev/Document",
              predicate: fixtures.spdx[platform.spdx],
            }),
          ),
          payloadType: "application/vnd.in-toto+json",
          signatures: [{ sig: "local-e2e-not-verified-by-design" }],
        },
      });
      const layerDigest = await digestOf(blob);
      blobs.set(`${imagePath}/${layerDigest}`, blob);
      const manifest = jsonBytes({
        schemaVersion: 2,
        mediaType: manifestMediaType,
        artifactType: bundleMediaType,
        layers: [{ digest: layerDigest, mediaType: bundleMediaType, size: blob.byteLength }],
        subject: { digest: image.indexDigest, mediaType: indexMediaType },
      });
      const digest = await digestOf(manifest);
      manifests.set(`${imagePath}/${digest}`, manifest);
      const size = manifest.byteLength;
      descriptors.push({
        artifactType: bundleMediaType,
        digest,
        mediaType: manifestMediaType,
        size,
      });
    }
    manifests.set(
      `${imagePath}/sha256-${image.indexDigest.slice(7)}`,
      jsonBytes({ schemaVersion: 2, mediaType: indexMediaType, manifests: descriptors }),
    );
  }
  return { manifests, blobs };
}

function buildFeeds(fixtures: LoadedFixtures): Feeds {
  const feeds = new Map<string, Map<string, string>>();
  for (const [key, vulns] of Object.entries(fixtures.queries)) {
    const ecosystem = key.split("|")[0] ?? "";
    // OSV publishes advisory feeds per ecosystem family, so Alpine:v3.21 shares Alpine's.
    for (const name of new Set([ecosystem, ecosystem.split(":")[0] ?? ecosystem])) {
      const feed = feeds.get(name) ?? new Map<string, string>();
      for (const vulnerability of vulns) feed.set(vulnerability.id, vulnerability.modified);
      feeds.set(name, feed);
    }
  }
  return feeds;
}

async function githubRoute(request: Request, path: string, state: GitHubState): Promise<Routed> {
  if (request.method === "POST" && accessTokenPattern.test(path))
    return Response.json({ token: state.token }, { status: 201 });
  if (request.method === "GET" && repositoryPattern.test(path))
    return Response.json({ full_name: state.fullName });
  const route = request.method === "POST" ? dispatchPattern.exec(path) : null;
  if (!route) return undefined;
  const [, owner = "", repo = "", workflow = ""] = route;
  const body: unknown = await request.json().catch(() => null);
  const parsed = dispatchBodySchema.safeParse(body);
  if (!parsed.success) return problem(400, "invalid dispatch body", path);
  let payload: unknown;
  try {
    payload = JSON.parse(parsed.data.inputs.payload);
  } catch {
    return problem(400, "invalid dispatch payload", path);
  }
  state.log.push({ owner, repo, workflow, ref: parsed.data.ref, payload });
  return new Response(null, { status: 204 });
}

function registryRoute(request: Request, path: string, registry: Registry): Routed {
  if (request.method !== "GET") return undefined;
  if (path === "/token") return Response.json({ token: "local-registry-token" });
  if (!path.startsWith("/v2/")) return undefined;
  const segments = path.split("/").filter(Boolean).map(decodeURIComponent);
  const reference = segments.at(-1) ?? "";
  const kind = segments.at(-2);
  const store =
    kind === "blobs" ? registry.blobs : kind === "manifests" ? registry.manifests : null;
  const bytes = store?.get(`${segments.slice(1, -2).join("/")}/${reference}`);
  if (!bytes) return problem(404, "registry object not found", path);
  const oci = reference.startsWith("sha256-") ? indexMediaType : manifestMediaType;
  const contentType = kind === "blobs" ? bundleMediaType : oci;
  return new Response(bytes, { headers: { "content-type": contentType } });
}

async function osvRoute(request: Request, path: string, osv: OsvState): Promise<Routed> {
  if (request.method === "POST") {
    if (path !== "/v1/querybatch") return undefined;
    const body: unknown = await request.json().catch(() => null);
    const parsed = queryRequestSchema.safeParse(body);
    if (!parsed.success) return problem(400, "invalid querybatch body", path);
    return Response.json({
      results: parsed.data.queries.map(({ package: identity, version }) => ({
        vulns: osv.queries[`${identity.ecosystem}|${identity.name}|${version ?? ""}`] ?? [],
      })),
    });
  }
  if (request.method !== "GET") return undefined;
  if (path === "/ecosystems.txt")
    return text(`${[...osv.feeds.keys()].sort().join("\n")}\n`, "text/plain");
  const [ecosystem = "", leaf = "", extra] = path.split("/").slice(1).map(decodeURIComponent);
  if (extra !== undefined || leaf === "") return undefined;
  if (leaf === "modified_id.csv") {
    const feed = osv.feeds.get(ecosystem);
    if (!feed) return problem(404, "unknown ecosystem", path);
    // Real OSV serves headerless "modified,id" rows, newest first.
    const rows = [...feed]
      .map(([id, modified]) => `${modified},${id}`)
      .sort((left, right) => right.localeCompare(left));
    return text(rows.length === 0 ? "" : `${rows.join("\n")}\n`, "text/csv");
  }
  if (!leaf.endsWith(".json")) return undefined;
  const document = osv.advisories[leaf.slice(0, -".json".length)];
  if (document === undefined) return problem(404, "unknown advisory", path);
  return text(document, "application/json");
}

/**
 * Builds the transport-agnostic fake origin: one handler impersonating the
 * GitHub API, GHCR, and OSV, routed purely on the request path so a single base
 * URL serves all three. Drive it from `Bun.serve` locally or from msw in CI.
 */
export function createOriginHandler(options: HandlerOptions): OriginHandler {
  const dispatches: DispatchRecord[] = [];
  const requests: string[] = [];
  const github: GitHubState = {
    token: options.installationToken ?? "local-installation-token",
    fullName: options.repositoryFullName ?? "tektum/verity-images",
    log: dispatches,
  };
  const osv: OsvState = { ...options.fixtures, feeds: buildFeeds(options.fixtures) };
  // Digests hash the exact bytes served, so the registry is built once, up
  // front, and any failure surfaces as a 500 on the request that needed it.
  const registry = buildRegistry(options.fixtures);
  registry.catch(() => undefined);
  return {
    async handle(request) {
      const path = new URL(request.url).pathname;
      requests.push(`${request.method} ${path}`);
      try {
        return (
          (await githubRoute(request, path, github)) ??
          registryRoute(request, path, await registry) ??
          (await osvRoute(request, path, osv)) ??
          problem(404, `no fake origin route for ${request.method}`, path)
        );
      } catch (error) {
        return problem(500, `fake origin failed: ${String(error)}`, path);
      }
    },
    state: {
      dispatches,
      requests,
      reset() {
        dispatches.length = requests.length = 0;
      },
    },
  };
}

/** Local-run transport: a real listener on a caller-provided bind address. */
export async function startOrigin(options: OriginOptions): Promise<Origin> {
  const { handle, state } = createOriginHandler({
    fixtures: loadFixtures(options.fixturesDir),
    installationToken: options.installationToken,
    repositoryFullName: options.repositoryFullName,
  });
  const server = Bun.serve({ hostname: options.hostname, port: options.port ?? 0, fetch: handle });
  return {
    ...state,
    url: server.url.origin,
    stop: () => server.stop(true),
  };
}
