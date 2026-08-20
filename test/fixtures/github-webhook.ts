import { exportPKCS8, generateKeyPair } from "jose";
import { HttpResponse, http } from "msw";
import { respond } from "../http";
import { server } from "../server";
import { AMD64_DIGEST, ARM64_DIGEST, INDEX_DIGEST, statement } from "./github-webhook-statement";

export const WEBHOOK_SECRET = "test-webhook-secret";
export const REPOSITORY_ID = 123;
export const INSTALLATION_ID = 456;

export type FailureCase =
  | "changed"
  | "duplicates"
  | "event"
  | "ignored"
  | "index-only"
  | "installation"
  | "mixed-referrers"
  | "many-attestations"
  | "noisy-index"
  | "predicate"
  | "repository"
  | "signature"
  | "subject"
  | "unattested"
  | "vulnerable";

type Fixture = {
  readonly bindings: Record<string, unknown>;
  readonly request: () => Request;
};

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
}

export async function githubWebhookFixture(
  failure?: FailureCase,
  registryStatus = 200,
  packageVersionId = 789,
  attestationsVisible: { value: boolean } = { value: failure !== "unattested" },
): Promise<Fixture> {
  const appKeys = await generateKeyPair("RS256", { extractable: true });
  const component =
    failure === "vulnerable" ? { componentName: "lodash", componentVersion: "4.17.20" } : {};
  const statements = [
    statement("amd64", AMD64_DIGEST, {
      ...component,
      indexOnly: failure === "index-only",
      wrongSubject: failure === "subject",
    }),
    statement("arm64", ARM64_DIGEST, {
      ...component,
      ...(failure === "changed" ? { componentVersion: "2.0.0" } : {}),
      indexOnly: failure === "index-only",
      invalidPredicate: failure === "predicate",
      wrongSubject: failure === "subject",
    }),
  ];
  const body = JSON.stringify({
    action: failure === "ignored" ? "deleted" : "published",
    installation: { id: failure === "installation" ? 999 : INSTALLATION_ID },
    registry_package: {
      id: 42,
      name: "demo",
      namespace: "owner",
      package_type: "container",
      package_version: {
        id: failure === "changed" ? packageVersionId + 1 : packageVersionId,
        container_metadata: {
          tag: { name: "latest", digest: INDEX_DIGEST },
          manifest: {
            digest: INDEX_DIGEST,
            media_type: "application/vnd.oci.image.index.v1+json",
            uri: `repositories/owner/demo/manifests/${INDEX_DIGEST}`,
          },
        },
      },
    },
    repository: {
      id: failure === "repository" ? 999 : REPOSITORY_ID,
      full_name: failure === "repository" ? "owner/other" : "owner/repo",
    },
    sender: { login: "github-actions[bot]", id: 41898282 },
  });
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(WEBHOOK_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  const attestations = [
    {
      manifestDigest: `sha256:${"d".repeat(64)}`,
      layerDigest: `sha256:${"f".repeat(64)}`,
      statement: statements[0],
    },
    {
      manifestDigest: `sha256:${"e".repeat(64)}`,
      layerDigest: `sha256:${"0".repeat(64)}`,
      statement: statements[1],
    },
  ];
  const primaryAttestation = attestations[0];
  if (!primaryAttestation) throw new Error("missing primary attestation");
  server.use(
    http.get("https://ghcr.io/token", () =>
      registryStatus === 200
        ? HttpResponse.json({ token: "registry-token" })
        : HttpResponse.json({ error: "unavailable" }, { status: registryStatus }),
    ),
    http.get("https://ghcr.io/v2/owner/demo/manifests/:reference", ({ params }) => {
      // biome-ignore lint/complexity/useLiteralKeys: params is an index-signature map.
      const reference = String(params["reference"]);
      if (!attestationsVisible.value && reference === `sha256-${INDEX_DIGEST.slice(7)}`)
        return HttpResponse.json({ error: "not found" }, { status: 404 });
      if (reference === `sha256-${INDEX_DIGEST.slice(7)}`)
        return HttpResponse.json({
          schemaVersion: 2,
          manifests: [
            ...(failure === "mixed-referrers"
              ? Array.from({ length: 25 }, (_, index) => ({
                  artifactType: "application/vnd.oci.empty.v1+json",
                  digest: `sha256:${(index + 1).toString(16).padStart(64, "0")}`,
                  mediaType: "application/vnd.oci.image.manifest.v1+json",
                }))
              : failure === "noisy-index"
                ? Array.from({ length: 21 }, (_, index) => ({
                    artifactType: "application/vnd.oci.empty.v1+json",
                    digest: `sha256:${index.toString(16).padStart(64, "0")}`,
                    mediaType: "application/vnd.oci.image.manifest.v1+json",
                  }))
                : []),
            ...(failure === "many-attestations"
              ? Array.from({ length: 10 }, () => primaryAttestation)
              : failure === "duplicates"
                ? [...attestations, ...attestations]
                : attestations
            ).map((attestation) => ({
              artifactType:
                failure === "mixed-referrers"
                  ? "application/vnd.oci.empty.v1+json"
                  : "application/vnd.dev.sigstore.bundle.v0.3+json",
              digest: attestation.manifestDigest,
              mediaType: "application/vnd.oci.image.manifest.v1+json",
            })),
          ],
        });
      const attestation = attestations.find((candidate) => candidate.manifestDigest === reference);
      return attestation
        ? HttpResponse.json({
            artifactType: "application/vnd.dev.sigstore.bundle.v0.3+json",
            layers: [
              {
                digest: attestation.layerDigest,
                mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
              },
            ],
          })
        : HttpResponse.json({ error: "not found" }, { status: 404 });
    }),
    http.get("https://ghcr.io/v2/owner/demo/blobs/:digest", ({ params }) => {
      const attestation = attestations.find(
        // biome-ignore lint/complexity/useLiteralKeys: params is an index-signature map.
        (candidate) => candidate.layerDigest === String(params["digest"]),
      );
      return attestation
        ? HttpResponse.json({
            mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
            dsseEnvelope: {
              payload: btoa(JSON.stringify(attestation.statement)),
              payloadType: "application/vnd.in-toto+json",
              signatures: [{ sig: "not-verified-by-design" }],
            },
          })
        : HttpResponse.json({ error: "not found" }, { status: 404 });
    }),
  );
  respond({
    method: "POST",
    url: "https://api.osv.test/v1/querybatch",
    status: 200,
    body:
      failure === "vulnerable"
        ? {
            results: [
              {
                vulns: [
                  {
                    id: "GHSA-35jh-r3h4-6jhm",
                    modified: "2026-01-01T00:00:00Z",
                    affected: [
                      {
                        package: { ecosystem: "npm", name: "lodash" },
                        ranges: [
                          { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] },
                        ],
                        versions: [],
                      },
                    ],
                  },
                ],
              },
            ],
          }
        : { results: [] },
  });
  return {
    bindings: {
      GH_APP_ID: "1234",
      GH_APP_INSTALLATION_ID: String(INSTALLATION_ID),
      GH_APP_PRIVATE_KEY: await exportPKCS8(appKeys.privateKey),
      GH_WEBHOOK_SECRET: WEBHOOK_SECRET,
      OSV_API_URL: "https://api.osv.test",
      OSV_BASE_URL: "https://osv.test",
      DISPATCH_ENABLED: "false",
    },
    request: (() => {
      const deliveryId = crypto.randomUUID();
      return () =>
        new Request("https://squawk.test/webhooks/github", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-github-delivery": deliveryId,
            "x-github-event": failure === "event" ? "push" : "registry_package",
            "x-hub-signature-256": `sha256=${failure === "signature" ? "0".repeat(64) : hex(signature)}`,
          },
          body,
        });
    })(),
  };
}
