import { exportPKCS8, generateKeyPair } from "jose";
import { http, HttpResponse } from "msw";
import { respond } from "../http";
import { server } from "../server";

export const WEBHOOK_SECRET = "test-webhook-secret";
export const REPOSITORY_ID = 123;
export const INSTALLATION_ID = 456;
export const PLATFORM_DIGEST = `sha256:${"a".repeat(64)}`;
export const INDEX_DIGEST = `sha256:${"b".repeat(64)}`;

export type FailureCase =
  | "action"
  | "event"
  | "repository"
  | "signature"
  | "subject"
  | "predicate"
  | "task";

type Fixture = {
  readonly bindings: Record<string, unknown>;
  readonly request: () => Request;
};

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
}

export async function githubWebhookFixture(
  failure?: FailureCase,
  githubStatus = 200,
  componentVersion = "1.5.0",
  deploymentId = 789,
): Promise<Fixture> {
  const appKeys = await generateKeyPair("RS256", { extractable: true });
  const subjectDigest = failure === "subject" ? `sha256:${"c".repeat(64)}` : PLATFORM_DIGEST;
  const statementSubjectDigest = failure === "subject" ? PLATFORM_DIGEST : subjectDigest;
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "ghcr.io/owner/demo", digest: { sha256: statementSubjectDigest.slice(7) } }],
    predicateType: "https://cyclonedx.org/bom",
    predicate:
      failure === "predicate"
        ? { spdxVersion: "SPDX-2.3", packages: [] }
        : {
            bomFormat: "CycloneDX",
            components: [
              { name: "demo", version: componentVersion, purl: `pkg:npm/demo@${componentVersion}` },
            ],
          },
  };
  const statementBytes = new TextEncoder().encode(JSON.stringify(statement));
  const body = JSON.stringify({
    action: failure === "action" ? "deleted" : "created",
    deployment: {
      id: deploymentId,
      ref: "refs/heads/main",
      sha: "1".repeat(40),
      task: failure === "task" ? "deploy" : "squawk-sbom",
      payload: {
        schema_version: 1,
        platform: "linux/amd64",
        image_ref: `ghcr.io/owner/demo@${PLATFORM_DIGEST}`,
        logical_image_ref: `ghcr.io/owner/demo@${INDEX_DIGEST}`,
        subject_digest: subjectDigest,
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
  const bundleUrl = "https://api.github.test/attestation-bundle";
  server.use(
    http.post(
      `https://api.github.com/app/installations/${INSTALLATION_ID}/access_tokens`,
      async ({ request }) => {
        const payload = await request.json();
        return JSON.stringify(payload) ===
          JSON.stringify({ repository_ids: [REPOSITORY_ID], permissions: { attestations: "read" } })
          ? HttpResponse.json({ token: "installation-token" }, { status: 201 })
          : HttpResponse.json({ message: "token was not repository scoped" }, { status: 400 });
      },
    ),
  );
  respond({
    url: `https://api.github.com/repos/owner/repo/attestations/${subjectDigest}`,
    status: githubStatus,
    body:
      githubStatus === 200
        ? { attestations: [{ repository_id: REPOSITORY_ID, bundle_url: bundleUrl }] }
        : { message: "try again" },
  });
  respond({
    url: bundleUrl,
    status: 200,
    body: {
      mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
      verificationMaterial: {},
      dsseEnvelope: {
        payload: btoa(String.fromCharCode(...statementBytes)),
        payloadType: "application/vnd.in-toto+json",
        signatures: [{ sig: "not-verified-by-design" }],
      },
    },
  });
  respond({
    method: "POST",
    url: "https://osv.test/v1/querybatch",
    status: 200,
    body: { results: [] },
  });
  return {
    bindings: {
      GH_APP_ID: "1234",
      GH_APP_PRIVATE_KEY: await exportPKCS8(appKeys.privateKey),
      GH_WEBHOOK_SECRET: WEBHOOK_SECRET,
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
            "x-github-event": failure === "event" ? "push" : "deployment",
            "x-hub-signature-256": `sha256=${failure === "signature" ? "0".repeat(64) : hex(signature)}`,
          },
          body,
        });
    })(),
  };
}
