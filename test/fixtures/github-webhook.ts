import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from "jose";
import { http, HttpResponse } from "msw";
import { respond } from "../http";
import { server } from "../server";

export const WEBHOOK_SECRET = "test-webhook-secret";
export const REPOSITORY_ID = 123;
export const INSTALLATION_ID = 456;
export const WORKFLOW_SHA = "1".repeat(40);
export const PLATFORM_DIGEST = `sha256:${"a".repeat(64)}`;
export const INDEX_DIGEST = `sha256:${"b".repeat(64)}`;
export const WORKFLOW_REF = "owner/repo/.github/workflows/build.yaml@refs/heads/main";
export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
export const GITHUB_JWKS = "https://token.actions.githubusercontent.com/.well-known/jwks";

export type FailureCase =
  | "action"
  | "audience"
  | "event"
  | "installation"
  | "oidc_subject"
  | "ref"
  | "repository"
  | "signature"
  | "statement"
  | "subject"
  | "task"
  | "workflow"
  | "workflow_sha";

type Fixture = {
  readonly bindings: Record<string, unknown>;
  readonly request: () => Request;
  readonly statementHash: string;
};

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes).buffer));
}

function audience(statementHash: string): string {
  return `urn:squawk:v1:${REPOSITORY_ID}:${WORKFLOW_SHA}:linux%2Famd64:${PLATFORM_DIGEST}:${INDEX_DIGEST}:${statementHash}`;
}

export async function githubWebhookFixture(
  failure?: FailureCase,
  githubStatus = 200,
  componentVersion = "1.5.0",
): Promise<Fixture> {
  const oidcKeys = await generateKeyPair("RS256", { extractable: true });
  const appKeys = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(oidcKeys.publicKey);
  const subjectDigest = failure === "subject" ? "c".repeat(64) : PLATFORM_DIGEST.slice(7);
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "ghcr.io/owner/demo", digest: { sha256: subjectDigest } }],
    predicateType: "https://cyclonedx.org/bom",
    predicate: {
      bomFormat: "CycloneDX",
      components: [
        { name: "demo", version: componentVersion, purl: `pkg:npm/demo@${componentVersion}` },
      ],
    },
  };
  const statementBytes = new TextEncoder().encode(JSON.stringify(statement));
  const statementHash = await sha256(statementBytes);
  const payloadHash = failure === "statement" ? "d".repeat(64) : statementHash;
  const token = await new SignJWT({
    repository_id: failure === "repository" ? "999" : String(REPOSITORY_ID),
    repository: "owner/repo",
    ref: failure === "ref" ? "refs/heads/other" : "refs/heads/main",
    workflow_sha: failure === "workflow_sha" ? "2".repeat(40) : WORKFLOW_SHA,
    job_workflow_ref:
      failure === "workflow"
        ? "owner/repo/.github/workflows/other.yaml@refs/heads/main"
        : WORKFLOW_REF,
  })
    .setProtectedHeader({ alg: "RS256", kid: "github" })
    .setIssuer(GITHUB_ISSUER)
    .setSubject(
      failure === "oidc_subject"
        ? "repo:owner/other:ref:refs/heads/main"
        : "repo:owner/repo:ref:refs/heads/main",
    )
    .setAudience(failure === "audience" ? "wrong" : audience(payloadHash))
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(oidcKeys.privateKey);
  const body = JSON.stringify({
    action: failure === "action" ? "deleted" : "created",
    deployment: {
      id: 789,
      ref: "refs/heads/main",
      sha: WORKFLOW_SHA,
      task: failure === "task" ? "deploy" : "squawk-sbom",
      payload: {
        schema_version: 1,
        image: "ghcr.io/owner/demo",
        platform: "linux/amd64",
        image_digest: PLATFORM_DIGEST,
        index_digest: INDEX_DIGEST,
        statement_sha256: payloadHash,
        oidc_token: token,
      },
    },
    installation: { id: failure === "installation" ? 999 : INSTALLATION_ID },
    repository: { id: REPOSITORY_ID, full_name: "owner/repo" },
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
  respond({
    url: GITHUB_JWKS,
    status: 200,
    body: { keys: [{ ...jwk, kid: "github", alg: "RS256", use: "sig" }] },
  });
  server.use(
    http.post(
      `https://api.github.com/app/installations/${INSTALLATION_ID}/access_tokens`,
      async ({ request }) => {
        const body = await request.json();
        return JSON.stringify(body) ===
          JSON.stringify({ repository_ids: [REPOSITORY_ID], permissions: { attestations: "read" } })
          ? HttpResponse.json({ token: "installation-token" }, { status: 201 })
          : HttpResponse.json({ message: "token was not repository scoped" }, { status: 400 });
      },
    ),
  );
  respond({
    url: `https://api.github.com/repos/owner/repo/attestations/${PLATFORM_DIGEST}`,
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
      GH_OIDC_ISSUER: GITHUB_ISSUER,
      GH_OIDC_JWKS_URL: GITHUB_JWKS,
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
    statementHash,
  };
}
