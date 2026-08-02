import { z } from "zod";
import type { GitHubAppEnv } from "./github";

const maxBodyBytes = 64 * 1024;
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);

export const webhookSchema = z.object({
  action: z.literal("created"),
  deployment: z.object({
    ref: z.string().min(1),
    sha: z.string().regex(/^[a-f0-9]{40}$/),
    task: z.literal("squawk-sbom"),
    payload: z.object({
      schema_version: z.literal(1),
      image: z.string().regex(/^ghcr\.io\/[a-z0-9_.-]+\/[a-z0-9_./-]+$/),
      platform: z.enum(["linux/amd64", "linux/arm64"]),
      image_digest: digestSchema,
      index_digest: digestSchema,
      statement_sha256: z.string().regex(/^[a-f0-9]{64}$/),
      oidc_token: z.string().min(1),
    }),
  }),
  installation: z.object({ id: z.union([z.number().int().positive(), z.string().regex(/^\d+$/)]) }),
  repository: z.object({
    id: z.union([z.number().int().positive(), z.string().regex(/^\d+$/)]),
    full_name: z.string().regex(/^[^/]+\/[^/]+$/),
  }),
  sender: z.object({ id: z.number().int().positive(), login: z.string().min(1) }),
});
export const sourceSchema = z.object({
  org_id: z.string().min(1).brand<"TenantId">(),
  workflow: z.string().regex(/^\.github\/workflows\/[a-zA-Z0-9_.-]+$/),
  ref: z.string(),
});
export const claimsSchema = z.object({
  repository_id: z.string(),
  repository: z.string(),
  ref: z.string(),
  workflow_sha: z.string(),
  job_workflow_ref: z.string(),
  sub: z.string(),
});
export const statementSchema = z.object({
  _type: z.literal("https://in-toto.io/Statement/v1"),
  subject: z.array(z.object({ name: z.string(), digest: z.object({ sha256: z.string() }) })).min(1),
  predicateType: z.literal("https://cyclonedx.org/bom"),
  predicate: z.unknown(),
});

export type WebhookEnv = GitHubAppEnv & {
  readonly DB: D1Database;
  readonly EXECUTION_CONTEXT: ExecutionContext;
  readonly GH_OIDC_ISSUER: string;
  readonly GH_OIDC_JWKS_URL: string;
  readonly GH_WEBHOOK_SECRET: string;
  readonly OSV_BASE_URL: string;
};

export class WebhookError extends Error {
  readonly name = "WebhookError";
  constructor(
    readonly status: 400 | 401 | 403 | 409 | 413 | 502,
    message: string,
  ) {
    super(message);
  }
}

async function readBody(request: Request): Promise<Uint8Array> {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (declared > maxBodyBytes) throw new WebhookError(413, "payload too large");
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    length += part.value.byteLength;
    if (length > maxBodyBytes) {
      await reader.cancel();
      throw new WebhookError(413, "payload too large");
    }
    chunks.push(part.value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function verifySignature(bytes: Uint8Array, header: string | undefined, secret: string) {
  const encoded = /^sha256=([a-f0-9]{64})$/.exec(header ?? "")?.[1];
  if (!encoded) throw new WebhookError(401, "invalid signature");
  const signature = Uint8Array.from(encoded.match(/.{2}/g) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  if (!(await crypto.subtle.verify("HMAC", key, signature, new Uint8Array(bytes).buffer)))
    throw new WebhookError(401, "invalid signature");
}

export function audience(
  payload: z.infer<typeof webhookSchema>["deployment"]["payload"],
  repositoryId: string,
  workflowSha: string,
): string {
  return `urn:squawk:v1:${repositoryId}:${workflowSha}:${encodeURIComponent(payload.platform)}:${payload.image_digest}:${payload.index_digest}:${payload.statement_sha256}`;
}

export async function parseWebhook(request: Request, secret: string) {
  const body = await readBody(request);
  await verifySignature(body, request.headers.get("x-hub-signature-256") ?? undefined, secret);
  if (request.headers.get("x-github-event") !== "deployment")
    throw new WebhookError(400, "wrong event");
  return {
    deliveryId: z.string().uuid().parse(request.headers.get("x-github-delivery")),
    event: webhookSchema.parse(JSON.parse(new TextDecoder().decode(body))),
  };
}
