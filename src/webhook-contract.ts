import { z } from "zod";
import type { GitHubAppEnv } from "./github";

const maxBodyBytes = 64 * 1024;
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const packagePathSchema = z.string().regex(/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/);

export const webhookSchema = z.object({
  action: z.string().min(1),
  installation: z.object({ id: z.union([z.number().int().positive(), z.string().regex(/^\d+$/)]) }),
  registry_package: z.object({
    id: z.number().int().positive(),
    name: z.string().min(1),
    namespace: z.string().min(1),
    package_type: z.string().min(1),
    package_version: z.object({
      id: z.number().int().positive(),
      container_metadata: z.object({
        tag: z.object({ name: z.string(), digest: digestSchema }),
        manifest: z.object({
          digest: digestSchema,
          media_type: z.string().min(1),
          uri: z
            .string()
            .regex(/^repositories\/.+\/manifests\/sha256:[a-f0-9]{64}$/)
            .transform((value) => value.slice("repositories/".length).split("/manifests/")[0])
            .pipe(packagePathSchema),
        }),
      }),
    }),
  }),
  repository: z.object({
    id: z.union([z.number().int().positive(), z.string().regex(/^\d+$/)]),
    full_name: z.string().regex(/^[^/]+\/[^/]+$/),
  }),
  sender: z.object({ id: z.number().int().positive(), login: z.string().min(1) }),
});
export const sourceSchema = z.object({
  installation_id: z.string().regex(/^\d+$/),
  org_id: z.string().min(1).brand<"TenantId">(),
});
export const statementSchema = z.object({
  _type: z.enum(["https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"]),
  subject: z.array(z.object({ name: z.string(), digest: z.object({ sha256: z.string() }) })).min(1),
  predicateType: z.literal("https://spdx.dev/Document"),
  predicate: z.unknown(),
});

export type WebhookEnv = GitHubAppEnv & {
  readonly DB: D1Database;
  readonly EXECUTION_CONTEXT: ExecutionContext;
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

export async function parseWebhook(request: Request, secret: string) {
  const body = await readBody(request);
  await verifySignature(body, request.headers.get("x-hub-signature-256") ?? undefined, secret);
  if (request.headers.get("x-github-event") !== "registry_package")
    throw new WebhookError(400, "wrong event");
  return {
    deliveryId: z.string().uuid().parse(request.headers.get("x-github-delivery")),
    event: webhookSchema.parse(JSON.parse(new TextDecoder().decode(body))),
  };
}
