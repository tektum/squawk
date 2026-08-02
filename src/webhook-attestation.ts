import { z } from "zod";
import { GitHubApiError, installationToken } from "./github";
import {
  statementSchema,
  WebhookError,
  type WebhookEnv,
  type webhookSchema,
} from "./webhook-contract";

const attestationIndexSchema = z.object({
  attestations: z
    .array(z.object({ repository_id: z.number(), bundle_url: z.string().url() }))
    .max(100),
});
const bundleSchema = z.object({
  mediaType: z.literal("application/vnd.dev.sigstore.bundle.v0.3+json"),
  dsseEnvelope: z.object({
    payload: z.string().min(1),
    payloadType: z.literal("application/vnd.in-toto+json"),
    signatures: z.array(z.object({ sig: z.string().min(1) })).min(1),
  }),
});
type StatementRequest = {
  readonly env: WebhookEnv;
  readonly installationId: string;
  readonly payload: z.infer<typeof webhookSchema>["deployment"]["payload"];
  readonly repository: string;
  readonly repositoryId: string;
};

async function githubJson(url: string, token: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "user-agent": "squawk",
      "x-github-api-version": "2026-03-10",
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new GitHubApiError(response.status);
  return response.json();
}

export async function statementFor(request: StatementRequest) {
  const token = await installationToken(request.env, {
    installationId: request.installationId,
    repositoryId: request.repositoryId,
    permissions: { attestations: "read" },
  });
  const index = attestationIndexSchema.parse(
    await githubJson(
      `https://api.github.com/repos/${request.repository}/attestations/${request.payload.subject_digest}`,
      token,
    ),
  );
  for (const item of index.attestations.filter(
    (entry) => String(entry.repository_id) === request.repositoryId,
  )) {
    const bundle = bundleSchema.parse(await githubJson(item.bundle_url, token));
    const bytes = Uint8Array.from(atob(bundle.dsseEnvelope.payload), (character) =>
      character.charCodeAt(0),
    );
    return statementSchema.parse(JSON.parse(new TextDecoder().decode(bytes)));
  }
  throw new WebhookError(400, "matching statement not found");
}
