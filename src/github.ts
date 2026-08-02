import { importPKCS8, SignJWT } from "jose";
import { z } from "zod";
import type { SubrequestBudget } from "./budget";

export type GitHubAppEnv = {
  readonly GH_APP_ID: string;
  readonly GH_APP_PRIVATE_KEY: string;
};

type TokenRequest = {
  readonly installationId: string;
  readonly repositoryId?: string;
  readonly permissions?: Readonly<Record<string, "read" | "write">>;
};

export class GitHubApiError extends Error {
  readonly name = "GitHubApiError";
  constructor(readonly status: number) {
    super(`GitHub API failed (${status})`);
  }
}

export async function installationToken(
  env: GitHubAppEnv,
  request: TokenRequest,
  now = Date.now(),
  budget?: SubrequestBudget,
): Promise<string> {
  const key = await importPKCS8(env.GH_APP_PRIVATE_KEY, "RS256");
  const jwt = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(env.GH_APP_ID)
    .setIssuedAt(Math.floor(now / 1000) - 60)
    .setExpirationTime(Math.floor(now / 1000) + 540)
    .sign(key);
  budget?.take();
  const response = await fetch(
    `https://api.github.com/app/installations/${request.installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${jwt}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
        "user-agent": "squawk",
        "x-github-api-version": "2026-03-10",
      },
      body: JSON.stringify({
        ...(request.repositoryId ? { repository_ids: [Number(request.repositoryId)] } : {}),
        ...(request.permissions ? { permissions: request.permissions } : {}),
      }),
      signal: AbortSignal.timeout(10_000),
    },
  );
  if (!response.ok) throw new GitHubApiError(response.status);
  return z.object({ token: z.string().min(1) }).parse(await response.json()).token;
}
