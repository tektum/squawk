import { createRemoteJWKSet, errors, jwtVerify } from "jose";
import { z } from "zod";
import { sha256 } from "./digest";

const issuer = "https://token.actions.githubusercontent.com";
export const reconciliationAudience = "squawk:github-actions:reconciliation:v2";
const trustedActorId = "312570741";
const authorizationSchema = z
  .string()
  .regex(/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
  .transform((value) => value.slice("Bearer ".length));
const claimsSchema = z.object({
  repository_id: z.string().regex(/^\d+$/),
  run_id: z.string().regex(/^\d+$/),
  event_name: z.literal("workflow_dispatch"),
  actor_id: z.literal(trustedActorId),
  workflow_ref: z.string().min(1),
  exp: z.number().int().positive(),
});
const keys = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks`));

export class ActionsAuthenticationError extends Error {
  readonly name = "ActionsAuthenticationError";
}

export class ActionsAuthorizationError extends Error {
  readonly name = "ActionsAuthorizationError";
}

export type ActionsRunBinding = {
  readonly repositoryId: string;
  readonly runId: string;
  readonly workflowRefSha256: string;
};

export async function authenticateActionsRun(
  authorization: string | undefined,
  binding: ActionsRunBinding,
): Promise<void> {
  let token: string;
  try {
    token = authorizationSchema.parse(authorization);
  } catch {
    throw new ActionsAuthenticationError("invalid actions authentication input");
  }
  let payload: unknown;
  try {
    payload = (
      await jwtVerify(token, keys, {
        issuer,
        audience: reconciliationAudience,
        algorithms: ["RS256"],
      })
    ).payload;
  } catch (error) {
    if (error instanceof errors.JOSEError)
      throw new ActionsAuthenticationError("invalid actions identity");
    throw error;
  }
  const claims = claimsSchema.safeParse(payload);
  if (!claims.success) throw new ActionsAuthenticationError("invalid actions claims");
  if (
    claims.data.repository_id !== binding.repositoryId ||
    claims.data.run_id !== binding.runId ||
    (await sha256(claims.data.workflow_ref)) !== binding.workflowRefSha256
  )
    throw new ActionsAuthorizationError("actions run is not authorized for delivery");
}
