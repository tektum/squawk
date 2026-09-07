import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { HttpResponse, http } from "msw";
import { beforeAll, beforeEach } from "vitest";
import { reconciliationAudience } from "../../src/actions-oidc";
import { server } from "../server";

let signingKey: CryptoKey;
let publicJwk: JsonWebKey;
const keyId = "actions-test-key";

export const workflowRef = "owner/repo/.github/workflows/monitor.yaml@refs/heads/main";
export const workflowRefSha256 = "9c8629e077b28b0fe69f38b3b14ba13b4de8c9e40b80d498fbb7ed2273962eae";
export const actionsBinding = {
  repositoryId: "9",
  runId: "77",
  workflowRefSha256,
};
export const validClaims = {
  repository_id: "9",
  run_id: "77",
  event_name: "workflow_dispatch",
  actor_id: "312570741",
  workflow_ref: workflowRef,
};

export function installActionsJwks(): void {
  beforeAll(async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    signingKey = pair.privateKey;
    publicJwk = await exportJWK(pair.publicKey);
  });
  beforeEach(() => {
    server.use(
      http.get("https://token.actions.githubusercontent.com/.well-known/jwks", () =>
        HttpResponse.json({ keys: [{ ...publicJwk, kid: keyId, alg: "RS256", use: "sig" }] }),
      ),
    );
  });
}

export async function actionsToken(
  claims: Record<string, unknown> = validClaims,
  options: { issuer?: string; audience?: string; expired?: boolean; key?: CryptoKey } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: keyId })
    .setIssuer(options.issuer ?? "https://token.actions.githubusercontent.com")
    .setAudience(options.audience ?? reconciliationAudience)
    .setIssuedAt(now - 1)
    .setExpirationTime(options.expired ? now - 1 : now + 300)
    .sign(options.key ?? signingKey);
}
