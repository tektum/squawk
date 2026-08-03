import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import { CapabilitySchema, TenantIdSchema, UserIdSchema, type Principal } from "./domain";

const discoverySchema = z.object({ jwks_uri: z.string().url() });
const claimsSchema = z.object({
  tenants: z.array(z.string().min(1)).length(1),
  permissions: z.array(CapabilitySchema).default([]),
  sub: z.string().min(1).optional(),
});

type AuthConfig = {
  readonly issuer: string;
  readonly audience: string;
  readonly discoveryUrl: string;
};

const discoveryCache = new Map<string, z.infer<typeof discoverySchema>>();
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export class AuthenticationError extends Error {
  readonly name = "AuthenticationError";
}

export class AuthorizationError extends Error {
  readonly name = "AuthorizationError";
}

export async function authenticate(
  authorization: string | undefined,
  config: AuthConfig,
): Promise<Principal> {
  if (!authorization?.startsWith("Bearer ")) throw new AuthenticationError("missing bearer token");
  const discoveryUrl = new URL(config.discoveryUrl);
  if (discoveryUrl.protocol !== "https:") throw new AuthenticationError("discovery must use HTTPS");
  let discovery = discoveryCache.get(config.discoveryUrl);
  if (!discovery) {
    const discoveryResponse = await fetch(discoveryUrl, { signal: AbortSignal.timeout(5_000) });
    if (!discoveryResponse.ok) throw new AuthenticationError("discovery unavailable");
    discovery = discoverySchema.parse(await discoveryResponse.json());
    discoveryCache.set(config.discoveryUrl, discovery);
  }
  const jwksUrl = new URL(discovery.jwks_uri);
  if (jwksUrl.protocol !== "https:" || jwksUrl.origin !== discoveryUrl.origin) {
    throw new AuthenticationError("untrusted discovery document");
  }
  let remoteJwks = jwksCache.get(discovery.jwks_uri);
  if (!remoteJwks) {
    remoteJwks = createRemoteJWKSet(jwksUrl, { cooldownDuration: 0 });
    jwksCache.set(discovery.jwks_uri, remoteJwks);
  }
  const verified = await jwtVerify(authorization.slice(7), remoteJwks, {
    issuer: config.issuer,
    ...(config.audience ? { audience: config.audience } : {}),
    algorithms: ["RS256"],
    clockTolerance: 5,
  });
  const claims = claimsSchema.parse(verified.payload);
  return {
    tenantId: TenantIdSchema.parse(claims.tenants[0]),
    userId: claims.sub ? UserIdSchema.parse(claims.sub) : undefined,
    capabilities: new Set(claims.permissions),
  };
}

export function requireCapability(
  principal: Principal,
  capability: z.infer<typeof CapabilitySchema>,
): void {
  if (!principal.capabilities.has(capability)) throw new AuthorizationError("missing capability");
}
