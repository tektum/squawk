import DescopeClient, { type AuthenticationInfo } from "@descope/node-sdk";
import { z } from "zod";
import {
  capabilityValues,
  CapabilitySchema,
  TenantIdSchema,
  UserIdSchema,
  type Principal,
} from "./domain";

const claimsSchema = z.object({ sub: z.string().min(1).optional() });

type AuthConfig = {
  readonly audience: string;
  readonly baseUrl?: string;
  readonly projectId: string;
};

type AuthClient = {
  readonly getJwtPermissions: (token: string, tenant?: string) => string[];
  readonly getTenants: (token: string) => string[];
  readonly validateSession: (
    token: string,
    options?: { readonly audience?: string | string[] },
  ) => Promise<AuthenticationInfo>;
};
const clients = new Map<string, AuthClient>();

function client(config: AuthConfig): AuthClient {
  const key = `${config.projectId}\u0000${config.baseUrl ?? ""}`;
  let value = clients.get(key);
  if (!value) {
    value = DescopeClient({
      projectId: config.projectId,
      ...(config.baseUrl ? { baseUrl: config.baseUrl } : {}),
    });
    clients.set(key, value);
  }
  return value;
}

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
  const sdk = client(config);
  let authInfo: AuthenticationInfo;
  try {
    authInfo = await sdk.validateSession(authorization.slice(7), {
      ...(config.audience ? { audience: config.audience } : {}),
    });
  } catch {
    throw new AuthenticationError("invalid session");
  }
  const tenants = sdk.getTenants(authInfo.jwt);
  if (tenants.length !== 1) throw new AuthenticationError("ambiguous tenant context");
  const tenantId = TenantIdSchema.parse(tenants[0]);
  const permissions = new Set(sdk.getJwtPermissions(authInfo.jwt, tenantId));
  const claims = claimsSchema.parse(authInfo.token);
  return {
    tenantId,
    userId: claims.sub ? UserIdSchema.parse(claims.sub) : undefined,
    capabilities: new Set(
      capabilityValues.filter((capability) => permissions.has(CapabilitySchema.parse(capability))),
    ),
  };
}

export function requireCapability(
  principal: Principal,
  capability: z.infer<typeof CapabilitySchema>,
): void {
  if (!principal.capabilities.has(capability)) throw new AuthorizationError("missing capability");
}
