import DescopeClient, { type AuthenticationInfo } from "@descope/node-sdk";
import { z } from "zod";
import { sha256 } from "./digest";
import {
  CapabilitySchema,
  capabilityValues,
  type Principal,
  TenantIdSchema,
  UserIdSchema,
} from "./domain";

const claimsSchema = z.object({ sub: z.string().min(1).optional() });
const authorizationSchema = z
  .string()
  .regex(/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
  .transform((value) => value.slice("Bearer ".length));
const configSchema = z.object({
  baseUrl: z.string().url().startsWith("https://").optional(),
  projectId: z.string().min(1),
});

type AuthConfig = {
  readonly baseUrl?: string;
  readonly projectId: string;
};

type AuthClient = {
  readonly getJwtPermissions: (token: string, tenant?: string) => string[];
  readonly getTenants: (token: string) => string[];
  readonly validateSession: (token: string) => Promise<AuthenticationInfo>;
};
const clients = new Map<string, AuthClient>();

async function client(config: AuthConfig): Promise<AuthClient> {
  const parsed = configSchema.parse(config);
  const key = await sha256(JSON.stringify(parsed));
  let value = clients.get(key);
  if (!value) {
    value = DescopeClient({
      projectId: parsed.projectId,
      ...(parsed.baseUrl ? { baseUrl: parsed.baseUrl } : {}),
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
  let token: string;
  let parsed: z.infer<typeof configSchema>;
  try {
    token = authorizationSchema.parse(authorization);
    parsed = configSchema.parse(config);
  } catch {
    throw new AuthenticationError("invalid authentication input");
  }
  const sdk = await client({
    projectId: parsed.projectId,
    ...(parsed.baseUrl ? { baseUrl: parsed.baseUrl } : {}),
  });
  let authInfo: AuthenticationInfo;
  try {
    authInfo = await sdk.validateSession(token);
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

export function principalForOrg(principal: Principal, orgId: string): Principal {
  if (principal.tenantId !== TenantIdSchema.parse(orgId))
    throw new AuthorizationError("wrong tenant");
  return principal;
}
