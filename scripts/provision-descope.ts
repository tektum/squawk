import { z } from "zod";
import { type Capability, capabilityValues } from "../src/domain";
import { request } from "./descope-request";
import { type AuthorizationChange, reconcileAuthorization } from "./provision-authorization";

const capabilityDescriptions: Record<Capability, string> = {
  "operations.run": "Run scheduled operations",
  "pipeline.read": "Read pipeline, ingestion, and dispatch state",
  "sbom.manage": "Manage stored SBOM data",
  "findings.read": "Read tenant findings",
  "vex.write": "Write human VEX statements",
};

const scopeSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  values: z.array(z.string()).optional(),
  optional: z.boolean().optional(),
});
const inputSchema = z.object({
  baseUrl: z.string().url().default("https://api.descope.com"),
  projectId: z.string().min(1),
  managementKey: z.string().min(1),
  tenant: z.object({ id: z.string().min(1), name: z.string().min(1) }),
  application: z.object({
    name: z.string().min(1),
    description: z.string().optional(),
    permissionsScopes: z.array(scopeSchema),
    humanRole: z.object({ name: z.string().min(1), description: z.string().min(1) }),
  }),
});
const tenantSchema = z.object({ id: z.string(), name: z.string() });
const applicationSchema = z.object({
  id: z.string(),
  clientId: z.string(),
  name: z.string(),
  description: z.string().nullish(),
  permissionsScopes: z.array(scopeSchema),
});

type ProvisionInput = z.input<typeof inputSchema>;
type Change =
  | AuthorizationChange
  | "tenant:create"
  | "tenant:update"
  | "application:create"
  | "application:update";
}

export async function provisionDescope(rawInput: ProvisionInput): Promise<{
  readonly tenantId: string;
  readonly inboundAppId: string;
  readonly clientId: string;
  readonly changes: readonly Change[];
}> {
  const input = inputSchema.parse(rawInput);
  const authorization = `Bearer ${input.projectId}:${input.managementKey}`;
  const changes: Change[] = [];
  const tenantUrl = new URL("/v1/mgmt/tenant", input.baseUrl);
  tenantUrl.searchParams.set("id", input.tenant.id);
  const loadedTenant = await request(tenantUrl, authorization);
  if (loadedTenant.status === 404) {
    const created = await request(new URL("/v1/mgmt/tenant/create", input.baseUrl), authorization, {
      method: "POST",
      body: JSON.stringify(input.tenant),
    });
    if (!created.ok) throw new Error(`Descope tenant create failed (${created.status})`);
    changes.push("tenant:create");
  } else {
    if (!loadedTenant.ok) throw new Error(`Descope tenant load failed (${loadedTenant.status})`);
    const tenant = tenantSchema.parse(await loadedTenant.json());
    if (tenant.name !== input.tenant.name) {
      const updated = await request(
        new URL("/v1/mgmt/tenant/update", input.baseUrl),
        authorization,
        { method: "POST", body: JSON.stringify(input.tenant) },
      );
      if (!updated.ok) throw new Error(`Descope tenant update failed (${updated.status})`);
      changes.push("tenant:update");
    }
  }
  const applicationsResponse = await request(
    new URL("/v1/mgmt/thirdparty/apps/load", input.baseUrl),
    authorization,
  );
  if (!applicationsResponse.ok)
    throw new Error(`Descope application list failed (${applicationsResponse.status})`);
  const applications = z
    .object({ apps: z.array(applicationSchema) })
    .parse(await applicationsResponse.json()).apps;
  // Session validation does not check `aud`, because Descope mints it as the
  // project id that the project JWKS already binds. That holds only while the
  // project has exactly one inbound application, so the count — not a mutable
  // name — carries the invariant, and provisioning fails closed otherwise.
  if (applications.length > 1)
    throw new Error(
      `Descope project holds ${applications.length} inbound applications; audience validation is required before adding another`,
    );
  let application = applications[0];
  if (application && application.name !== input.application.name)
    throw new Error(
      `Descope project holds inbound application ${application.id} that Squawk does not own; audience validation is required before sharing a project`,
    );
  if (!application) {
    const created = await request(
      new URL("/v1/mgmt/thirdparty/app/create", input.baseUrl),
      authorization,
      { method: "POST", body: JSON.stringify(input.application) },
    );
    if (!created.ok) throw new Error(`Descope application create failed (${created.status})`);
    // The create response also carries the client secret in cleartext, which is
    // deliberately not parsed, logged or returned.
    const result = z.object({ id: z.string(), clientId: z.string() }).parse(await created.json());
    application = { id: result.id, clientId: result.clientId, ...input.application };
    changes.push("application:create");
  } else if (
    application.description !== (input.application.description ?? null) ||
    JSON.stringify(application.permissionsScopes) !==
      JSON.stringify(input.application.permissionsScopes)
  ) {
    const updated = await request(
      new URL("/v1/mgmt/thirdparty/app/update", input.baseUrl),
      authorization,
      { method: "POST", body: JSON.stringify({ id: application.id, ...input.application }) },
    );
    if (!updated.ok) throw new Error(`Descope application update failed (${updated.status})`);
    changes.push("application:update");
  }
  changes.push(
    ...(await reconcileAuthorization(input.baseUrl, authorization, {
      tenantId: input.tenant.id,
      role: input.application.humanRole,
      permissions: input.application.permissionsScopes.map((scope) => ({
        name: scope.name,
        description: scope.description,
      })),
    })),
  );
  return {
    tenantId: input.tenant.id,
    inboundAppId: application.id,
    clientId: application.clientId,
    changes,
  };
}

const cliInput = z.object({
  DESCOPE_MANAGEMENT_KEY: z.string().min(1),
  DESCOPE_PROJECT_ID: z.string().min(1),
  DESCOPE_TENANT_ID: z.string().min(1),
});

/* Single source of truth for the capability set: `capabilityValues` is what the Worker
   enforces, so provisioning derives scopes and the tenant role from the same list
   and a new capability cannot ship without an identity to carry it. */
export function squawkApplication(
  tenantId: string,
  projectId: string,
): z.input<typeof inputSchema>["application"] {
  return {
    name: `Squawk ${tenantId}`,
    description: `OAuth client for Descope project ${projectId}`,
    permissionsScopes: capabilityValues.map((capability) => ({
      name: capability,
      description: capabilityDescriptions[capability],
    })),
    humanRole: {
      name: "Squawk Operator",
      description: "Full control over Squawk through the admin panel and API",
    },
  };
}

if (import.meta.main) {
  const environment = cliInput.parse(process.env);
  const result = await provisionDescope({
    projectId: environment.DESCOPE_PROJECT_ID,
    managementKey: environment.DESCOPE_MANAGEMENT_KEY,
    tenant: { id: environment.DESCOPE_TENANT_ID, name: `Squawk ${environment.DESCOPE_TENANT_ID}` },
    application: squawkApplication(environment.DESCOPE_TENANT_ID, environment.DESCOPE_PROJECT_ID),
  });
  console.log(JSON.stringify(result));
}
