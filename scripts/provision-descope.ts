import { z } from "zod";

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
    humanGrant: z.object({ permissions: z.array(z.string().min(1)).min(1) }),
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
const resourceSchema = z.object({ value: z.unknown() });

type ProvisionInput = z.input<typeof inputSchema>;
type Change =
  | "tenant:create"
  | "tenant:update"
  | "application:create"
  | "application:update"
  | "human-grant:create"
  | "human-grant:update";

async function request(url: URL, authorization: string, init?: RequestInit): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: { authorization, "content-type": "application/json", ...init?.headers },
    signal: AbortSignal.timeout(10_000),
  });
}

async function reconcile(
  baseUrl: string,
  authorization: string,
  path: string,
  value: unknown,
  changes: Change[],
  created: Change,
  updated: Change,
): Promise<void> {
  const url = new URL(`/v1/mgmt/thirdparty/app/${path}`, baseUrl);
  const loaded = await request(url, authorization);
  if (loaded.status === 404) {
    const response = await request(new URL(`${url.pathname}/create`, baseUrl), authorization, {
      method: "POST",
      body: JSON.stringify(value),
    });
    if (!response.ok) throw new Error(`Descope ${path} create failed (${response.status})`);
    changes.push(created);
    return;
  }
  if (!loaded.ok) throw new Error(`Descope ${path} load failed (${loaded.status})`);
  if (JSON.stringify(resourceSchema.parse(await loaded.json()).value) !== JSON.stringify(value)) {
    const response = await request(new URL(`${url.pathname}/update`, baseUrl), authorization, {
      method: "POST",
      body: JSON.stringify(value),
    });
    if (!response.ok) throw new Error(`Descope ${path} update failed (${response.status})`);
    changes.push(updated);
  }
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
  // project id that the project JWKS already binds. That is only safe while the
  // project holds a single inbound application, so provisioning refuses to
  // continue once a second one exists.
  const foreign = applications.filter((candidate) => candidate.name !== input.application.name);
  if (foreign.length > 0)
    throw new Error(
      `Descope project holds ${applications.length} inbound applications; audience validation is required before adding another`,
    );
  let application = applications.find((candidate) => candidate.name === input.application.name);
  if (!application) {
    const created = await request(
      new URL("/v1/mgmt/thirdparty/app/create", input.baseUrl),
      authorization,
      { method: "POST", body: JSON.stringify(input.application) },
    );
    if (!created.ok) throw new Error(`Descope application create failed (${created.status})`);
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
  await reconcile(
    input.baseUrl,
    authorization,
    "human-grant",
    { tenantId: input.tenant.id, ...input.application.humanGrant },
    changes,
    "human-grant:create",
    "human-grant:update",
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

if (import.meta.main) {
  const environment = cliInput.parse(process.env);
  const result = await provisionDescope({
    projectId: environment.DESCOPE_PROJECT_ID,
    managementKey: environment.DESCOPE_MANAGEMENT_KEY,
    tenant: { id: environment.DESCOPE_TENANT_ID, name: `Squawk ${environment.DESCOPE_TENANT_ID}` },
    application: {
      name: `Squawk ${environment.DESCOPE_TENANT_ID}`,
      description: `OAuth client for Descope project ${environment.DESCOPE_PROJECT_ID}`,
      permissionsScopes: [
        { name: "operations.run", description: "Run scheduled operations" },
        { name: "sbom.manage", description: "Manage stored SBOM data" },
        { name: "findings.read", description: "Read tenant findings" },
        { name: "vex.write", description: "Write human VEX statements" },
      ],
      humanGrant: { permissions: ["operations.run", "sbom.manage", "findings.read", "vex.write"] },
    },
  });
  console.log(JSON.stringify(result));
}
