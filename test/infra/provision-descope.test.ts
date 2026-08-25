import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { provisionDescope, squawkApplication } from "../../scripts/provision-descope";
import { capabilityValues } from "../../src/domain";
import { server } from "../server";

const desired = {
  baseUrl: "https://api.descope.test",
  projectId: "project",
  managementKey: "management-key",
  tenant: { id: "tenant-1", name: "Squawk tenant" },
  application: {
    name: "Squawk tenant-1",
    description: "Human data management application",
    permissionsScopes: [
      { name: "operations.run", description: "Run scheduled operations" },
      { name: "sbom.manage", description: "Manage stored SBOM data" },
      { name: "findings.read", description: "Read findings" },
      { name: "vex.write", description: "Write VEX statements" },
    ],
    humanGrant: { permissions: ["operations.run", "sbom.manage", "findings.read", "vex.write"] },
    humanRole: { name: "Squawk Operator", description: "Full control over Squawk" },
  },
};

const projectPermissions = desired.application.permissionsScopes;
const tenantRole = {
  name: desired.application.humanRole.name,
  description: desired.application.humanRole.description,
  permissionNames: projectPermissions.map((permission) => permission.name),
  tenantId: desired.tenant.id,
};

function authorizationHandlers(
  permissions: readonly { name: string; description: string }[],
  roles: readonly unknown[],
) {
  return [
    http.get("https://api.descope.test/v1/mgmt/permission/all", () =>
      HttpResponse.json({ permissions }),
    ),
    http.get("https://api.descope.test/v1/mgmt/role/all", () => HttpResponse.json({ roles })),
    http.post(
      "https://api.descope.test/v1/mgmt/permission/:action",
      () => new HttpResponse(null, { status: 200 }),
    ),
    http.post(
      "https://api.descope.test/v1/mgmt/role/:action",
      () => new HttpResponse(null, { status: 200 }),
    ),
  ];
}

describe("Descope management provisioning", () => {
  beforeEach(() => undefined);

  it("creates a missing tenant and inbound application with documented wire shapes", async () => {
    server.use(
      http.get(
        "https://api.descope.test/v1/mgmt/tenant",
        () => new HttpResponse(null, { status: 404 }),
      ),
      http.post("https://api.descope.test/v1/mgmt/tenant/create", async ({ request }) => {
        expect(await request.json()).toEqual(desired.tenant);
        return HttpResponse.json({ id: "tenant-1" });
      }),
      http.get("https://api.descope.test/v1/mgmt/thirdparty/apps/load", () =>
        HttpResponse.json({ apps: [] }),
      ),
      http.post("https://api.descope.test/v1/mgmt/thirdparty/app/create", async ({ request }) => {
        expect(await request.json()).toEqual(desired.application);
        return HttpResponse.json({ id: "app-1", clientId: "client-1", cleartext: "discarded" });
      }),
      http.get(
        "https://api.descope.test/v1/mgmt/thirdparty/app/:path",
        () => new HttpResponse(null, { status: 404 }),
      ),
      http.post(
        "https://api.descope.test/v1/mgmt/thirdparty/app/:path/create",
        () => new HttpResponse(null, { status: 200 }),
      ),
      ...authorizationHandlers([], []),
    );

    await expect(provisionDescope(desired)).resolves.toEqual({
      tenantId: "tenant-1",
      inboundAppId: "app-1",
      clientId: "client-1",
      changes: [
        "tenant:create",
        "application:create",
        "human-grant:create",
        ...projectPermissions.map(() => "permission:create"),
        "role:create",
      ],
    });
  });

  it("updates drift and performs no writes when desired state already matches", async () => {
    server.use(
      http.get("https://api.descope.test/v1/mgmt/tenant", () =>
        HttpResponse.json({ id: "tenant-1", name: "Old" }),
      ),
      http.post(
        "https://api.descope.test/v1/mgmt/tenant/update",
        () => new HttpResponse(null, { status: 200 }),
      ),
      http.get("https://api.descope.test/v1/mgmt/thirdparty/apps/load", () =>
        HttpResponse.json({
          apps: [
            {
              id: "app-1",
              clientId: "client-1",
              name: desired.application.name,
              description: "Old",
              permissionsScopes: [],
            },
          ],
        }),
      ),
      http.post(
        "https://api.descope.test/v1/mgmt/thirdparty/app/update",
        () => new HttpResponse(null, { status: 200 }),
      ),
      http.get("https://api.descope.test/v1/mgmt/thirdparty/app/:path", () =>
        HttpResponse.json({ value: {} }),
      ),
      http.post(
        "https://api.descope.test/v1/mgmt/thirdparty/app/:path/update",
        () => new HttpResponse(null, { status: 200 }),
      ),
      ...authorizationHandlers(
        projectPermissions.map((permission, index) =>
          index === 0 ? { ...permission, description: "Old" } : permission,
        ),
        [{ ...tenantRole, permissionNames: ["operations.run"] }],
      ),
    );
    await expect(provisionDescope(desired)).resolves.toMatchObject({
      changes: [
        "tenant:update",
        "application:update",
        "human-grant:update",
        "permission:update",
        "role:update",
      ],
    });

    server.use(
      http.get("https://api.descope.test/v1/mgmt/tenant?id=tenant-1", () =>
        HttpResponse.json(desired.tenant),
      ),
      http.get("https://api.descope.test/v1/mgmt/thirdparty/apps/load", () =>
        HttpResponse.json({
          apps: [{ id: "app-1", clientId: "client-1", ...desired.application }],
        }),
      ),
      http.get("https://api.descope.test/v1/mgmt/thirdparty/app/:path", () =>
        HttpResponse.json({
          value: { tenantId: "tenant-1", ...desired.application.humanGrant },
        }),
      ),
      ...authorizationHandlers(projectPermissions, [tenantRole]),
    );
    await expect(provisionDescope(desired)).resolves.toMatchObject({ changes: [] });
  });

  it("fails closed without leaking the management key", async () => {
    server.use(
      http.get(
        "https://api.descope.test/v1/mgmt/tenant",
        () => new HttpResponse(null, { status: 401 }),
      ),
    );
    const error = await provisionDescope(desired).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain("management-key");
  });

  it("refuses to provision when the project holds another inbound application", async () => {
    // Session validation skips the aud claim, which is only sound while this
    // project has one inbound application.
    server.use(
      http.get("https://api.descope.test/v1/mgmt/tenant", () =>
        HttpResponse.json({ id: "tenant-1", name: desired.tenant.name }),
      ),
      http.get("https://api.descope.test/v1/mgmt/thirdparty/apps/load", () =>
        HttpResponse.json({
          apps: [
            { id: "app-1", clientId: "client-1", ...desired.application },
            {
              id: "app-2",
              clientId: "client-2",
              name: "Another app",
              description: "someone else",
              permissionsScopes: [],
            },
          ],
        }),
      ),
    );

    await expect(provisionDescope(desired)).rejects.toThrow(
      /holds 2 inbound applications; audience validation is required/,
    );
  });

  it("refuses a sole inbound application Squawk does not own", async () => {
    // Names are mutable, so uniqueness is carried by the count; ownership of the
    // single application is still checked before it is reconciled.
    server.use(
      http.get("https://api.descope.test/v1/mgmt/tenant", () =>
        HttpResponse.json({ id: "tenant-1", name: desired.tenant.name }),
      ),
      http.get("https://api.descope.test/v1/mgmt/thirdparty/apps/load", () =>
        HttpResponse.json({
          apps: [
            {
              id: "app-9",
              clientId: "client-9",
              name: "Someone else's app",
              description: "not squawk",
              permissionsScopes: [],
            },
          ],
        }),
      ),
    );

    await expect(provisionDescope(desired)).rejects.toThrow(
      /inbound application app-9 that Squawk does not own/,
    );
  });

  it("reports an unavailable grant endpoint instead of failing the deploy", async () => {
    // The application and its scopes provision fine; only the grant sub-resource
    // route is absent, which must not break the whole apply.
    server.use(
      http.get("https://api.descope.test/v1/mgmt/tenant", () =>
        HttpResponse.json({ id: "tenant-1", name: desired.tenant.name }),
      ),
      http.get("https://api.descope.test/v1/mgmt/thirdparty/apps/load", () =>
        HttpResponse.json({
          apps: [{ id: "app-1", clientId: "client-1", ...desired.application }],
        }),
      ),
      http.get(
        "https://api.descope.test/v1/mgmt/thirdparty/app/human-grant",
        () => new HttpResponse(null, { status: 404 }),
      ),
      http.post(
        "https://api.descope.test/v1/mgmt/thirdparty/app/human-grant/create",
        () => new HttpResponse(null, { status: 404 }),
      ),
      ...authorizationHandlers(projectPermissions, [tenantRole]),
    );

    await expect(provisionDescope(desired)).resolves.toMatchObject({
      changes: ["human-grant:unavailable"],
    });
  });

  it("refuses to send the management key to a plaintext endpoint", async () => {
    await expect(
      provisionDescope({ ...desired, baseUrl: "http://api.descope.test" }),
    ).rejects.toThrow(/must use https/);
  });

  it("grants the tenant role every capability the Worker enforces", () => {
    const application = squawkApplication("tenant-1", "project");

    expect(application.permissionsScopes.map((scope) => scope.name)).toEqual([...capabilityValues]);
    expect(application.humanGrant.permissions).toEqual([...capabilityValues]);
    expect(application.humanRole.name).toBe("Squawk Operator");
  });
});
