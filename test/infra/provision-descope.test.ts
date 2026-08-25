import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { provisionDescope } from "../../scripts/provision-descope";
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
  },
};

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
    );

    await expect(provisionDescope(desired)).resolves.toEqual({
      tenantId: "tenant-1",
      inboundAppId: "app-1",
      clientId: "client-1",
      changes: ["tenant:create", "application:create", "human-grant:create"],
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
    );
    await expect(provisionDescope(desired)).resolves.toMatchObject({
      changes: ["tenant:update", "application:update", "human-grant:update"],
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
});
