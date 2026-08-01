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
    description: "GitHub OIDC inbound application",
    permissionsScopes: [{ name: "sbom.write", description: "Submit signed SBOM predicates" }],
    issuerTrust: {
      issuer: "https://token.actions.githubusercontent.com",
      subject: "repo:tektum/verity-images:*",
    },
    machineGrant: {
      grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer" as const,
      permissions: ["sbom.write"],
    },
    humanGrant: { permissions: ["findings.read", "vex.write"] },
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
      changes: [
        "tenant:create",
        "application:create",
        "issuer:create",
        "machine-grant:create",
        "human-grant:create",
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
    );
    await expect(provisionDescope(desired)).resolves.toMatchObject({
      changes: [
        "tenant:update",
        "application:update",
        "issuer:update",
        "machine-grant:update",
        "human-grant:update",
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
      http.get("https://api.descope.test/v1/mgmt/thirdparty/app/:path", ({ request }) =>
        HttpResponse.json({
          value: new URL(request.url).pathname.endsWith("issuer-trust")
            ? { appId: "app-1", ...desired.application.issuerTrust }
            : new URL(request.url).pathname.endsWith("machine-grant")
              ? { appId: "app-1", ...desired.application.machineGrant }
              : { tenantId: "tenant-1", ...desired.application.humanGrant },
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
});
