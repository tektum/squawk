import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { http, HttpResponse } from "msw";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { authenticate, requireCapability } from "../../src/auth";
import { server } from "../server";

const baseUrl = "https://api.descope.test";
const projectId = "P3HPBhYIOusbZgLWvcVqLbmmnv1i";
const audience = "squawk-audience";

describe("Descope authentication", () => {
  let privateKey: CryptoKey;
  let publicJwk: JsonWebKey;

  beforeAll(async () => {
    const pair = await generateKeyPair("RS256");
    privateKey = pair.privateKey;
    publicJwk = await exportJWK(pair.publicKey);
  });

  beforeEach(() => {
    server.use(
      http.get(`${baseUrl}/v2/keys/${projectId}`, () =>
        HttpResponse.json({ keys: [{ ...publicJwk, kid: "key-1", alg: "RS256", use: "sig" }] }),
      ),
    );
  });

  async function token(
    tenants: Record<string, { permissions: string[]; roles: string[] }>,
    options: {
      readonly audience?: string;
      readonly issuer?: string;
      readonly subject?: string;
    } = {},
  ): Promise<string> {
    return new SignJWT({ tenants })
      .setProtectedHeader({ alg: "RS256", kid: "key-1" })
      .setIssuer(options.issuer ?? projectId)
      .setAudience(options.audience ?? audience)
      .setSubject(options.subject ?? "user-1")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  }

  const config = { audience, baseUrl, projectId };

  it("accepts tenant-scoped Descope permissions", async () => {
    const principal = await authenticate(
      `Bearer ${await token({ tenant: { permissions: ["findings.read", "vex.write"], roles: ["Tenant Admin"] } })}`,
      config,
    );

    expect(principal).toMatchObject({ tenantId: "tenant", userId: "user-1" });
    expect(() => requireCapability(principal, "vex.write")).not.toThrow();
  });

  it("accepts the real Descope tenant claim shape for scheduled operations", async () => {
    const principal = await authenticate(
      `Bearer ${await token({ T3HPBllDcX3I1zI7FqDhYEWHEKHd: { permissions: ["operations.run"], roles: ["Tenant Admin"] } })}`,
      config,
    );

    expect(principal.tenantId).toBe("T3HPBllDcX3I1zI7FqDhYEWHEKHd");
    expect(() => requireCapability(principal, "operations.run")).not.toThrow();
  });

  it("ignores unsupported permissions", async () => {
    const principal = await authenticate(
      `Bearer ${await token({ tenant: { permissions: ["SSO Admin", "sbom.write"], roles: [] } })}`,
      config,
    );

    expect(principal.capabilities.size).toBe(0);
  });

  it("rejects wrong audience and ambiguous tenant context", async () => {
    await expect(
      authenticate(
        `Bearer ${await token({ tenant: { permissions: [], roles: [] } }, { audience: "wrong" })}`,
        config,
      ),
    ).rejects.toThrow("invalid session");
    await expect(
      authenticate(
        `Bearer ${await token({ one: { permissions: [], roles: [] }, two: { permissions: [], roles: [] } })}`,
        config,
      ),
    ).rejects.toThrow("ambiguous tenant context");
  });

  it("rejects expired tokens and bad signatures", async () => {
    const expired = await new SignJWT({ tenants: { tenant: { permissions: [], roles: [] } } })
      .setProtectedHeader({ alg: "RS256", kid: "key-1" })
      .setIssuer(projectId)
      .setAudience(audience)
      .setIssuedAt(1)
      .setExpirationTime(2)
      .sign(privateKey);
    await expect(authenticate(`Bearer ${expired}`, config)).rejects.toThrow("invalid session");

    const attacker = await generateKeyPair("RS256");
    const forged = await new SignJWT({ tenants: { tenant: { permissions: [], roles: [] } } })
      .setProtectedHeader({ alg: "RS256", kid: "key-1" })
      .setIssuer(projectId)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(attacker.privateKey);
    await expect(authenticate(`Bearer ${forged}`, config)).rejects.toThrow("invalid session");
  });
});
