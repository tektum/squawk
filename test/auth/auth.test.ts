import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { http, HttpResponse } from "msw";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { authenticate, AuthorizationError, requireCapability } from "../../src/auth";
import { server } from "../server";

const issuer = "https://issuer.test";
const audience = "squawk-audience";

describe("JOSE authentication", () => {
  let privateKey: CryptoKey;
  let publicJwk: JsonWebKey;

  beforeAll(async () => {
    const pair = await generateKeyPair("RS256");
    privateKey = pair.privateKey;
    publicJwk = await exportJWK(pair.publicKey);
  });

  beforeEach(() => {
    server.use(
      http.get(`${issuer}/.well-known/openid-configuration`, () =>
        HttpResponse.json({ issuer, jwks_uri: `${issuer}/jwks` }),
      ),
      http.get(`${issuer}/jwks`, () =>
        HttpResponse.json({ keys: [{ ...publicJwk, kid: "key-1", alg: "RS256", use: "sig" }] }),
      ),
    );
  });

  async function token(
    claims: Record<string, unknown>,
    targetAudience = audience,
  ): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "key-1" })
      .setIssuer(issuer)
      .setAudience(targetAudience)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  }

  it("accepts a machine principal with the SBOM capability", async () => {
    const principal = await authenticate(
      `Bearer ${await token({ tenants: ["tenant-1"], permissions: ["sbom.write"] })}`,
      {
        issuer,
        audience,
        discoveryUrl: `${issuer}/.well-known/openid-configuration`,
      },
    );

    expect(principal.userId).toBeUndefined();
    expect(() => requireCapability(principal, "sbom.write")).not.toThrow();
    expect(() => requireCapability(principal, "vex.write")).toThrow(AuthorizationError);
  });

  it("accepts a hosted human with query and VEX capabilities", async () => {
    const principal = await authenticate(
      `Bearer ${await token({ sub: "user-1", tenants: ["tenant-1"], permissions: ["findings.read", "vex.write"] })}`,
      {
        issuer,
        audience,
        discoveryUrl: `${issuer}/.well-known/openid-configuration`,
      },
    );

    expect(principal.userId).toBe("user-1");
    expect(() => requireCapability(principal, "vex.write")).not.toThrow();
  });

  it("rejects wrong audience and ambiguous tenant context", async () => {
    await expect(
      authenticate(`Bearer ${await token({ tenants: ["tenant-1"], permissions: [] }, "wrong")}`, {
        issuer,
        audience,
        discoveryUrl: `${issuer}/.well-known/openid-configuration`,
      }),
    ).rejects.toThrow();
    await expect(
      authenticate(`Bearer ${await token({ tenants: ["one", "two"], permissions: [] })}`, {
        issuer,
        audience,
        discoveryUrl: `${issuer}/.well-known/openid-configuration`,
      }),
    ).rejects.toThrow();
  });

  it("rejects expired tokens, bad signatures, and algorithm confusion", async () => {
    const expired = await new SignJWT({ tenants: ["tenant-1"], permissions: [] })
      .setProtectedHeader({ alg: "RS256", kid: "key-1" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt(1)
      .setExpirationTime(2)
      .sign(privateKey);
    await expect(
      authenticate(`Bearer ${expired}`, {
        issuer,
        audience,
        discoveryUrl: `${issuer}/.well-known/openid-configuration`,
      }),
    ).rejects.toThrow();

    const attacker = await generateKeyPair("RS256");
    const forged = await new SignJWT({ tenants: ["tenant-1"], permissions: [] })
      .setProtectedHeader({ alg: "RS256", kid: "key-1" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(attacker.privateKey);
    await expect(
      authenticate(`Bearer ${forged}`, {
        issuer,
        audience,
        discoveryUrl: `${issuer}/.well-known/openid-configuration`,
      }),
    ).rejects.toThrow();

    const confused = await new SignJWT({ tenants: ["tenant-1"], permissions: [] })
      .setProtectedHeader({ alg: "HS256", kid: "key-1" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode("not-an-rsa-key-but-long-enough"));
    await expect(
      authenticate(`Bearer ${confused}`, {
        issuer,
        audience,
        discoveryUrl: `${issuer}/.well-known/openid-configuration`,
      }),
    ).rejects.toThrow();
  });

  it("loads a rotated JWKS key without a Worker restart", async () => {
    const rotationIssuer = "https://rotate.test";
    const rotated = await generateKeyPair("RS256");
    const rotatedJwk = await exportJWK(rotated.publicKey);
    server.use(
      http.get(`${rotationIssuer}/.well-known/openid-configuration`, () =>
        HttpResponse.json({ issuer: rotationIssuer, jwks_uri: `${rotationIssuer}/jwks` }),
      ),
      http.get(
        `${rotationIssuer}/jwks`,
        () =>
          HttpResponse.json({ keys: [{ ...publicJwk, kid: "key-1", alg: "RS256", use: "sig" }] }),
        { once: true },
      ),
      http.get(`${rotationIssuer}/jwks`, () =>
        HttpResponse.json({
          keys: [
            { ...publicJwk, kid: "key-1", alg: "RS256", use: "sig" },
            { ...rotatedJwk, kid: "key-2", alg: "RS256", use: "sig" },
          ],
        }),
      ),
    );
    const original = await new SignJWT({ tenants: ["tenant-1"], permissions: [] })
      .setProtectedHeader({ alg: "RS256", kid: "key-1" })
      .setIssuer(rotationIssuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
    await authenticate(`Bearer ${original}`, {
      issuer: rotationIssuer,
      audience,
      discoveryUrl: `${rotationIssuer}/.well-known/openid-configuration`,
    });
    const rotatedToken = await new SignJWT({ tenants: ["tenant-1"], permissions: [] })
      .setProtectedHeader({ alg: "RS256", kid: "key-2" })
      .setIssuer(rotationIssuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(rotated.privateKey);

    await expect(
      authenticate(`Bearer ${rotatedToken}`, {
        issuer: rotationIssuer,
        audience,
        discoveryUrl: `${rotationIssuer}/.well-known/openid-configuration`,
      }),
    ).resolves.toMatchObject({ tenantId: "tenant-1" });
  });
});
