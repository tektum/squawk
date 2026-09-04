import { createPrivateKey } from "node:crypto";
import { exportPKCS8, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { installationToken } from "../../src/github";
import { respond } from "../http";

describe("GitHub App private keys", () => {
  it("mints an installation token from GitHub's PKCS#1 PEM format", async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    const pkcs8 = await exportPKCS8(pair.privateKey);
    // GitHub downloads App keys as `BEGIN RSA PRIVATE KEY` (PKCS#1), while jose's
    // importPKCS8 rejects that format. This reproduces the production secret exactly.
    const pkcs1 = createPrivateKey(pkcs8).export({ format: "pem", type: "pkcs1" }).toString();
    respond({
      method: "POST",
      url: "https://api.github.com/app/installations/123/access_tokens",
      status: 201,
      body: { token: "installation-token" },
    });

    await expect(
      installationToken(
        { GH_APP_ID: "42", GH_APP_PRIVATE_KEY: pkcs1 },
        { installationId: "123", repositoryId: "9" },
        1_000_000,
      ),
    ).resolves.toBe("installation-token");
  });
});
