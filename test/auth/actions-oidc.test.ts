import { generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { authenticateActionsRun } from "../../src/actions-oidc";
import { actionsBinding, actionsToken, installActionsJwks, validClaims } from "./actions-fixture";

installActionsJwks();

describe("GitHub Actions reconciliation identity", () => {
  it("accepts only the exact persisted run and workflow binding", async () => {
    await expect(
      authenticateActionsRun(`Bearer ${await actionsToken()}`, actionsBinding),
    ).resolves.toBeUndefined();
  });

  it.each([
    ["issuer", { issuer: "https://issuer.invalid" }, validClaims],
    ["audience", { audience: "wrong" }, validClaims],
    ["expiry", { expired: true }, validClaims],
    ["repository", {}, { ...validClaims, repository_id: "10" }],
    ["event", {}, { ...validClaims, event_name: "push" }],
    ["run", {}, { ...validClaims, run_id: "78" }],
    ["actor", {}, { ...validClaims, actor_id: "1" }],
    [
      "workflow",
      {},
      { ...validClaims, workflow_ref: "owner/repo/.github/workflows/other.yaml@refs/heads/main" },
    ],
    [
      "workflow repository",
      {},
      {
        ...validClaims,
        workflow_ref: "attacker/repo/.github/workflows/monitor.yaml@refs/heads/main",
      },
    ],
  ])("rejects a wrong %s claim", async (_name, options, claims) => {
    await expect(
      authenticateActionsRun(`Bearer ${await actionsToken(claims, options)}`, actionsBinding),
    ).rejects.toThrow();
  });

  it("rejects a token signed by an untrusted key", async () => {
    const attacker = await generateKeyPair("RS256");
    await expect(
      authenticateActionsRun(
        `Bearer ${await actionsToken(validClaims, { key: attacker.privateKey })}`,
        actionsBinding,
      ),
    ).rejects.toThrow();
  });
});
