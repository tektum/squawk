# Squawk architecture

Status: approved implementation contract, 2026-08-02.

## Purpose

Squawk stores immutable platform SBOM identities, backfills historical OSV
findings, incrementally processes OSV updates every four hours, exposes human
findings and VEX APIs, and dispatches new unsuppressed findings to GitHub.

## Producer trust contract

The existing GitHub App subscribes to the `deployment` webhook. A valid ingest
delivery has `action=created`, `deployment.task=squawk-sbom`, a registered
installation/repository ID pair, and this versioned deployment payload:

- immutable platform image reference and immutable logical/index image reference;
- `linux/amd64` or `linux/arm64` and the repository attestation subject digest.

Squawk verifies the GitHub App webhook HMAC and maps the installation/repository
pair to a configured tenant. It then mints a repository-scoped App installation
token with only `attestations:read`, loads the subject digest's repository
attestation bundles, selects the matching repository, and schema-parses the
in-toto CycloneDX subject and predicate.

Squawk does not implement Sigstore verification. The GitHub App webhook plus
authenticated repository attestation retrieval are the inbound trust proof.
Independent Sigstore verification is future hardening, not current behavior.

Webhook HMAC-SHA-256 verification uses Web Crypto `subtle.verify` over the exact
received bytes before JSON parsing. Bodies are bounded before and while buffering.
Webhook secrets and raw bodies are never persisted.

## Durability and ingestion

`github_sources` maps immutable installation/repository IDs to a tenant ID.
`github_deliveries` durably records delivery GUID, deployment ID, source IDs,
subject digest, and terminal status. GitHub/API failures before acceptance leave
no receipt so GitHub can retry. Replays return success without duplicating SBOMs.

After trust verification, the existing CycloneDX parser, immutable D1 ingest,
OSV backfill, scheduled retry, finding lifecycle, VEX, and outbound dispatch
paths remain authoritative.

## Authentication and credentials

Producers use commit-pinned `actions/attest` v4 and `GITHUB_TOKEN` with
`attestations:write`, `deployments:write`, `packages:write`, and `contents:read`.
They have no Squawk URL, Squawk credential, Descope exchange, or configured
Squawk audience.

Descope is only for human `findings.read`, `vex.write`, and `sbom.manage` routes.
No machine grant, GitHub issuer trust, or `sbom.write` capability is provisioned.
The GitHub App private key and webhook HMAC secret exist only in Worker secrets.
