# Squawk

Squawk is a Cloudflare Worker that receives GitHub-attested SBOM predicates, matches
components against OSV advisories, stores findings in D1, and exposes
authenticated findings and VEX workflows.

## Architecture

The Hono Worker validates inbound requests with Zod, uses D1 for tenant,
SBOM, finding, and delivery state, and calls a small Go/WASM matcher for
ecosystem-aware version comparison. OpenTofu provisions the Cloudflare
resources. The GitHub App receives `registry_package` events for tagged GHCR
indexes. The Worker verifies the webhook HMAC over untouched bytes, reads the
digest-bound SPDX Cosign bundles from public GHCR, and ingests one SBOM per platform.
Static OSV feeds are read from the public OSV storage bucket; component lookups use
the OSV query API. These endpoints are separate Worker bindings so published image
backfills cannot post queries to the static feed host.

Squawk intentionally does not verify Sigstore signatures locally. The signed GitHub
App webhook, immutable registry digests, and repository allowlist are the current
trust boundary; independent Sigstore verification is future hardening. Private and
internal GHCR packages require a separate registry credential and are not supported.

## Prerequisites and setup

Install [Devbox](https://www.jetify.com/docs/devbox), then run:

```sh
devbox run install
devbox shell
```

Devbox pins Bun, Go, OpenTofu, Go quality tools, Trivy, terraform-docs, and
TFLint. The critical packages support Linux (x86_64 and ARM64) and Apple
Silicon macOS. The OpenTofu provider lock covers Linux (x86_64 and ARM64) and
macOS (Intel and Apple Silicon). `devbox run install` uses the locked Bun
dependencies; a cold install needs network access to fetch locked Nix packages.

## Common commands

```sh
devbox run check          # all formatting, lint, security, test, and IaC checks
bun run format             # format TypeScript
bun run format:go          # format the Go matcher
bun run format:infra       # format OpenTofu
bun run build:matcher      # rebuild the WASM matcher
bun run check:infra        # OpenTofu, Trivy, docs, and advisory TFLint checks
```

## Testing

`bun run test:isolated` is the deterministic Workers-pool invocation. It runs
each test file in its own Vitest process with `fileParallelism: false` and one
worker, avoiding the known shared-pool startup hang without retries. The
matcher gate runs `go test -race -shuffle=on -count=1` after gofumpt,
golangci-lint v2, govulncheck, and module verification.

## Deployment and secrets

`Deploy Squawk` provisions D1, applies D1 migrations, deploys the advisory queue
consumer, and enables outbound finding dispatch by default. Set
`DISPATCH_ENABLED=false` for incident rollback. Store Cloudflare, human Descope,
and GitHub App values in
GitHub secrets or Cloudflare secrets only; never put them in `devbox.json`,
OpenTofu variables, or repository files. See [the rollout runbook](docs/runbook.md)
for the ordered deployment and rollback procedure.
