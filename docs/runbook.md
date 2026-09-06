# Squawk rollout

1. Configure the existing GitHub App webhook URL as
   `https://WORKER/webhooks/github`, content type `application/json`, with the
   `registry_package` event enabled. Grant Packages read for delivery subscription
   and retain the existing Actions permission used by outbound finding dispatch.
2. Add the same random webhook value to the App and the deployment environment as
   `GH_WEBHOOK_SECRET`. Keep `GH_APP_ID`, `GH_APP_INSTALLATION_ID`, and
   `GH_APP_PRIVATE_KEY` in Worker/GitHub secrets only.
3. Build the Worker, apply `cloudflare_d1_database.squawk` and both queue resources,
   apply all D1 migrations, then apply the remaining infrastructure with
   `DISPATCH_ENABLED=true`. Use `false` only for investigation or rollback.
`OSV_BASE_URL` must remain the OSV static-feed bucket and `OSV_API_URL` must point to
the OSV query API. Do not use the static-feed URL for `/v1/querybatch`.
4. Seed the immutable source mapping until a management UI exists:

```sh
bun scripts/seed-github-source.ts squawk-staging \
  INSTALLATION_ID REPOSITORY_ID DESCOPE_TENANT_ID
```

5. Publish a known public GHCR image from protected `main`. Confirm one accepted
   `github_deliveries` row and one complete `sboms` row per platform. Confirm a
   replay returns success without adding rows.
6. Exercise human findings, VEX, SBOM retirement, and one cross-repository dispatch
   receipt with a hosted Descope session.

Manually trigger the deployed scheduled pipeline with a hosted Descope human token
that includes `operations.run`:

```sh
curl -X POST https://WORKER/v1/operations/scheduled \
  -H "Authorization: Bearer $DESCOPE_ACCESS_TOKEN"
```

The endpoint returns `204` only after the scheduled pipeline completes. It rejects
missing tokens, principals without `operations.run`, and machine-only principals.

## Reconciliation v2 cutover

Do not change a source to schema v2 until the consumer and producer versions are
deployed together. The observed staging Worker origin is
`https://squawk-staging.omerc.workers.dev`; no production Worker origin is known.
Configure that exact origin, without a trailing slash, in the staging workflow's
trusted `SQUAWK_RECONCILIATION_ORIGIN`; never derive it from a dispatch payload.

After applying migrations, set `DISPATCH_ENABLED=false`. While dispatch is paused,
repair stored component identities and reingest current images from the authoritative registry index:

```sh
bun scripts/reconcile-ecosystems.ts squawk-staging
bun scripts/reconcile-github-images.ts squawk-staging CATALOG_URL INSTALLATION_ID REPOSITORY_ID
```

Wait for no ingestion jobs, no incomplete active SBOM backfills, and no incomplete
advisory jobs through each latest feed check. Every image must have one active amd64
and one active arm64 SBOM whose child digest equals the final OCI index descriptor.
`image_reconciliation_state` must be `ready`; Ubuntu or unknown deb coverage must be
explicitly supported rather than omitted. Old immutable `created_at` values are valid;
the feed check and evaluation must be current.

With dispatch still paused, verify D1 has no pending v1 delivery and the configured
GitHub workflow has no queued, requested, waiting, or in-progress legacy
`workflow_dispatch` run. Legacy accepted rows have no run ID, so both checks are
required. Verify the latest eligible checkpoint, then set the consumer repository
variable `SQUAWK_RECONCILIATION_ORIGIN` to the independently reviewed endpoint
`https://squawk-staging.omerc.workers.dev`; any other origin is rejected before
OIDC minting. While still paused, set the consumer's
`SQUAWK_RECONCILIATION_V2_REQUIRED=true` and that source's
`dispatch_schema_version=2`, then restore dispatch for the initial canary.
Version 2 requires the consumer flag to equal `true`; version 1 requires it not to.
Verify the first v2 run binds the returned GitHub `workflow_run_id`, fetches with
the exact OIDC claims, and acknowledges the exact served checkpoint. Keep v2
enabled only after this verification; otherwise pause dispatch. Drain in-flight
workflows before changing either protocol setting during rollback. A missing
acknowledgement or a newer blocked revision must leave the image unapplied and
retryable. Manual SBOM retirement is not authoritative retirement evidence and
must remain blocked.

## Admin panel

`https://WORKER/admin` runs the Descope `sign-up-or-in` flow and, once signed in,
exposes the same `/v1` surface the runbook drives by hand: inventory with backfill
errors, findings with VEX, ingestion/advisory/dispatch jobs, sources, and the manual
scheduled run. The shell is public; every row behind it needs a capability.

Deployment reconciles the project permissions and a tenant role named
`Squawk Operator` that carries all of them. Assigning that role to a person stays a
console decision, so provisioning never touches user records: in
**Descope console -> Users**, grant `Squawk Operator` in the Squawk tenant. Without
it a real operator authenticates and is then refused every view, because a session
JWT only carries permissions attached to a role.

Reads use `pipeline.read`; the panel hides controls the token cannot exercise, and
the Worker rejects them regardless.

GitHub 5xx/rate-limit failures return a retryable webhook response and create no
delivery receipt. Inspect inbound state with
`SELECT * FROM github_deliveries ORDER BY created_at DESC`; failed backfills with
`SELECT * FROM sboms WHERE backfill_status='failed'`; matcher failures with
`SELECT * FROM matching_errors ORDER BY created_at DESC`; and outbound retries
with `SELECT * FROM dispatch_deliveries WHERE status IN ('pending','failed')`.

Rollback: set `DISPATCH_ENABLED=false`, disable only the App's `registry_package`
subscription if inbound processing must stop, and preserve D1 for investigation.
No static producer credential exists to revoke.
