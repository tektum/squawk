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

GitHub 5xx/rate-limit failures return a retryable webhook response and create no
delivery receipt. Inspect inbound state with
`SELECT * FROM github_deliveries ORDER BY created_at DESC`; failed backfills with
`SELECT * FROM sboms WHERE backfill_status='failed'`; matcher failures with
`SELECT * FROM matching_errors ORDER BY created_at DESC`; and outbound retries
with `SELECT * FROM dispatch_deliveries WHERE status IN ('pending','failed')`.

Rollback: set `DISPATCH_ENABLED=false`, disable only the App's `registry_package`
subscription if inbound processing must stop, and preserve D1 for investigation.
No static producer credential exists to revoke.
