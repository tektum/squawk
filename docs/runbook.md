# Squawk rollout

1. Build the Worker bundle.
2. Apply only `cloudflare_d1_database.squawk` with nonsecret OpenTofu variables. `DESCOPE_MANAGEMENT_KEY` stays in the inherited CI environment and is never a Tofu variable, output, or state value.
3. Apply migrations to the selected D1 database.
4. Apply the remaining infrastructure dark with `DISPATCH_ENABLED=false`; this uploads the Worker, deploys it, creates the four-hour cron, and reconciles Descope.
5. Inject `GH_APP_ID`, `GH_APP_INSTALLATION_ID`, and `GH_APP_PRIVATE_KEY` with `wrangler secret put` through stdin.
6. Run `/health`, authenticated SBOM submission, findings query, and the verity-images receiver smoke flow.
7. Enable dispatch only after the cross-repository smoke receipt passes.

The deployed Worker compatibility date is the plan's `2026-08-01`. The pinned local Workers-pool runtime currently falls back to `2025-12-13` during tests; this is a local runtime limitation only and does not alter the deployed compatibility date.

Rollback: set `DISPATCH_ENABLED=false`, deploy Squawk, then run `scripts/rollback-monitor.sh ../verity-images-squawk` to restore the pinned baseline schedule and scanner response path.

D1 operations: inspect failed backfills with `SELECT * FROM sboms WHERE backfill_status='failed'`; matching failures with `SELECT * FROM matching_errors ORDER BY created_at DESC`; delivery retries with `SELECT * FROM dispatch_deliveries WHERE status IN ('pending','failed')`.
