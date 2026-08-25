-- Dispatch targets the repository that published the image. The source rows already
-- identify that repository, so the per-tenant columns are removed and the source
-- carries the full name, workflow and ref to dispatch. The previous `workflow` and
-- `ref` columns were never read and held the webhook event name instead.
ALTER TABLE github_sources ADD COLUMN repository_full_name TEXT;

ALTER TABLE github_sources ADD COLUMN dispatch_workflow TEXT;

ALTER TABLE github_sources ADD COLUMN dispatch_ref TEXT;

ALTER TABLE github_sources DROP COLUMN workflow;

ALTER TABLE github_sources DROP COLUMN ref;

ALTER TABLE orgs DROP COLUMN github_dispatch_repo;

ALTER TABLE orgs DROP COLUMN github_dispatch_workflow;
