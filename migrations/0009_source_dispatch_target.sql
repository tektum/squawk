-- Dispatch targets the repository that published the image. Each SBOM records the
-- GitHub source that produced it, so a digest published by two sources cannot route
-- a finding to the wrong repository, and the source carries the workflow and ref to
-- dispatch. Repository paths are resolved transiently at dispatch time from the
-- immutable repository ID, so no external repository name is stored. The previous
-- `workflow` and `ref` columns were never read and held the webhook event name.
ALTER TABLE sboms ADD COLUMN installation_id TEXT;

ALTER TABLE sboms ADD COLUMN repository_id TEXT;

ALTER TABLE github_sources ADD COLUMN dispatch_workflow TEXT;

ALTER TABLE github_sources ADD COLUMN dispatch_ref TEXT;

ALTER TABLE github_sources DROP COLUMN workflow;

ALTER TABLE github_sources DROP COLUMN ref;

ALTER TABLE orgs DROP COLUMN github_dispatch_repo;

ALTER TABLE orgs DROP COLUMN github_dispatch_workflow;

CREATE INDEX idx_sboms_source ON sboms(installation_id, repository_id);
