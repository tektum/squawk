ALTER TABLE github_deliveries ADD COLUMN deployment_id TEXT;
ALTER TABLE github_deliveries ADD COLUMN subject_digest TEXT;
UPDATE github_deliveries SET subject_digest=statement_sha256 WHERE subject_digest IS NULL;
CREATE UNIQUE INDEX idx_github_deliveries_deployment_id
  ON github_deliveries(deployment_id)
  WHERE deployment_id IS NOT NULL;
