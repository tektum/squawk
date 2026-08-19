CREATE TABLE github_ingestion_jobs (
  subject_digest TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  logical_image_ref TEXT NOT NULL UNIQUE,
  delivery_id TEXT,
  deployment_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'failed')),
  attempted_at INTEGER,
  error TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (installation_id, repository_id)
    REFERENCES github_sources(installation_id, repository_id)
);

CREATE INDEX idx_github_ingestion_jobs_pending
  ON github_ingestion_jobs(status, created_at);
