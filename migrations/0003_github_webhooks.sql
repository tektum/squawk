CREATE TABLE github_sources (
  installation_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  org_id TEXT NOT NULL REFERENCES orgs(descope_tenant_id),
  workflow TEXT NOT NULL,
  ref TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (installation_id, repository_id)
);

CREATE TABLE github_deliveries (
  delivery_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  statement_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('accepted', 'rejected')),
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  FOREIGN KEY (installation_id, repository_id)
    REFERENCES github_sources(installation_id, repository_id)
);

CREATE INDEX idx_github_deliveries_source
  ON github_deliveries(installation_id, repository_id, created_at DESC);
