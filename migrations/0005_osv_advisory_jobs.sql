CREATE TABLE osv_advisory_jobs (
  ecosystem TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  modified_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'complete', 'failed')),
  attempted_at INTEGER,
  error TEXT,
  PRIMARY KEY (ecosystem, advisory_id)
);

CREATE INDEX idx_osv_advisory_jobs_pending
  ON osv_advisory_jobs(status, modified_at)
  WHERE status IN ('pending', 'failed');
