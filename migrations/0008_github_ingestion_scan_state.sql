ALTER TABLE github_ingestion_jobs ADD COLUMN saw_spdx INTEGER NOT NULL DEFAULT 0
  CHECK (saw_spdx IN (0, 1));
