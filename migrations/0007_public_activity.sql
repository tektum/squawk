CREATE TABLE public_activity (
  event_sha256 TEXT PRIMARY KEY CHECK (length(event_sha256) = 64 AND event_sha256 GLOB '[0-9a-f]*'),
  kind TEXT NOT NULL CHECK (kind IN ('webhook', 'cron', 'scan', 'advisory')),
  outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'pending', 'ignored', 'completed', 'failed')),
  occurred_at INTEGER NOT NULL
);

CREATE INDEX idx_public_activity_recent
  ON public_activity(occurred_at DESC, event_sha256 DESC);
