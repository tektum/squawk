-- Dispatch was the one pipeline stage with no durable outcome. A failure inside it
-- was swallowed into console.error, and a stage skipped for lack of subrequest budget
-- left no trace at all, so a cron that dispatched nothing looked identical to a cron
-- that dispatched successfully: both recorded only 'cron'/'completed'.
--
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt with 'dispatch'
-- added to the allowed kinds. Rows are preserved.
CREATE TABLE public_activity_rebuilt (
  event_sha256 TEXT PRIMARY KEY CHECK (length(event_sha256) = 64 AND event_sha256 NOT GLOB '*[^0-9a-f]*'),
  kind TEXT NOT NULL CHECK (kind IN ('webhook', 'cron', 'scan', 'advisory', 'dispatch')),
  outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'pending', 'ignored', 'completed', 'failed')),
  occurred_at INTEGER NOT NULL
);

INSERT INTO public_activity_rebuilt (event_sha256, kind, outcome, occurred_at)
SELECT event_sha256, kind, outcome, occurred_at FROM public_activity;

DROP TABLE public_activity;

ALTER TABLE public_activity_rebuilt RENAME TO public_activity;

CREATE INDEX idx_public_activity_recent
  ON public_activity(occurred_at DESC, event_sha256 DESC);
