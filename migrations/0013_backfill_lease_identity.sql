ALTER TABLE sboms ADD COLUMN backfill_lease_sha256 TEXT
  CHECK (backfill_lease_sha256 IS NULL OR (length(backfill_lease_sha256) = 64 AND backfill_lease_sha256 NOT GLOB '*[^0-9a-f]*'));
