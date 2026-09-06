ALTER TABLE github_sources ADD COLUMN dispatch_schema_version INTEGER NOT NULL DEFAULT 1
  CHECK (dispatch_schema_version IN (1, 2));

CREATE TABLE image_inventory_generations (
  installation_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  logical_image_ref TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (installation_id, repository_id, logical_image_ref),
  FOREIGN KEY (installation_id, repository_id)
    REFERENCES github_sources(installation_id, repository_id)
);

CREATE TABLE advisory_feed_checks (
  checkpoint_id TEXT PRIMARY KEY CHECK (length(checkpoint_id) = 64 AND checkpoint_id NOT GLOB '*[^0-9a-f]*'),
  ecosystem TEXT NOT NULL,
  cursor_modified_at TEXT NOT NULL,
  checked_at INTEGER NOT NULL,
  completed_at INTEGER,
  discovery_complete INTEGER NOT NULL DEFAULT 0 CHECK (discovery_complete IN (0, 1)),
  status TEXT NOT NULL CHECK (status IN ('pending', 'complete', 'failed')),
  error TEXT
);

CREATE INDEX idx_advisory_feed_checks_latest
  ON advisory_feed_checks(ecosystem, checked_at DESC, checkpoint_id DESC);

CREATE TABLE image_reconciliation_state (
  installation_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  logical_image_ref TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
  state TEXT NOT NULL CHECK (state IN ('ready', 'blocked')),
  reason TEXT,
  checkpoint_id TEXT,
  applied_revision INTEGER NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
  inventory_generation INTEGER NOT NULL CHECK (inventory_generation >= 0),
  state_sha256 TEXT NOT NULL CHECK (length(state_sha256) = 64 AND state_sha256 NOT GLOB '*[^0-9a-f]*'),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (installation_id, repository_id, logical_image_ref),
  FOREIGN KEY (installation_id, repository_id)
    REFERENCES github_sources(installation_id, repository_id),
  FOREIGN KEY (checkpoint_id) REFERENCES reconciliation_checkpoints(checkpoint_id)
);

CREATE TABLE reconciliation_checkpoints (
  checkpoint_id TEXT PRIMARY KEY CHECK (length(checkpoint_id) = 64 AND checkpoint_id NOT GLOB '*[^0-9a-f]*'),
  installation_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  logical_image_ref TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  state TEXT NOT NULL CHECK (state IN ('ready', 'blocked')),
  reason TEXT,
  payload_json TEXT,
  payload_sha256 TEXT CHECK (payload_sha256 IS NULL OR (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*')),
  created_at INTEGER NOT NULL,
  UNIQUE (installation_id, repository_id, logical_image_ref, revision),
  FOREIGN KEY (installation_id, repository_id)
    REFERENCES github_sources(installation_id, repository_id)
);

CREATE TABLE reconciliation_deliveries (
  delivery_id TEXT PRIMARY KEY CHECK (length(delivery_id) = 64 AND delivery_id NOT GLOB '*[^0-9a-f]*'),
  installation_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  logical_image_ref TEXT NOT NULL,
  target_revision INTEGER NOT NULL CHECK (target_revision > 0),
  status TEXT NOT NULL CHECK (status IN ('pending', 'dispatched', 'acked', 'failed')),
  workflow_run_id TEXT,
  served_checkpoint_id TEXT,
  attempt_id TEXT,
  workflow_ref_sha256 TEXT CHECK (workflow_ref_sha256 IS NULL OR (length(workflow_ref_sha256) = 64 AND workflow_ref_sha256 NOT GLOB '*[^0-9a-f]*')),
  served_revision INTEGER,
  served_payload_sha256 TEXT,
  attempted_at INTEGER,
  error TEXT,
  created_at INTEGER NOT NULL,
  acked_at INTEGER,
  FOREIGN KEY (installation_id, repository_id)
    REFERENCES github_sources(installation_id, repository_id),
  FOREIGN KEY (served_checkpoint_id) REFERENCES reconciliation_checkpoints(checkpoint_id)
);

CREATE UNIQUE INDEX idx_reconciliation_delivery_run
  ON reconciliation_deliveries(workflow_run_id) WHERE workflow_run_id IS NOT NULL;
CREATE UNIQUE INDEX idx_reconciliation_delivery_active_image
  ON reconciliation_deliveries(installation_id, repository_id, logical_image_ref)
  WHERE status IN ('pending', 'dispatched');
CREATE INDEX idx_reconciliation_delivery_pending
  ON reconciliation_deliveries(status, created_at) WHERE status IN ('pending', 'dispatched');

CREATE TABLE authoritative_retirements (
  event_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  logical_image_ref TEXT NOT NULL,
  replacement_logical_image_ref TEXT NOT NULL,
  replacement_published_at INTEGER NOT NULL,
  replacement_run_url TEXT NOT NULL,
  retired_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (installation_id, repository_id, logical_image_ref),
  FOREIGN KEY (installation_id, repository_id)
    REFERENCES github_sources(installation_id, repository_id)
);

CREATE TRIGGER bump_generation_job_insert AFTER INSERT ON github_ingestion_jobs BEGIN
  INSERT INTO image_inventory_generations VALUES (NEW.installation_id,NEW.repository_id,NEW.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER bump_generation_job_update AFTER UPDATE ON github_ingestion_jobs BEGIN
  INSERT INTO image_inventory_generations VALUES (NEW.installation_id,NEW.repository_id,NEW.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER bump_generation_job_delete AFTER DELETE ON github_ingestion_jobs BEGIN
  INSERT INTO image_inventory_generations VALUES (OLD.installation_id,OLD.repository_id,OLD.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;

CREATE TRIGGER bump_generation_sbom_insert AFTER INSERT ON sboms
WHEN NEW.installation_id IS NOT NULL AND NEW.repository_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM github_sources g WHERE g.installation_id=NEW.installation_id AND g.repository_id=NEW.repository_id) BEGIN
  INSERT INTO image_inventory_generations VALUES (NEW.installation_id,NEW.repository_id,NEW.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER bump_generation_sbom_update AFTER UPDATE ON sboms
WHEN NEW.installation_id IS NOT NULL AND NEW.repository_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM github_sources g WHERE g.installation_id=NEW.installation_id AND g.repository_id=NEW.repository_id) BEGIN
  INSERT INTO image_inventory_generations VALUES (NEW.installation_id,NEW.repository_id,NEW.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER bump_generation_sbom_delete AFTER DELETE ON sboms
WHEN OLD.installation_id IS NOT NULL AND OLD.repository_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM github_sources g WHERE g.installation_id=OLD.installation_id AND g.repository_id=OLD.repository_id) BEGIN
  INSERT INTO image_inventory_generations VALUES (OLD.installation_id,OLD.repository_id,OLD.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;

CREATE TRIGGER bump_generation_component_insert AFTER INSERT ON components BEGIN
  INSERT INTO image_inventory_generations
  SELECT s.installation_id,s.repository_id,s.logical_image_ref,1,unixepoch()*1000
  FROM sboms s JOIN github_sources g ON g.installation_id=s.installation_id AND g.repository_id=s.repository_id
  WHERE s.id=NEW.sbom_id
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER bump_generation_component_update AFTER UPDATE ON components BEGIN
  INSERT INTO image_inventory_generations
  SELECT s.installation_id,s.repository_id,s.logical_image_ref,1,unixepoch()*1000
  FROM sboms s JOIN github_sources g ON g.installation_id=s.installation_id AND g.repository_id=s.repository_id
  WHERE s.id=NEW.sbom_id
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER bump_generation_component_delete AFTER DELETE ON components BEGIN
  INSERT INTO image_inventory_generations
  SELECT s.installation_id,s.repository_id,s.logical_image_ref,1,unixepoch()*1000
  FROM sboms s JOIN github_sources g ON g.installation_id=s.installation_id AND g.repository_id=s.repository_id
  WHERE s.id=OLD.sbom_id
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;

CREATE TRIGGER bump_generation_finding_insert AFTER INSERT ON findings BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.id=NEW.component_id AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_finding_delete AFTER DELETE ON findings BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.id=OLD.component_id AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;

CREATE TRIGGER bump_generation_matching_insert AFTER INSERT ON matching_errors BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.id=NEW.component_id AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_matching_update AFTER UPDATE ON matching_errors BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.id=NEW.component_id AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_matching_delete AFTER DELETE ON matching_errors BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.id=OLD.component_id AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;

CREATE TRIGGER bump_generation_feed_insert AFTER INSERT ON advisory_feed_checks BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.matchable=1 AND (c.ecosystem=NEW.ecosystem OR c.ecosystem LIKE NEW.ecosystem || ':%')
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_feed_update AFTER UPDATE ON advisory_feed_checks BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.matchable=1 AND (c.ecosystem=NEW.ecosystem OR c.ecosystem LIKE NEW.ecosystem || ':%')
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_feed_delete AFTER DELETE ON advisory_feed_checks BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.matchable=1 AND (c.ecosystem=OLD.ecosystem OR c.ecosystem LIKE OLD.ecosystem || ':%')
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;

CREATE TRIGGER bump_generation_job_advisory_insert AFTER INSERT ON osv_advisory_jobs BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.matchable=1 AND (c.ecosystem=NEW.ecosystem OR c.ecosystem LIKE NEW.ecosystem || ':%')
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_job_advisory_update AFTER UPDATE ON osv_advisory_jobs BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.matchable=1 AND (c.ecosystem=NEW.ecosystem OR c.ecosystem LIKE NEW.ecosystem || ':%')
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_job_advisory_delete AFTER DELETE ON osv_advisory_jobs BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.matchable=1 AND (c.ecosystem=OLD.ecosystem OR c.ecosystem LIKE OLD.ecosystem || ':%')
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;

CREATE TRIGGER bump_generation_vex_insert AFTER INSERT ON vex_statements BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE s.org_id=NEW.org_id AND c.package_name=NEW.package_name AND c.ecosystem=NEW.ecosystem
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;

CREATE TRIGGER bump_generation_vulnerability_insert AFTER INSERT ON vulnerabilities BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.package_name=NEW.package_name AND c.ecosystem=NEW.ecosystem
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_vulnerability_update AFTER UPDATE ON vulnerabilities BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.package_name=NEW.package_name AND c.ecosystem=NEW.ecosystem
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;
CREATE TRIGGER bump_generation_vulnerability_delete AFTER DELETE ON vulnerabilities BEGIN
  UPDATE image_inventory_generations SET generation=generation+1,updated_at=unixepoch()*1000
  WHERE EXISTS (SELECT 1 FROM components c JOIN sboms s ON s.id=c.sbom_id
    WHERE c.package_name=OLD.package_name AND c.ecosystem=OLD.ecosystem
      AND s.installation_id=image_inventory_generations.installation_id
      AND s.repository_id=image_inventory_generations.repository_id AND s.logical_image_ref=image_inventory_generations.logical_image_ref);
END;

CREATE TRIGGER bump_generation_retirement_insert AFTER INSERT ON authoritative_retirements BEGIN
  INSERT INTO image_inventory_generations VALUES (NEW.installation_id,NEW.repository_id,NEW.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER bump_generation_retirement_update AFTER UPDATE ON authoritative_retirements BEGIN
  INSERT INTO image_inventory_generations VALUES (NEW.installation_id,NEW.repository_id,NEW.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER bump_generation_retirement_delete AFTER DELETE ON authoritative_retirements BEGIN
  INSERT INTO image_inventory_generations VALUES (OLD.installation_id,OLD.repository_id,OLD.logical_image_ref,1,unixepoch()*1000)
  ON CONFLICT(installation_id,repository_id,logical_image_ref) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at;
END;
