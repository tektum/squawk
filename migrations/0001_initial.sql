PRAGMA foreign_keys = ON;

CREATE TABLE orgs (
  descope_tenant_id TEXT PRIMARY KEY,
  descope_inbound_app_id TEXT NOT NULL,
  github_dispatch_repo TEXT NOT NULL,
  github_dispatch_workflow TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE sboms (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(descope_tenant_id),
  image_ref TEXT NOT NULL,
  logical_image_ref TEXT NOT NULL,
  platform TEXT NOT NULL,
  predicate_sha256 TEXT NOT NULL,
  backfill_status TEXT NOT NULL CHECK (backfill_status IN ('pending', 'running', 'complete', 'failed')),
  backfill_attempted_at INTEGER,
  backfill_error TEXT,
  created_at INTEGER NOT NULL,
  retired_at INTEGER,
  UNIQUE (org_id, image_ref, platform)
);

CREATE TABLE components (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sbom_id TEXT NOT NULL REFERENCES sboms(id),
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  version TEXT NOT NULL,
  purl TEXT NOT NULL,
  matchable INTEGER NOT NULL CHECK (matchable IN (0, 1)),
  UNIQUE (sbom_id, package_name, ecosystem, version, purl)
);

CREATE TABLE vulnerabilities (
  id TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  affected_ranges TEXT NOT NULL,
  severity TEXT,
  summary TEXT,
  modified_at TEXT NOT NULL,
  PRIMARY KEY (id, ecosystem, package_name)
);

CREATE TABLE findings (
  org_id TEXT NOT NULL REFERENCES orgs(descope_tenant_id),
  component_id INTEGER NOT NULL REFERENCES components(id),
  vuln_id TEXT NOT NULL,
  detected_at INTEGER NOT NULL,
  dispatched_at INTEGER,
  PRIMARY KEY (component_id, vuln_id)
);

CREATE TABLE vex_statements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL REFERENCES orgs(descope_tenant_id),
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  vuln_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation')),
  justification TEXT,
  created_by_descope_user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE sync_cursors (
  ecosystem TEXT PRIMARY KEY,
  last_synced_at TEXT NOT NULL,
  boundary_ids TEXT NOT NULL DEFAULT '',
  continuation_id TEXT,
  ecosystems_cached_at INTEGER
);

CREATE TABLE osv_ecosystems (
  ecosystem TEXT PRIMARY KEY,
  cached_at INTEGER NOT NULL
);

CREATE TABLE matching_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  component_id INTEGER NOT NULL REFERENCES components(id),
  vuln_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE dispatch_deliveries (
  delivery_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(descope_tenant_id),
  logical_image_ref TEXT NOT NULL,
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  version TEXT NOT NULL,
  vuln_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'failed')),
  attempted_at INTEGER,
  error TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_components_active_package ON components(package_name, ecosystem) WHERE matchable = 1;
CREATE INDEX idx_sboms_pending_backfill ON sboms(backfill_status) WHERE retired_at IS NULL;
CREATE INDEX idx_findings_org_current ON findings(org_id, dispatched_at);
CREATE INDEX idx_vex_latest ON vex_statements(org_id, package_name, ecosystem, vuln_id, created_at DESC, id DESC);
CREATE INDEX idx_dispatch_pending ON dispatch_deliveries(status) WHERE status IN ('pending', 'failed');
CREATE INDEX idx_ecosystems_active ON osv_ecosystems(ecosystem);
