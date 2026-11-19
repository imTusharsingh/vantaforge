PRAGMA foreign_keys = ON;

CREATE TABLE assets (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  kind TEXT NOT NULL DEFAULT 'real_footage' CHECK (kind IN ('real_footage')),
  storage_key TEXT NOT NULL UNIQUE,
  media_type TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  bytes INTEGER NOT NULL CHECK (bytes > 0),
  checksum TEXT,
  duration_seconds REAL,
  width INTEGER,
  height INTEGER,
  metadata TEXT NOT NULL DEFAULT '{}',
  license_type TEXT,
  license_id TEXT,
  source_url TEXT,
  rights_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (rights_confirmed IN (0, 1)),
  attribution_required INTEGER NOT NULL DEFAULT 0 CHECK (attribution_required IN (0, 1)),
  attribution_text TEXT,
  upload_token_hash TEXT UNIQUE,
  upload_expires_at TEXT,
  scan_status TEXT NOT NULL DEFAULT 'pending' CHECK (scan_status IN ('pending', 'unavailable', 'clean', 'blocked')),
  licensing_status TEXT NOT NULL DEFAULT 'pending' CHECK (licensing_status IN ('pending', 'valid', 'blocked')),
  status TEXT NOT NULL DEFAULT 'pending_upload' CHECK (status IN ('pending_upload', 'pending_scan', 'ready', 'blocked')),
  blocked_reason TEXT,
  created_by_user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX assets_workspace_idx ON assets(workspace_id, created_at DESC);
CREATE INDEX assets_status_idx ON assets(workspace_id, status);

CREATE TABLE asset_references (
  id TEXT PRIMARY KEY NOT NULL,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  source_url TEXT,
  license_id TEXT,
  expires_at TEXT,
  attribution_required INTEGER NOT NULL DEFAULT 0 CHECK (attribution_required IN (0, 1)),
  usage_scope TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX asset_references_asset_idx ON asset_references(asset_id);
