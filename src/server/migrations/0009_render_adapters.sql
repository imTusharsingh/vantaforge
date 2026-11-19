PRAGMA foreign_keys = ON;

CREATE TABLE production_provider_capabilities (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  capability TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('available', 'unavailable')),
  blocker_code TEXT,
  checked_at TEXT NOT NULL,
  UNIQUE (workspace_id, provider, capability)
);
CREATE INDEX production_provider_capabilities_workspace_idx ON production_provider_capabilities(workspace_id, provider);

CREATE TABLE production_render_attempts (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  production_job_id TEXT NOT NULL REFERENCES production_jobs(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  provider TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('planned', 'blocked', 'submitted', 'processing', 'succeeded', 'failed', 'cancelled')),
  blocker_code TEXT,
  provider_job_id TEXT,
  output_asset_id TEXT REFERENCES assets(id),
  estimate_microusd INTEGER,
  actual_microusd INTEGER CHECK (actual_microusd IS NULL OR actual_microusd >= 0),
  error_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (workspace_id, idempotency_key)
);
CREATE INDEX production_render_attempts_job_idx ON production_render_attempts(production_job_id, created_at);
CREATE TRIGGER production_render_attempts_immutable_request BEFORE UPDATE OF workspace_id, production_job_id, idempotency_key, request_hash, provider, estimate_microusd ON production_render_attempts BEGIN SELECT RAISE(ABORT, 'immutable render request'); END;
