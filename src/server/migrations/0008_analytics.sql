PRAGMA foreign_keys = ON;

CREATE TABLE analytics_runs (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  created_by_user_id TEXT NOT NULL REFERENCES users(id),
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('youtube','instagram')),
  connection_id TEXT REFERENCES publishing_connections(id),
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','blocked','failed')),
  blocker_code TEXT,
  error_message TEXT,
  policy_snapshot TEXT NOT NULL,
  provider_snapshot TEXT NOT NULL,
  fetch_started_at TEXT,
  fetch_completed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, idempotency_key)
);
CREATE INDEX analytics_runs_workspace_idx ON analytics_runs(workspace_id, created_at DESC);

CREATE TABLE analytics_provider_snapshots (
  id TEXT PRIMARY KEY NOT NULL,
  run_id TEXT NOT NULL REFERENCES analytics_runs(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  platform TEXT NOT NULL,
  account_id TEXT,
  channel_id TEXT,
  captured_at TEXT NOT NULL,
  snapshot_json TEXT NOT NULL
);

CREATE TABLE analytics_source_refs (
  id TEXT PRIMARY KEY NOT NULL,
  run_id TEXT NOT NULL REFERENCES analytics_runs(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  attribution TEXT NOT NULL,
  response_hash TEXT NOT NULL
);

CREATE TABLE analytics_metrics (
  id TEXT PRIMARY KEY NOT NULL,
  run_id TEXT NOT NULL REFERENCES analytics_runs(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  platform TEXT NOT NULL,
  account_id TEXT NOT NULL,
  content_id TEXT,
  metric TEXT NOT NULL,
  value REAL NOT NULL CHECK (value >= 0),
  observed_at TEXT NOT NULL,
  source_ref TEXT NOT NULL
);
CREATE INDEX analytics_metrics_workspace_idx ON analytics_metrics(workspace_id, observed_at DESC);

CREATE TABLE analytics_suggestions (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  created_by_user_id TEXT NOT NULL REFERENCES users(id),
  idempotency_key TEXT NOT NULL,
  evidence_run_ids TEXT NOT NULL,
  provider_snapshot TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('succeeded','blocked','failed')),
  blocker_code TEXT,
  suggestion TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(workspace_id, idempotency_key)
);
