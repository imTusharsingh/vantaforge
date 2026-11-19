PRAGMA foreign_keys = ON;

CREATE TABLE publishing_connections (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  platform TEXT NOT NULL CHECK (platform IN ('youtube', 'instagram')),
  account_id TEXT,
  channel_id TEXT,
  scopes TEXT NOT NULL,
  encrypted_access_token TEXT,
  encrypted_refresh_token TEXT,
  access_expires_at TEXT,
  credential_status TEXT NOT NULL CHECK (credential_status IN ('pending_authorization', 'active', 'expired', 'revoked', 'error', 'blocked')),
  last_verified_at TEXT,
  last_error_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, platform)
);
CREATE INDEX publishing_connections_workspace_idx ON publishing_connections(workspace_id, platform);

CREATE TABLE publishing_oauth_states (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id),
  platform TEXT NOT NULL CHECK (platform IN ('youtube', 'instagram')),
  state_hash TEXT NOT NULL UNIQUE,
  nonce_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'used', 'expired', 'blocked', 'error')),
  error_code TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX publishing_oauth_states_expiry_idx ON publishing_oauth_states(expires_at, status);

CREATE TABLE publish_requests (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  production_job_id TEXT NOT NULL REFERENCES production_jobs(id),
  quality_gate_run_id TEXT NOT NULL REFERENCES quality_gate_runs(id),
  connection_id TEXT NOT NULL REFERENCES publishing_connections(id),
  asset_id TEXT NOT NULL REFERENCES assets(id),
  scheduled_for TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload TEXT NOT NULL,
  platform_payload_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'retry_scheduled', 'processing', 'blocked', 'succeeded', 'failed', 'cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  last_error_code TEXT,
  last_error_message TEXT,
  created_by_user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, idempotency_key)
);
CREATE INDEX publish_requests_due_idx ON publish_requests(status, next_attempt_at, scheduled_for);

CREATE TABLE publish_request_events (
  id TEXT PRIMARY KEY NOT NULL,
  publish_request_id TEXT NOT NULL REFERENCES publish_requests(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  reason_code TEXT,
  attempt INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE published_posts (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  publish_request_id TEXT NOT NULL UNIQUE REFERENCES publish_requests(id),
  platform TEXT NOT NULL CHECK (platform IN ('youtube', 'instagram')),
  platform_post_id TEXT NOT NULL,
  url TEXT NOT NULL,
  published_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'published'
);
