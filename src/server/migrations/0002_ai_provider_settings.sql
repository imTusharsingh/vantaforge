PRAGMA foreign_keys = ON;

CREATE TABLE ai_provider_connections (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  credential_kind TEXT NOT NULL CHECK (credential_kind IN ('api_key')),
  encrypted_secret TEXT,
  selected_model TEXT,
  status TEXT NOT NULL DEFAULT 'unconfigured' CHECK (status IN ('configured', 'unconfigured', 'verified', 'unverified', 'invalid')),
  last_verified_at TEXT,
  last_error_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (workspace_id, provider)
);

CREATE INDEX ai_provider_connections_workspace_idx ON ai_provider_connections(workspace_id, provider);
