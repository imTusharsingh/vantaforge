PRAGMA foreign_keys = ON;

CREATE TABLE idea_scout_runs (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  created_by_user_id TEXT NOT NULL REFERENCES users(id),
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  provider_snapshot TEXT NOT NULL,
  policy_snapshot TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('blocked', 'failed', 'succeeded')),
  blocker_code TEXT,
  usage_json TEXT,
  cost_json TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  UNIQUE (workspace_id, idempotency_key)
);
CREATE INDEX idea_scout_runs_workspace_idx ON idea_scout_runs(workspace_id, created_at);

CREATE TABLE idea_candidates (
  id TEXT PRIMARY KEY NOT NULL,
  run_id TEXT NOT NULL REFERENCES idea_scout_runs(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  premise TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  trend_signals_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idea_candidates_run_idx ON idea_candidates(run_id, workspace_id);
