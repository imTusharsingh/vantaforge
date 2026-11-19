PRAGMA foreign_keys = ON;
CREATE TABLE content_briefs (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  idea_id TEXT NOT NULL REFERENCES idea_candidates(id), content TEXT NOT NULL,
  approved_by_user_id TEXT NOT NULL REFERENCES users(id), approved_at TEXT NOT NULL
);
CREATE TABLE production_jobs (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  created_by_user_id TEXT NOT NULL REFERENCES users(id), brief_id TEXT NOT NULL REFERENCES content_briefs(id),
  asset_ids TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
  policy_snapshot TEXT NOT NULL, provider_snapshot TEXT NOT NULL,
  ceiling_microusd INTEGER, estimate_microusd INTEGER, estimate_reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('planning','provider_preparation','rendering','awaiting_review','completed','failed','cancelled','blocked')),
  blocker_code TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(workspace_id,idempotency_key)
);
CREATE INDEX production_jobs_workspace_idx ON production_jobs(workspace_id, created_at);
CREATE TABLE production_job_events (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES production_jobs(id),
  status TEXT NOT NULL, reason TEXT, actor_id TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE TABLE production_cost_ledger (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES production_jobs(id),
  provider TEXT NOT NULL, model TEXT NOT NULL, usage_json TEXT NOT NULL,
  actual_microusd INTEGER NOT NULL CHECK(actual_microusd >= 0), created_at TEXT NOT NULL
);
CREATE TRIGGER production_job_snapshots_immutable BEFORE UPDATE OF brief_id, asset_ids, policy_snapshot, provider_snapshot, ceiling_microusd, estimate_microusd, estimate_reason ON production_jobs BEGIN SELECT RAISE(ABORT, 'immutable production snapshot'); END;
CREATE TRIGGER production_ledger_no_update BEFORE UPDATE ON production_cost_ledger BEGIN SELECT RAISE(ABORT, 'immutable ledger'); END;
CREATE TRIGGER production_ledger_no_delete BEFORE DELETE ON production_cost_ledger BEGIN SELECT RAISE(ABORT, 'immutable ledger'); END;
CREATE TRIGGER content_briefs_no_update BEFORE UPDATE ON content_briefs BEGIN SELECT RAISE(ABORT, 'immutable approved brief'); END;
CREATE TRIGGER content_briefs_no_delete BEFORE DELETE ON content_briefs BEGIN SELECT RAISE(ABORT, 'immutable approved brief'); END;
CREATE TRIGGER production_events_no_update BEFORE UPDATE ON production_job_events BEGIN SELECT RAISE(ABORT, 'immutable event'); END;
CREATE TRIGGER production_events_no_delete BEFORE DELETE ON production_job_events BEGIN SELECT RAISE(ABORT, 'immutable event'); END;
