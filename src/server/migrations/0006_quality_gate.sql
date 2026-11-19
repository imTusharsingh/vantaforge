PRAGMA foreign_keys = ON;
CREATE TABLE quality_gate_runs (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), production_job_id TEXT NOT NULL REFERENCES production_jobs(id),
  created_by_user_id TEXT NOT NULL REFERENCES users(id), idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
  provider_snapshot TEXT NOT NULL, policy_snapshot TEXT NOT NULL, evidence_refs TEXT NOT NULL, findings TEXT NOT NULL,
  score INTEGER, status TEXT NOT NULL CHECK(status IN ('passed','failed','blocked')), blocker_code TEXT,
  created_at TEXT NOT NULL, UNIQUE(workspace_id, idempotency_key)
);
CREATE INDEX quality_gate_runs_job_idx ON quality_gate_runs(production_job_id, created_at);
CREATE TABLE quality_gate_decisions (
  id TEXT PRIMARY KEY, quality_gate_run_id TEXT NOT NULL REFERENCES quality_gate_runs(id), workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')), reviewer_id TEXT NOT NULL REFERENCES users(id), reason TEXT,
  created_at TEXT NOT NULL
);
CREATE TRIGGER quality_gate_runs_immutable BEFORE UPDATE ON quality_gate_runs BEGIN SELECT RAISE(ABORT, 'immutable quality gate run'); END;
CREATE TRIGGER quality_gate_runs_no_delete BEFORE DELETE ON quality_gate_runs BEGIN SELECT RAISE(ABORT, 'immutable quality gate run'); END;
CREATE TRIGGER quality_gate_decisions_immutable BEFORE UPDATE ON quality_gate_decisions BEGIN SELECT RAISE(ABORT, 'immutable quality gate decision'); END;
CREATE TRIGGER quality_gate_decisions_no_delete BEFORE DELETE ON quality_gate_decisions BEGIN SELECT RAISE(ABORT, 'immutable quality gate decision'); END;
CREATE TRIGGER production_completion_requires_quality_gate BEFORE UPDATE OF status ON production_jobs
WHEN NEW.status = 'completed' AND NOT EXISTS (SELECT 1 FROM quality_gate_runs WHERE production_job_id = NEW.id AND status = 'passed')
BEGIN SELECT RAISE(ABORT, 'successful quality gate required'); END;
