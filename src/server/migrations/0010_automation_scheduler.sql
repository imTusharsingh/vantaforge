PRAGMA foreign_keys = ON;

CREATE TABLE automation_schedules (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  created_by_user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  cadence_minutes INTEGER NOT NULL CHECK (cadence_minutes BETWEEN 5 AND 10080),
  provider TEXT NOT NULL,
  configuration TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','paused','cancelled','blocked')),
  blocker_code TEXT,
  next_run_at TEXT NOT NULL,
  last_run_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX automation_schedules_due_idx ON automation_schedules(status, next_run_at);
CREATE INDEX automation_schedules_workspace_idx ON automation_schedules(workspace_id, created_at);

CREATE TABLE automation_runs (
  id TEXT PRIMARY KEY NOT NULL,
  schedule_id TEXT NOT NULL REFERENCES automation_schedules(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL,
  scheduled_for TEXT NOT NULL,
  policy_snapshot TEXT NOT NULL,
  configuration_snapshot TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','running','retry_scheduled','waiting_review','succeeded','blocked','failed','cancelled')),
  current_step TEXT,
  blocker_code TEXT,
  attempt INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  lease_owner TEXT,
  lease_expires_at TEXT,
  lease_fence INTEGER NOT NULL DEFAULT 0,
  cancel_requested_at TEXT,
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (schedule_id, scheduled_for),
  UNIQUE (workspace_id, idempotency_key)
);
CREATE INDEX automation_runs_due_idx ON automation_runs(status, next_attempt_at, scheduled_for);
CREATE INDEX automation_runs_workspace_idx ON automation_runs(workspace_id, created_at);

CREATE TABLE automation_run_steps (
  id TEXT PRIMARY KEY NOT NULL,
  run_id TEXT NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  step TEXT NOT NULL CHECK (step IN ('idea_scout','production','quality','publishing')),
  ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 4),
  idempotency_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','running','retry_scheduled','waiting_review','succeeded','blocked','failed','cancelled')),
  boundary_resource_id TEXT,
  blocker_code TEXT,
  attempt INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  lease_owner TEXT,
  lease_expires_at TEXT,
  lease_fence INTEGER NOT NULL DEFAULT 0,
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (run_id, step),
  UNIQUE (workspace_id, idempotency_key)
);
CREATE INDEX automation_steps_due_idx ON automation_run_steps(status, next_attempt_at, ordinal);

CREATE TABLE automation_run_events (
  id TEXT PRIMARY KEY NOT NULL,
  run_id TEXT NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
  step_id TEXT REFERENCES automation_run_steps(id) ON DELETE CASCADE,
  event TEXT NOT NULL,
  reason_code TEXT,
  attempt INTEGER NOT NULL,
  occurred_at TEXT NOT NULL
);
CREATE INDEX automation_events_run_idx ON automation_run_events(run_id, occurred_at);
CREATE TRIGGER automation_events_no_update BEFORE UPDATE ON automation_run_events BEGIN SELECT RAISE(ABORT, 'immutable automation event'); END;
CREATE TRIGGER automation_events_no_delete BEFORE DELETE ON automation_run_events BEGIN SELECT RAISE(ABORT, 'immutable automation event'); END;

CREATE TABLE automation_review_counters (
  workspace_id TEXT PRIMARY KEY NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  shorts_since_review INTEGER NOT NULL DEFAULT 0 CHECK (shorts_since_review >= 0),
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);
CREATE TRIGGER automation_count_real_publish AFTER INSERT ON published_posts
BEGIN
  INSERT INTO automation_review_counters (workspace_id,shorts_since_review,version,updated_at)
  VALUES (NEW.workspace_id,1,1,NEW.published_at)
  ON CONFLICT(workspace_id) DO UPDATE SET shorts_since_review=shorts_since_review+1,version=version+1,updated_at=NEW.published_at;
END;

CREATE TABLE automation_review_checkpoints (
  id TEXT PRIMARY KEY NOT NULL,
  run_id TEXT NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
  step_id TEXT NOT NULL REFERENCES automation_run_steps(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('assisted','cadence')),
  counter_version INTEGER,
  threshold INTEGER,
  shorts_reviewed INTEGER,
  approved_by_user_id TEXT NOT NULL REFERENCES users(id),
  reason TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (run_id, step_id, kind, counter_version)
);
CREATE UNIQUE INDEX automation_assisted_checkpoint_unique
  ON automation_review_checkpoints(run_id,step_id,kind) WHERE kind='assisted';
CREATE TRIGGER automation_review_checkpoints_no_update BEFORE UPDATE ON automation_review_checkpoints BEGIN SELECT RAISE(ABORT, 'immutable automation review checkpoint'); END;
CREATE TRIGGER automation_review_checkpoints_no_delete BEFORE DELETE ON automation_review_checkpoints BEGIN SELECT RAISE(ABORT, 'immutable automation review checkpoint'); END;

CREATE TABLE automation_budget_accounts (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  budget_date TEXT NOT NULL,
  limit_microusd INTEGER NOT NULL CHECK (limit_microusd > 0),
  reserved_microusd INTEGER NOT NULL DEFAULT 0 CHECK (reserved_microusd >= 0),
  actual_microusd INTEGER NOT NULL DEFAULT 0 CHECK (actual_microusd >= 0),
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, budget_date)
);
CREATE TABLE automation_budget_reservations (
  id TEXT PRIMARY KEY NOT NULL,
  run_id TEXT NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
  step_id TEXT NOT NULL REFERENCES automation_run_steps(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  budget_date TEXT NOT NULL,
  estimate_microusd INTEGER NOT NULL CHECK (estimate_microusd >= 0),
  actual_microusd INTEGER,
  status TEXT NOT NULL CHECK (status IN ('reserved','reconciled','released')),
  created_at TEXT NOT NULL,
  reconciled_at TEXT,
  UNIQUE (step_id)
);
CREATE INDEX automation_budget_reservations_account_idx ON automation_budget_reservations(workspace_id,budget_date,status);

CREATE TABLE automation_publish_claims (
  publish_request_id TEXT PRIMARY KEY NOT NULL REFERENCES publish_requests(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES automation_runs(id) ON DELETE CASCADE,
  step_id TEXT NOT NULL REFERENCES automation_run_steps(id) ON DELETE CASCADE,
  lease_fence INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('claimed','completed')),
  claimed_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE(step_id)
);
