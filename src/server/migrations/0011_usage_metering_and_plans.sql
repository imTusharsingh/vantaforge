PRAGMA foreign_keys = ON;

-- A catalog entry is inert until its evidence is independently verified.  No
-- seed plan is deliberately supplied: this deployment has no billing vendor.
CREATE TABLE billing_evidence (
  id TEXT PRIMARY KEY NOT NULL,
  provider TEXT NOT NULL,
  evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('billing_capability','pricing','entitlement')),
  reference TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  expires_at TEXT,
  verified_at TEXT NOT NULL,
  verified_by TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('verified','expired','revoked')),
  payload_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE INDEX billing_evidence_current_idx ON billing_evidence(status, expires_at, evidence_kind);

CREATE TABLE plan_catalogs (
  id TEXT PRIMARY KEY NOT NULL,
  code TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  allowance_microusd INTEGER NOT NULL CHECK (allowance_microusd >= 0),
  period_kind TEXT NOT NULL CHECK (period_kind IN ('monthly')),
  assisted_enabled INTEGER NOT NULL DEFAULT 1 CHECK (assisted_enabled IN (0,1)),
  autopilot_enabled INTEGER NOT NULL DEFAULT 0 CHECK (autopilot_enabled IN (0,1)),
  automation_upgrade_threshold INTEGER NOT NULL DEFAULT 10 CHECK (automation_upgrade_threshold >= 1),
  billing_evidence_id TEXT NOT NULL REFERENCES billing_evidence(id),
  pricing_evidence_id TEXT NOT NULL REFERENCES billing_evidence(id),
  status TEXT NOT NULL CHECK (status IN ('draft','enabled','retired')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TRIGGER plan_catalog_enabled_evidence BEFORE INSERT ON plan_catalogs WHEN NEW.status='enabled' BEGIN
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM billing_evidence WHERE id=NEW.billing_evidence_id AND evidence_kind='billing_capability' AND status='verified' AND (expires_at IS NULL OR expires_at>NEW.created_at)) THEN RAISE(ABORT,'verified billing evidence required') END;
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM billing_evidence WHERE id=NEW.pricing_evidence_id AND evidence_kind='pricing' AND status='verified' AND (expires_at IS NULL OR expires_at>NEW.created_at)) THEN RAISE(ABORT,'verified pricing evidence required') END;
END;
CREATE TRIGGER plan_catalog_enabled_evidence_update BEFORE UPDATE OF status ON plan_catalogs WHEN NEW.status='enabled' BEGIN
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM billing_evidence WHERE id=NEW.billing_evidence_id AND evidence_kind='billing_capability' AND status='verified' AND (expires_at IS NULL OR expires_at>NEW.updated_at)) THEN RAISE(ABORT,'verified billing evidence required') END;
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM billing_evidence WHERE id=NEW.pricing_evidence_id AND evidence_kind='pricing' AND status='verified' AND (expires_at IS NULL OR expires_at>NEW.updated_at)) THEN RAISE(ABORT,'verified pricing evidence required') END;
END;

CREATE TABLE workspace_plan_entitlements (
  workspace_id TEXT PRIMARY KEY NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  plan_id TEXT NOT NULL REFERENCES plan_catalogs(id),
  entitlement_evidence_id TEXT NOT NULL REFERENCES billing_evidence(id),
  status TEXT NOT NULL CHECK (status IN ('active','cancelled','expired')),
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (period_end > period_start)
);
CREATE TRIGGER workspace_entitlement_evidence BEFORE INSERT ON workspace_plan_entitlements WHEN NEW.status='active' BEGIN
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM billing_evidence WHERE id=NEW.entitlement_evidence_id AND evidence_kind='entitlement' AND status='verified' AND (expires_at IS NULL OR expires_at>NEW.created_at)) THEN RAISE(ABORT,'verified entitlement evidence required') END;
END;

CREATE TABLE usage_budget_policies (
  workspace_id TEXT PRIMARY KEY NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  monthly_limit_microusd INTEGER CHECK (monthly_limit_microusd IS NULL OR monthly_limit_microusd >= 0),
  custom_limit_microusd INTEGER CHECK (custom_limit_microusd IS NULL OR custom_limit_microusd >= 0),
  upgrade_threshold_percent INTEGER NOT NULL DEFAULT 20 CHECK (upgrade_threshold_percent IN (10,20) OR (upgrade_threshold_percent BETWEEN 1 AND 99)),
  automation_upgrade_threshold INTEGER NOT NULL DEFAULT 10 CHECK (automation_upgrade_threshold >= 1),
  updated_by_user_id TEXT NOT NULL REFERENCES users(id),
  updated_at TEXT NOT NULL
);

CREATE TABLE usage_period_accounts (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  allowance_microusd INTEGER NOT NULL CHECK (allowance_microusd >= 0),
  budget_microusd INTEGER NOT NULL CHECK (budget_microusd >= 0),
  reserved_microusd INTEGER NOT NULL DEFAULT 0 CHECK (reserved_microusd >= 0),
  settled_microusd INTEGER NOT NULL DEFAULT 0 CHECK (settled_microusd >= 0),
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(workspace_id,user_id,period_start),
  CHECK(period_end>period_start), CHECK(reserved_microusd+settled_microusd<=budget_microusd)
);
CREATE INDEX usage_period_rollover_idx ON usage_period_accounts(workspace_id, period_end);

CREATE TABLE usage_reservations (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  period_start TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  boundary TEXT NOT NULL CHECK(boundary IN ('production_render','publish','storage')),
  estimate_microusd INTEGER NOT NULL CHECK(estimate_microusd >= 0),
  status TEXT NOT NULL CHECK(status IN ('reserved','settled','released')),
  request_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  settled_at TEXT,
  released_at TEXT,
  release_reason TEXT,
  UNIQUE(workspace_id,idempotency_key),
  FOREIGN KEY(workspace_id,user_id,period_start) REFERENCES usage_period_accounts(workspace_id,user_id,period_start)
);
CREATE INDEX usage_reservations_reconcile_idx ON usage_reservations(status,updated_at);

CREATE TABLE usage_ledger (
  id TEXT PRIMARY KEY NOT NULL,
  reservation_id TEXT NOT NULL REFERENCES usage_reservations(id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('reserve','release','settle','reconcile')),
  amount_microusd INTEGER NOT NULL CHECK(amount_microusd >= 0),
  uncertainty TEXT NOT NULL CHECK(uncertainty IN ('verified','estimated','unknown')),
  evidence_id TEXT REFERENCES billing_evidence(id),
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX usage_ledger_workspace_idx ON usage_ledger(workspace_id,created_at);
CREATE TRIGGER usage_ledger_immutable_update BEFORE UPDATE ON usage_ledger BEGIN SELECT RAISE(ABORT,'immutable usage ledger'); END;
CREATE TRIGGER usage_ledger_immutable_delete BEFORE DELETE ON usage_ledger BEGIN SELECT RAISE(ABORT,'immutable usage ledger'); END;
