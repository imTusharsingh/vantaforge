import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const migration = readFileSync(new URL('../src/server/migrations/0011_usage_metering_and_plans.sql', import.meta.url), 'utf8');
test('usage migration is an evidence-gated, append-only D1 contract', () => {
  assert.match(migration, /CREATE TABLE billing_evidence/);
  assert.match(migration, /CREATE TABLE usage_reservations/);
  assert.match(migration, /CREATE TABLE usage_ledger/);
  assert.match(migration, /usage_ledger_immutable_update/);
  assert.match(migration, /upgrade_threshold_percent/);
  assert.match(migration, /CHECK\(reserved_microusd\+settled_microusd<=budget_microusd\)/);
  assert.match(migration, /verified billing evidence required/);
});
