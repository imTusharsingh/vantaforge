import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { canRunStep, leaseAvailable, policyBlocker, retryableAutomationCode, retryDelaySeconds, terminalState } from '../src/server/automation.ts';

const policy = (overrides = {}) => ({ mode: 'autopilot', enabled_capabilities: ['idea_discovery','production','quality','publishing'], review_mode: 'after_n_shorts', review_after_count: 10, daily_spend_limit: 25, per_job_cost_limit: 5, stop_switch: 0, ...overrides });

test('after-N review blocks only after N real published shorts, including 10 and 20', () => {
  assert.equal(policyBlocker(policy(), 'publishing', 9), null);
  assert.equal(policyBlocker(policy(), 'publishing', 10), 'review_required');
  assert.equal(policyBlocker(policy({ review_after_count: 20 }), 'publishing', 19), null);
  assert.equal(policyBlocker(policy({ review_after_count: 20 }), 'publishing', 20), 'review_required');
  assert.equal(policyBlocker(policy({ review_after_count: 20 }), 'publishing', 21), 'review_required');
  assert.equal(policyBlocker(policy({ review_mode: 'every_short' }), 'publishing', 0, 0, true), null);
});

test('policy fails closed before every capability and respects assisted and stop modes', () => {
  assert.equal(policyBlocker(policy({ stop_switch: 1 }), 'idea_scout', 0), 'stop_switch_enabled');
  assert.equal(policyBlocker(policy({ mode: 'assisted' }), 'production', 0), 'assisted_review_required');
  assert.equal(policyBlocker(policy({ enabled_capabilities: [] }), 'quality', 0), 'capability_disabled');
  assert.equal(policyBlocker(policy({ daily_spend_limit: null }), 'production', 0), 'daily_cost_ceiling_required');
  assert.equal(policyBlocker(policy({ per_job_cost_limit: 0 }), 'production', 0), 'job_cost_ceiling_required');
  assert.equal(policyBlocker(policy(), 'production', 0, 25_000_000), 'daily_cost_ceiling_exceeded');
  assert.equal(policyBlocker(policy(), 'production', 0, -1), 'daily_cost_unavailable');
});

test('terminal transitions, leases, and retries are replay safe and bounded', () => {
  assert.equal(canRunStep(null, 'queued'), true);
  assert.equal(canRunStep('succeeded', 'retry_scheduled'), true);
  assert.equal(canRunStep('succeeded', 'succeeded'), false);
  assert.equal(canRunStep(null, 'cancelled'), false);
  assert.equal(leaseAvailable('worker-a', '2026-01-01T00:01:00.000Z', '2026-01-01T00:00:00.000Z'), false);
  assert.equal(leaseAvailable('worker-a', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'), true);
  assert.equal(retryDelaySeconds(1), 15);
  assert.equal(retryDelaySeconds(100), 1920);
  assert.equal(terminalState('review_required'), 'waiting_review');
  assert.equal(terminalState('provider_unavailable'), 'blocked');
  assert.equal(retryableAutomationCode('platform_api_unavailable'), true);
  assert.equal(retryableAutomationCode('network_timeout'), true);
  for (const code of ['validation_error','brief_not_approved','asset_not_found','policy_blocked','credential_required','capability_disabled','provider_unavailable']) assert.equal(retryableAutomationCode(code), false);
});
