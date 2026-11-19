import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { canTransition, ceilingMicros, costBlocker } from '../src/server/production.ts';
test('state transitions cannot skip review or revive terminal jobs', () => {
  assert.equal(canTransition('planning', 'provider_preparation'), true);
  assert.equal(canTransition('rendering', 'completed'), false);
  assert.equal(canTransition('awaiting_review', 'completed'), true);
  assert.equal(canTransition('blocked', 'cancelled'), true);
  assert.equal(canTransition('cancelled', 'rendering'), false);
});
test('cost gate fails closed and uses integer millionths', () => {
  assert.equal(ceilingMicros(1.25), 1250000);
  assert.equal(ceilingMicros(0), null);
  assert.equal(costBlocker(null, 1), 'cost_ceiling_required');
  assert.equal(costBlocker(100, null), 'cost_estimate_unavailable');
  assert.equal(costBlocker(100, 60, 41), 'cost_ceiling_exceeded');
  assert.equal(costBlocker(100, 60, 40), null);
});
