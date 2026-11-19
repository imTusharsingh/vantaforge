import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { capabilitySnapshots, idempotencyHashInput, REAL_FOOTAGE_RENDER_ADAPTERS, validateMediaMetadata } from '../src/server/render-adapters.ts';
import { canTransitionRender, costBlocker, idempotencyConflict, workspaceCanRender } from '../src/server/production.ts';

test('the catalog fails closed when no real renderer is available', () => {
  assert.equal(REAL_FOOTAGE_RENDER_ADAPTERS.length, 0);
  assert.ok(capabilitySnapshots('openai', '2026-11-19T00:00:00.000Z').every((item) => item.status === 'unavailable' && item.blocker_code === 'provider_unavailable'));
});

test('media inspection never treats missing evidence as valid', () => {
  const findings = validateMediaMetadata({ audio_present: true }, 'output');
  assert.ok(findings.some((item) => item.code === 'metadata_unavailable' || item.code === 'container_unavailable'));
  assert.ok(findings.some((item) => item.code === 'captions_unavailable'));
});

test('render retries are explicit and terminal states cannot be replayed', () => {
  assert.equal(canTransitionRender('planned', 'blocked'), true);
  assert.equal(canTransitionRender('blocked', 'submitted'), false);
  assert.equal(canTransitionRender('succeeded', 'processing'), false);
  const hash = idempotencyHashInput({ workspace_id: 'w', job_id: 'j', source_asset_ids: ['b', 'a'], model: null });
  assert.equal(idempotencyConflict(hash, hash), false);
  assert.equal(idempotencyConflict(hash, hash + 'x'), true);
});

test('cost and workspace gates fail closed', () => {
  assert.equal(costBlocker(1_000_000, null), 'cost_estimate_unavailable');
  assert.equal(costBlocker(1_000_000, 1_000_001), 'cost_ceiling_exceeded');
  assert.equal(workspaceCanRender('editor', 'active'), true);
  assert.equal(workspaceCanRender('viewer', 'active'), false);
  assert.equal(workspaceCanRender('editor', 'suspended'), false);
});
