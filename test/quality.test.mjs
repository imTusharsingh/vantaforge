import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { evaluateDeterministicQuality, qualityScore } from '../src/server/quality.ts';

const ready = (overrides = {}) => ({ id: 'asset-1', kind: 'real_footage', media_type: 'video/mp4', duration_seconds: 30, width: 1080, height: 1920, metadata: JSON.stringify({ audio_ready: true, captions_ready: true }), status: 'ready', scan_status: 'clean', licensing_status: 'valid', rights_confirmed: 1, license_type: 'owned', ...overrides });
test('deterministic quality gate covers footage, media, rights and state', () => {
  assert.deepEqual(evaluateDeterministicQuality({ status: 'awaiting_review' }, [ready()], new Date().toISOString()), []);
  const findings = evaluateDeterministicQuality({ status: 'blocked' }, [ready({ width: 1920, metadata: '{}' })], new Date().toISOString());
  assert.deepEqual(findings.map((item) => item.code), ['aspect_ratio_constraint_failed', 'audio_readiness_unavailable', 'caption_readiness_unavailable', 'production_state_ineligible']);
  assert.equal(qualityScore(findings), null);
});
test('quality score is never invented for a blocking result', () => {
  assert.equal(qualityScore([]), 100);
  assert.equal(qualityScore([{ code: 'x', severity: 'blocking', message: 'x', evidence_refs: [] }]), null);
});
