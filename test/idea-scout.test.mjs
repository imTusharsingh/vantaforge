import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { ideaScoutBlocker } from '../src/server/idea-scout.ts';

const ready = { active: true, stopped: false, enabled: ['idea_discovery'], credential: true, verified: true, modelSupported: true };
test('policy takes precedence over provider configuration', () => {
  assert.equal(ideaScoutBlocker({ ...ready, stopped: true, credential: false }), 'policy_blocked');
  assert.equal(ideaScoutBlocker({ ...ready, enabled: [] }), 'policy_blocked');
  assert.equal(ideaScoutBlocker({ ...ready, active: false }), 'policy_blocked');
});
test('provider prerequisites and missing real source produce explicit blockers', () => {
  assert.equal(ideaScoutBlocker({ ...ready, credential: false }), 'credential_required');
  assert.equal(ideaScoutBlocker({ ...ready, verified: false }), 'connection_not_verified');
  assert.equal(ideaScoutBlocker({ ...ready, modelSupported: false }), 'model_not_selected');
  assert.equal(ideaScoutBlocker(ready), 'trend_source_unavailable');
});
