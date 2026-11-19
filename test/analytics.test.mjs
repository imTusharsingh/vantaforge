import test from "node:test";
import assert from "node:assert/strict";
import { analyticsBlocker, normalizeInstagramMetrics, normalizeYouTubeRows, suggestionEvidence } from "../src/server/analytics.ts";

const ready = { active: true, stopped: false, enabled: ["analytics"], connected: true, expired: false, revoked: false, credential: true, scopes: ["a", "b"], requiredScopes: ["a"] };
test("analytics blockers fail closed in stable order", () => {
  assert.equal(analyticsBlocker({ ...ready, stopped: true, connected: false }), "policy_blocked");
  assert.equal(analyticsBlocker({ ...ready, connected: false }), "connection_required");
  assert.equal(analyticsBlocker({ ...ready, scopes: [] }), "scope_missing");
  assert.equal(analyticsBlocker({ ...ready, hasData: false }), "data_unavailable");
});
test("normalization accepts provider values and drops invalid values", () => {
  const youtube = normalizeYouTubeRows([["video-1", "12", 3, "bad", 1]], "channel-1", "2026-01-01", "source-1");
  assert.deepEqual(youtube.map((item) => [item.metric, item.value]), [["views", 12], ["likes", 3], ["shares", 1]]);
  const instagram = normalizeInstagramMetrics([{ name: "likes", total_value: { value: 9 } }, { name: "comments", value: "2" }], "account-1", "2026-01-01", "source-2");
  assert.deepEqual(instagram.map((item) => item.value), [9, 2]);
  assert.equal(suggestionEvidence(youtube), true);
});
