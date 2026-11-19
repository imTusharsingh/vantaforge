import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { normalizeAssets, normalizePolicy, normalizeWorkspaces, resourceError } from "../dist/dashboard-state.js";

test("dashboard normalizes D1 workspace result envelopes", () => {
  assert.deepEqual(normalizeWorkspaces({ results: [{ id: "workspace-1" }] }), [{ id: "workspace-1" }]);
  assert.deepEqual(normalizeWorkspaces({ results: [] }), []);
  assert.deepEqual(normalizeWorkspaces({ data: [{ id: "wrong-shape" }] }), []);
});

test("dashboard reads licensing metadata from the API licensing object", () => {
  const [asset] = normalizeAssets({ results: [{ id: "asset-1", licensing: { type: "licensed", rights_confirmed: true } }] });
  assert.equal(asset.licensing.type, "licensed");
  assert.equal(asset.licensing.rights_confirmed, true);
});

test("dashboard policy normalization accepts the persisted JSON column", () => {
  assert.deepEqual(normalizePolicy({ enabled_capabilities: '["analytics"]' }).enabled_capabilities, ["analytics"]);
  assert.deepEqual(normalizePolicy({ enabled_capabilities: "not-json" }).enabled_capabilities, []);
});

test("resource failures remain explicit and publishing/analytics use declared Worker routes", () => {
  assert.deepEqual(resourceError(new Error("analytics unavailable")), { status: "error", data: null, error: "analytics unavailable" });
  const dashboard = fs.readFileSync(new URL("../dist/dashboard.js", import.meta.url), "utf8");
  assert.match(dashboard, /\/v1\/workspaces\/\$\{id\}\/publishing-connections/);
  assert.match(dashboard, /\/v1\/workspaces\/\$\{id\}\/analytics/);
  assert.match(dashboard, /Publishing actions unavailable/);
  assert.match(dashboard, /Fresh analytics unavailable/);
  assert.doesNotMatch(dashboard, /publishing-connections\/oauth/);
  assert.doesNotMatch(dashboard, /publishing-connections\/\$\{element\.dataset\.connection\}\/revoke/);
  assert.doesNotMatch(dashboard, /analytics-runs/);
  assert.doesNotMatch(dashboard, /Promise\.allSettled/);
  assert.doesNotMatch(dashboard, /catch\s*\([^)]*\)\s*\{\s*\[\]/);
});
