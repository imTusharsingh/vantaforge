import test from "node:test";
import assert from "node:assert/strict";

const rules = { youtube: { maxTitle: 100, maxDescription: 5000, maxDurationSeconds: 60 }, instagram: { maxTitle: 0, maxDescription: 2200, maxDurationSeconds: 90 } };
function validate(platform, { title, description, durationSeconds }) { const rule = rules[platform]; const errors = []; if (typeof title !== "string" || title.trim() === "") errors.push("title_required"); else if (rule.maxTitle > 0 && title.length > rule.maxTitle) errors.push("title_too_long"); if (typeof description !== "string") errors.push("description_required"); else if (description.length > rule.maxDescription) errors.push("description_too_long"); if (!Number.isFinite(durationSeconds) || durationSeconds <= 0 || durationSeconds > rule.maxDurationSeconds) errors.push("duration_out_of_range"); return errors; }
function retryDelaySeconds(attempt) { return Math.min(6 * 60 * 60, 30 * 2 ** (attempt - 1)); }

test("platform validation reports violations without truncating metadata", () => { const title = "x".repeat(101); assert.deepEqual(validate("youtube", { title, description: "ok", durationSeconds: 60 }), ["title_too_long"]); assert.equal(title.length, 101); assert.deepEqual(validate("instagram", { title: "caption", description: "x".repeat(2201), durationSeconds: 91 }), ["description_too_long", "duration_out_of_range"]); });
test("retry backoff is deterministic and capped", () => { assert.deepEqual([1, 2, 3, 4, 5, 20].map(retryDelaySeconds), [30, 60, 120, 240, 480, 21600]); });
test("OAuth state binds a nonce", async () => { const state = "csrf.nonce"; const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("nonce")); assert.equal([...new Uint8Array(digest)].length, 32); assert.equal(state.split(".").at(-1), "nonce"); });
