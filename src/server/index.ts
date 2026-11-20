import { canTransition, ceilingMicros, costBlocker, type ProductionState } from './production';
import { capabilitySnapshots, renderAdapterFor } from './render-adapters';
import { ideaScoutBlocker } from "./idea-scout";
import { decryptSecret, encryptSecret, hashPassword, randomId, randomToken, sha256, verifyPassword } from "./crypto";
import { modelDefinition, PROVIDERS, providerDefinition } from "./providers";
import { asRecord, email, password, requiredString, slug, ValidationError } from "./validation";
import { evaluateDeterministicQuality, qualityScore, type QualityAsset, type QualityFinding } from './quality';
import { ANALYTICS_SCOPES, oauthAuthorizationUrl, PLATFORM_RULES, publicConnection, retryDelaySeconds, validatePublishPayload, type PublishingPlatform } from "./publishing";
import { analyticsBlocker, normalizeInstagramMetrics, normalizeYouTubeRows, suggestionEvidence, type AnalyticsPlatform, type NormalizedMetric } from "./analytics";
import { AUTOMATION_STEPS, MAX_AUTOMATION_ATTEMPTS, policyBlocker, retryableAutomationCode, retryDelaySeconds as automationRetryDelay, terminalState, type AutomationPolicy, type AutomationStep } from './automation';
import { releaseUsage, reserveUsage, usageSummary } from './usage';

export interface Env { DB: D1Database; ASSETS?: R2Bucket; AUTOMATION_SCHEDULER_ENABLED?: string; ALLOWED_ORIGIN?: string; CREDENTIAL_ENCRYPTION_KEY?: string; PUBLIC_BASE_URL?: string; PUBLIC_MEDIA_BASE_URL?: string; YOUTUBE_CLIENT_ID?: string; YOUTUBE_CLIENT_SECRET?: string; INSTAGRAM_CLIENT_ID?: string; INSTAGRAM_CLIENT_SECRET?: string }
type User = { id: string; email: string; display_name: string; status: string };
type Auth = { user: User; token: string };

const json = (body: unknown, status = 200, headers: HeadersInit = {}) => Response.json(body, { status, headers: { "cache-control": "no-store", ...headers } });
const fail = (status: number, code: string, message: string, details?: Record<string, unknown>) => json({ error: { code, message, ...(details ? { details } : {}) }, request_id: crypto.randomUUID() }, status);
const now = () => new Date().toISOString();
const MAX_ASSET_BYTES = 500 * 1024 * 1024;
const UPLOAD_TTL_MS = 60 * 60 * 1000;
const VIDEO_TYPES = new Set(["video/mp4", "video/quicktime", "video/webm", "video/x-matroska"]);
const LICENSE_TYPES = new Set(["owned", "licensed", "public_domain", "cc_by", "cc_by_sa"]);

async function body(request: Request): Promise<Record<string, unknown>> {
  try { return asRecord(await request.json()); } catch (error) { if (error instanceof ValidationError) throw error; throw new ValidationError("Request body must be valid JSON"); }
}

async function authenticate(request: Request, db: D1Database): Promise<Auth | null> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  if (!token) return null;
  const row = await db.prepare(`SELECT u.id, u.email, u.display_name, u.status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?1 AND s.expires_at>?2 AND u.status='active'`).bind(await sha256(token), now()).first<User>();
  if (!row) return null;
  await db.prepare("UPDATE sessions SET last_seen_at=?1 WHERE token_hash=?2").bind(now(), await sha256(token)).run();
  return { user: row, token };
}

function requireAuth(auth: Auth | null): Auth { if (!auth) throw new HttpError(401, "unauthenticated", "A valid session is required"); return auth; }
async function workspace(request: Request, db: D1Database, userId: string, id: string) {
  return db.prepare(`SELECT w.*, m.role FROM workspaces w JOIN memberships m ON m.workspace_id=w.id WHERE w.id=?1 AND m.user_id=?2 AND m.status='active'`).bind(id, userId).first<Record<string, unknown>>();
}

class HttpError extends Error { constructor(public status: number, public code: string, message: string, public details?: Record<string, unknown>) { super(message); } }

async function signup(request: Request, db: D1Database) {
  const input = await body(request); const normalizedEmail = email(input.email); const displayName = requiredString(input.display_name, "display_name", 120); const rawPassword = password(input.password);
  if (await db.prepare("SELECT id FROM users WHERE email=?1").bind(normalizedEmail).first()) throw new HttpError(409, "email_taken", "An account with that email already exists");
  const id = randomId(); const credentials = await hashPassword(rawPassword); const created = now();
  await db.batch([
    db.prepare("INSERT INTO users (id,email,display_name,password_hash,password_salt,created_at,last_seen_at) VALUES (?1,?2,?3,?4,?5,?6,?6)").bind(id, normalizedEmail, displayName, credentials.hash, credentials.salt, created),
  ]);
  return sessionResponse(db, { id, email: normalizedEmail, display_name: displayName, status: "active" });
}

async function login(request: Request, db: D1Database) {
  const input = await body(request); const normalizedEmail = email(input.email); const rawPassword = password(input.password);
  const row = await db.prepare("SELECT id,email,display_name,status,password_hash,password_salt FROM users WHERE email=?1").bind(normalizedEmail).first<User & { password_hash: string; password_salt: string }>();
  if (!row || row.status !== "active" || !(await verifyPassword(rawPassword, row.password_hash, row.password_salt))) throw new HttpError(401, "invalid_credentials", "Email or password is incorrect");
  await db.prepare("UPDATE users SET last_seen_at=?1 WHERE id=?2").bind(now(), row.id).run();
  return sessionResponse(db, { id: row.id, email: row.email, display_name: row.display_name, status: row.status });
}

async function sessionResponse(db: D1Database, user: User) {
  const token = randomToken(); const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
  await db.prepare("INSERT INTO sessions (id,user_id,token_hash,expires_at,created_at,last_seen_at) VALUES (?1,?2,?3,?4,?5,?5)").bind(randomId(), user.id, await sha256(token), expires, now()).run();
  return json({ data: { user, token, expires_at: expires } }, 201);
}

async function createWorkspace(request: Request, db: D1Database, auth: Auth) {
  const input = await body(request); const name = requiredString(input.name, "name", 120); const workspaceSlug = slug(input.slug ?? name.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "")); const timezone = requiredString(input.timezone ?? "UTC", "timezone", 64);
  if (await db.prepare("SELECT id FROM workspaces WHERE slug=?1").bind(workspaceSlug).first()) throw new HttpError(409, "slug_taken", "That workspace slug is already in use");
  const id = randomId(); const created = now();
  await db.batch([
    db.prepare("INSERT INTO workspaces (id,name,slug,owner_user_id,timezone,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)").bind(id, name, workspaceSlug, auth.user.id, timezone, created),
    db.prepare("INSERT INTO memberships (id,workspace_id,user_id,role,created_at) VALUES (?1,?2,?3,'owner',?4)").bind(randomId(), id, auth.user.id, created),
    db.prepare("INSERT INTO automation_policies (workspace_id,updated_at) VALUES (?1,?2)").bind(id, created),
  ]);
  return json({ data: await workspace(request, db, auth.user.id, id) }, 201);
}

async function updateWorkspace(request: Request, db: D1Database, auth: Auth, id: string) {
  const existing = await workspace(request, db, auth.user.id, id); if (!existing) throw new HttpError(404, "workspace_not_found", "Workspace not found");
  if (!["owner", "admin"].includes(String(existing.role))) throw new HttpError(403, "forbidden", "Only workspace owners and admins can update settings");
  const input = await body(request); const name = input.name === undefined ? String(existing.name) : requiredString(input.name, "name", 120); const timezone = input.timezone === undefined ? String(existing.timezone) : requiredString(input.timezone, "timezone", 64);
  await db.prepare("UPDATE workspaces SET name=?1, timezone=?2, updated_at=?3 WHERE id=?4").bind(name, timezone, now(), id).run();
  return json({ data: await workspace(request, db, auth.user.id, id) });
}

async function policy(request: Request, db: D1Database, auth: Auth, id: string) {
  const existing = await workspace(request, db, auth.user.id, id); if (!existing) throw new HttpError(404, "workspace_not_found", "Workspace not found");
  if (request.method === "GET") return json({ data: await db.prepare("SELECT * FROM automation_policies WHERE workspace_id=?1").bind(id).first() });
  if (!["owner", "admin"].includes(String(existing.role))) throw new HttpError(403, "forbidden", "Only workspace owners and admins can update automation policy");
  const input = await body(request); const allowedModes = ["assisted", "autopilot"]; const allowedReview = ["every_short", "after_n_shorts", "none"];
  if (input.mode !== undefined && (typeof input.mode !== "string" || !allowedModes.includes(input.mode))) throw new ValidationError("mode is invalid");
  if (input.review_mode !== undefined && (typeof input.review_mode !== "string" || !allowedReview.includes(input.review_mode))) throw new ValidationError("review_mode is invalid");
  if (input.review_after_count !== undefined && (!Number.isSafeInteger(input.review_after_count) || Number(input.review_after_count) < 1 || Number(input.review_after_count) > 100000)) throw new ValidationError("review_after_count must be a positive integer");
  const current = await db.prepare("SELECT * FROM automation_policies WHERE workspace_id=?1").bind(id).first<Record<string, unknown>>(); if (!current) throw new HttpError(404, "policy_not_found", "Automation policy not found");
  const next = { mode: input.mode ?? current.mode, enabled: input.enabled_capabilities ?? JSON.parse(String(current.enabled_capabilities)), review: input.review_mode ?? current.review_mode, after: input.review_after_count ?? current.review_after_count, daily: input.daily_spend_limit ?? current.daily_spend_limit, perJob: input.per_job_cost_limit ?? current.per_job_cost_limit, stop: input.stop_switch ?? Boolean(current.stop_switch) };
  if (next.review === 'after_n_shorts' && (!Number.isSafeInteger(Number(next.after)) || Number(next.after) < 1 || Number(next.after) > 100000)) throw new ValidationError('review_after_count is required for after_n_shorts');
  if (!Array.isArray(next.enabled)) throw new ValidationError("enabled_capabilities is invalid");
  await db.prepare("UPDATE automation_policies SET mode=?1, enabled_capabilities=?2, review_mode=?3, review_after_count=?4, daily_spend_limit=?5, per_job_cost_limit=?6, stop_switch=?7, version=version+1, updated_at=?8 WHERE workspace_id=?9").bind(next.mode, JSON.stringify(next.enabled), next.review, next.after, next.daily, next.perJob, next.stop ? 1 : 0, now(), id).run();
  if (next.stop || next.enabled.length === 0) await cancelEligibleAutomationRuns(db,id,next.stop ? 'stop_switch_enabled' : 'automation_disabled',now());
  return json({ data: await db.prepare("SELECT * FROM automation_policies WHERE workspace_id=?1").bind(id).first() });
}

async function workspaceUsage(request: Request, db: D1Database, auth: Auth, workspaceId: string) {
  await providerAccess(request, db, auth, workspaceId);
  return json({ data: await usageSummary(db, workspaceId, now()) });
}

async function usagePolicy(request: Request, db: D1Database, auth: Auth, workspaceId: string) {
  const member=await providerAccess(request,db,auth,workspaceId,true);
  if (!['owner','admin'].includes(String(member.role))) throw new HttpError(403,'forbidden','Only workspace owners and admins can manage usage policy');
  const input=await body(request); if (Object.keys(input).some((key)=>!['monthly_limit_microusd','custom_limit_microusd','automation_upgrade_threshold'].includes(key))) throw new ValidationError('Unexpected usage policy field');
  const integer=(value:unknown,name:string) => { if (value !== null && (!Number.isSafeInteger(value) || Number(value)<0)) throw new ValidationError(`${name} must be a non-negative integer or null`); return value as number|null; };
  const monthly=integer(input.monthly_limit_microusd,'monthly_limit_microusd'); const custom=integer(input.custom_limit_microusd,'custom_limit_microusd'); const threshold=input.automation_upgrade_threshold;
  if (threshold !== undefined && (!Number.isSafeInteger(threshold) || Number(threshold)<1 || Number(threshold)>100000)) throw new ValidationError('automation_upgrade_threshold must be a positive integer');
  const current=await db.prepare('SELECT * FROM usage_budget_policies WHERE workspace_id=?1').bind(workspaceId).first<Record<string,unknown>>(); const timestamp=now();
  await db.prepare("INSERT INTO usage_budget_policies(workspace_id,monthly_limit_microusd,custom_limit_microusd,automation_upgrade_threshold,updated_by_user_id,updated_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(workspace_id) DO UPDATE SET monthly_limit_microusd=excluded.monthly_limit_microusd,custom_limit_microusd=excluded.custom_limit_microusd,automation_upgrade_threshold=excluded.automation_upgrade_threshold,updated_by_user_id=excluded.updated_by_user_id,updated_at=excluded.updated_at").bind(workspaceId,monthly ?? current?.monthly_limit_microusd ?? null,custom ?? current?.custom_limit_microusd ?? null,threshold ?? current?.automation_upgrade_threshold ?? 10,auth.user.id,timestamp).run();
  return json({data:await usageSummary(db,workspaceId,timestamp)});
}

type ProviderConnection = { id: string; workspace_id: string; provider: string; credential_kind: string; encrypted_secret: string | null; selected_model: string | null; status: string; last_verified_at: string | null; last_error_code: string | null; created_at: string; updated_at: string };

function providerSummary(provider: typeof PROVIDERS[number], connection?: ProviderConnection) {
  return {
    id: provider.id,
    name: provider.name,
    credential_kind: provider.credential_kind,
    credential_configured: Boolean(connection?.encrypted_secret),
    status: connection?.status ?? "unconfigured",
    selected_model: connection?.selected_model ?? null,
    last_verified_at: connection?.last_verified_at ?? null,
    last_error_code: connection?.last_error_code ?? null,
    models: provider.models,
  };
}

async function providerAccess(request: Request, db: D1Database, auth: Auth, workspaceId: string, mutate = false) {
  const existing = await workspace(request, db, auth.user.id, workspaceId);
  if (!existing) throw new HttpError(404, "workspace_not_found", "Workspace not found");
  if (mutate && !["owner", "admin"].includes(String(existing.role))) throw new HttpError(403, "forbidden", "Only workspace owners and admins can manage AI provider settings");
  return existing;
}

async function listProviders(request: Request, db: D1Database, auth: Auth, workspaceId: string) {
  await providerAccess(request, db, auth, workspaceId);
  const rows = await db.prepare("SELECT id,workspace_id,provider,credential_kind,encrypted_secret,selected_model,status,last_verified_at,last_error_code,created_at,updated_at FROM ai_provider_connections WHERE workspace_id=?1").bind(workspaceId).all<ProviderConnection>();
  const byProvider = new Map(rows.results.map((row) => [row.provider, row]));
  return json({ data: PROVIDERS.map((provider) => providerSummary(provider, byProvider.get(provider.id))) });
}

async function listModels(request: Request, db: D1Database, auth: Auth, workspaceId: string) {
  await providerAccess(request, db, auth, workspaceId);
  const providerId = new URL(request.url).searchParams.get("provider");
  if (!providerId) throw new ValidationError("provider is required");
  const provider = providerDefinition(providerId); if (!provider) throw new HttpError(422, "provider_unsupported", "The provider is not in the supported catalog");
  return json({ data: { provider: provider.id, models: provider.models } });
}

async function connectionFor(db: D1Database, workspaceId: string, providerOrId: string) {
  return db.prepare("SELECT id,workspace_id,provider,credential_kind,encrypted_secret,selected_model,status,last_verified_at,last_error_code,created_at,updated_at FROM ai_provider_connections WHERE workspace_id=?1 AND (provider=?2 OR id=?2)").bind(workspaceId, providerOrId).first<ProviderConnection>();
}

async function saveCredential(request: Request, db: D1Database, auth: Auth, env: Env, workspaceId: string, providerId: string) {
  await providerAccess(request, db, auth, workspaceId, true);
  const provider = providerDefinition(providerId); if (!provider) throw new HttpError(422, "provider_unsupported", "The provider is not in the supported catalog");
  const input = await body(request); const key = requiredString(input.api_key, "api_key", 4096);
  if (!env.CREDENTIAL_ENCRYPTION_KEY) throw new HttpError(503, "credential_encryption_not_configured", "Credential encryption is not configured");
  let encrypted: string;
  try { encrypted = await encryptSecret(key, env.CREDENTIAL_ENCRYPTION_KEY); } catch { throw new HttpError(503, "credential_encryption_not_configured", "Credential encryption is not configured correctly"); }
  const existing = await connectionFor(db, workspaceId, provider.id); const timestamp = now();
  if (existing) await db.prepare("UPDATE ai_provider_connections SET encrypted_secret=?1,status='configured',last_verified_at=NULL,last_error_code=NULL,updated_at=?2 WHERE id=?3").bind(encrypted, timestamp, existing.id).run();
  else await db.prepare("INSERT INTO ai_provider_connections (id,workspace_id,provider,credential_kind,encrypted_secret,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,'configured',?6,?6)").bind(randomId(), workspaceId, provider.id, provider.credential_kind, encrypted, timestamp).run();
  return json({ data: { provider: provider.id, credential_configured: true, status: "configured", verified: false } });
}

async function deleteCredential(request: Request, db: D1Database, auth: Auth, workspaceId: string, providerOrId: string) {
  await providerAccess(request, db, auth, workspaceId, true);
  const connection = await connectionFor(db, workspaceId, providerOrId); if (!connection) throw new HttpError(404, "credential_not_configured", "No credential is configured for this provider");
  await db.prepare("UPDATE ai_provider_connections SET encrypted_secret=NULL,status='unconfigured',selected_model=NULL,last_verified_at=NULL,last_error_code=NULL,updated_at=?1 WHERE id=?2").bind(now(), connection.id).run();
  return json({ data: { provider: connection.provider, credential_configured: false, status: "unconfigured" } });
}

async function selectModel(request: Request, db: D1Database, auth: Auth, workspaceId: string, providerOrId: string) {
  await providerAccess(request, db, auth, workspaceId, true);
  const connection = await connectionFor(db, workspaceId, providerOrId); if (!connection || !connection.encrypted_secret) throw new HttpError(409, "credential_required", "Configure a provider credential before selecting a model");
  if (connection.status !== "verified") throw new HttpError(409, "connection_not_verified", "Verify the provider credential before selecting a model");
  const provider = providerDefinition(connection.provider); if (!provider) throw new HttpError(422, "provider_unsupported", "The provider is not in the supported catalog");
  const input = await body(request); const model = requiredString(input.model, "model", 160); const selected = modelDefinition(provider, model); if (!selected) throw new HttpError(422, "capability_unsupported", "The requested model is not supported for this provider");
  if (input.capability !== undefined && (typeof input.capability !== "string" || !selected.capabilities.includes(input.capability))) throw new HttpError(422, "capability_unsupported", "The requested capability is not supported by this model");
  await db.prepare("UPDATE ai_provider_connections SET selected_model=?1,updated_at=?2 WHERE id=?3").bind(model, now(), connection.id).run();
  return json({ data: { provider: connection.provider, selected_model: model, status: "verified" } });
}

async function verifyProvider(request: Request, db: D1Database, auth: Auth, env: Env, workspaceId: string, providerOrId: string) {
  await providerAccess(request, db, auth, workspaceId, true);
  const connection = await connectionFor(db, workspaceId, providerOrId); if (!connection || !connection.encrypted_secret) throw new HttpError(409, "credential_required", "No credential is configured for this provider");
  if (!env.CREDENTIAL_ENCRYPTION_KEY) throw new HttpError(503, "credential_encryption_not_configured", "Credential encryption is not configured");
  const provider = providerDefinition(connection.provider); if (!provider) throw new HttpError(422, "provider_unsupported", "The provider is not in the supported catalog");
  if (!provider.verify) throw new HttpError(422, "provider_unverified", "This provider is catalogued but has no live verification adapter");
  let credential: string; try { credential = await decryptSecret(connection.encrypted_secret, env.CREDENTIAL_ENCRYPTION_KEY); } catch { throw new HttpError(503, "credential_encryption_not_configured", "Stored credential cannot be decrypted with the configured encryption key"); }
  const result = await provider.verify(credential); const timestamp = now();
  if (result.verified) { await db.prepare("UPDATE ai_provider_connections SET status='verified',last_verified_at=?1,last_error_code=NULL,updated_at=?1 WHERE id=?2").bind(timestamp, connection.id).run(); return json({ data: { provider: provider.id, verified: true, status: "verified" } }); }
  const code = result.code ?? "provider_unavailable"; await db.prepare("UPDATE ai_provider_connections SET status=?1,last_error_code=?2,updated_at=?3 WHERE id=?4").bind(code === "credential_invalid" ? "invalid" : "unverified", code, timestamp, connection.id).run();
  throw new HttpError(code === "credential_invalid" ? 422 : 503, code, code === "credential_invalid" ? "The provider rejected the credential" : "The provider could not be reached or verified");
}

type AssetRow = { id: string; workspace_id: string; kind: string; media_type: string; original_filename: string; bytes: number; checksum: string | null; duration_seconds: number | null; width: number | null; height: number | null; metadata: string; license_type: string | null; license_id: string | null; source_url: string | null; rights_confirmed: number; attribution_required: number; attribution_text: string | null; scan_status: string; licensing_status: string; status: string; blocked_reason: string | null; created_by_user_id: string; created_at: string; updated_at: string };

function publicAsset(asset: AssetRow) {
  return { id: asset.id, workspace_id: asset.workspace_id, kind: asset.kind, media_type: asset.media_type, original_filename: asset.original_filename, bytes: asset.bytes, checksum: asset.checksum, duration_seconds: asset.duration_seconds, dimensions: asset.width && asset.height ? { width: asset.width, height: asset.height } : null, metadata: JSON.parse(asset.metadata), licensing: { type: asset.license_type, id: asset.license_id, source_url: asset.source_url, rights_confirmed: Boolean(asset.rights_confirmed), attribution_required: Boolean(asset.attribution_required), attribution_text: asset.attribution_text }, scan_status: asset.scan_status, licensing_status: asset.licensing_status, status: asset.status, blocked_reason: asset.blocked_reason, created_at: asset.created_at, updated_at: asset.updated_at };
}

function videoType(value: unknown): string { const mediaType = requiredString(value, "media_type", 120).toLowerCase(); if (!VIDEO_TYPES.has(mediaType)) throw new ValidationError("media_type must be a supported real-video type"); return mediaType; }
function positiveBytes(value: unknown): number { if (!Number.isInteger(value) || Number(value) < 1 || Number(value) > MAX_ASSET_BYTES) throw new ValidationError(`bytes must be an integer between 1 and ${MAX_ASSET_BYTES}`); return Number(value); }
function checksum(value: unknown): string { const normalized = requiredString(value, "checksum", 64).toLowerCase(); if (!/^[a-f0-9]{64}$/.test(normalized)) throw new ValidationError("checksum must be a SHA-256 hex digest"); return normalized; }
function booleanField(value: unknown, field: string): boolean { if (typeof value !== "boolean") throw new ValidationError(`${field} must be a boolean`); return value; }

async function createUploadIntent(request: Request, db: D1Database, auth: Auth, env: Env, workspaceId: string) {
  if (!env.ASSETS) throw new HttpError(503, "storage_unavailable", "Private asset storage is not configured");
  await providerAccess(request, db, auth, workspaceId);
  const input = await body(request); const mediaType = videoType(input.media_type); const bytes = positiveBytes(input.bytes); const filename = requiredString(input.filename, "filename", 255);
  const id = randomId(); const token = randomToken(); const created = now(); const expires = new Date(Date.now() + UPLOAD_TTL_MS).toISOString(); const storageKey = `workspaces/${workspaceId}/assets/${id}/source`;
  await db.prepare("INSERT INTO assets (id,workspace_id,storage_key,media_type,original_filename,bytes,upload_token_hash,upload_expires_at,created_by_user_id,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)").bind(id, workspaceId, storageKey, mediaType, filename, bytes, await sha256(token), expires, auth.user.id, created).run();
  const uploadUrl = new URL(`/v1/assets/uploads/${id}/content`, request.url); uploadUrl.searchParams.set("token", token);
  return json({ data: { asset_id: id, upload_url: uploadUrl.toString(), expires_at: expires, max_bytes: bytes, media_type: mediaType } }, 201);
}

async function uploadAssetContent(request: Request, db: D1Database, env: Env, assetId: string) {
  if (!env.ASSETS) throw new HttpError(503, "storage_unavailable", "Private asset storage is not configured");
  const token = new URL(request.url).searchParams.get("token"); if (!token) throw new HttpError(401, "upload_token_required", "The upload token is required");
  const asset = await db.prepare("SELECT id,storage_key,media_type,bytes,upload_expires_at,status,upload_token_hash FROM assets WHERE id=?1").bind(assetId).first<{ id: string; storage_key: string; media_type: string; bytes: number; upload_expires_at: string; status: string; upload_token_hash: string }>();
  if (!asset || asset.status !== "pending_upload" || asset.upload_expires_at < now() || !(await sha256(token) === asset.upload_token_hash)) throw new HttpError(404, "upload_not_found", "Upload intent not found or expired");
  if (request.headers.get("content-type")?.split(";", 1)[0].toLowerCase() !== asset.media_type) throw new HttpError(415, "media_type_mismatch", "The uploaded media type does not match the upload intent");
  const contentLength = Number(request.headers.get("content-length")); if (!Number.isInteger(contentLength) || contentLength !== asset.bytes) throw new HttpError(400, "byte_size_mismatch", "The uploaded byte size does not match the upload intent");
  const data = await request.arrayBuffer(); if (data.byteLength !== asset.bytes) throw new HttpError(400, "byte_size_mismatch", "The uploaded byte size does not match the upload intent");
  const digest = await sha256Bytes(data);
  await env.ASSETS.put(asset.storage_key, data, { httpMetadata: { contentType: asset.media_type }, customMetadata: { checksum: digest } });
  return json({ data: { asset_id: asset.id, uploaded: true } });
}

async function sha256Bytes(value: ArrayBuffer): Promise<string> { const digest = await crypto.subtle.digest("SHA-256", value); return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""); }

function licensing(input: Record<string, unknown>) {
  const type = requiredString(input.license_type, "license_type", 40); if (!LICENSE_TYPES.has(type)) throw new ValidationError("license_type is invalid");
  const rights = booleanField(input.rights_confirmed, "rights_confirmed"); if (!rights) throw new ValidationError("rights_confirmed must be true");
  const attribution = input.attribution_required === undefined ? false : booleanField(input.attribution_required, "attribution_required");
  const sourceUrl = input.source_url === undefined ? null : requiredString(input.source_url, "source_url", 2048); const licenseId = input.license_id === undefined ? null : requiredString(input.license_id, "license_id", 255); const attributionText = input.attribution_text === undefined ? null : requiredString(input.attribution_text, "attribution_text", 2000);
  if (type === "licensed" && !licenseId) throw new ValidationError("license_id is required for licensed footage");
  return { type, rights: 1, attribution: attribution ? 1 : 0, sourceUrl, licenseId, attributionText };
}

async function completeAsset(request: Request, db: D1Database, auth: Auth, env: Env, assetId: string) {
  const asset = await db.prepare("SELECT * FROM assets WHERE id=?1").bind(assetId).first<AssetRow & { storage_key: string; upload_expires_at: string | null }>(); if (!asset) throw new HttpError(404, "asset_not_found", "Asset not found"); await providerAccess(request, db, auth, asset.workspace_id);
  if (asset.created_by_user_id !== auth.user.id && !["owner", "admin"].includes(String((await workspace(request, db, auth.user.id, asset.workspace_id))?.role))) throw new HttpError(403, "forbidden", "Only the uploader or a workspace owner/admin can complete this upload");
  if (!env.ASSETS) throw new HttpError(503, "storage_unavailable", "Private asset storage is not configured"); const object = await env.ASSETS.head(asset.storage_key); if (!object) throw new HttpError(409, "upload_incomplete", "Upload content must be stored before completion");
  if (object.size !== asset.bytes) throw new HttpError(400, "byte_size_mismatch", "Stored object size does not match the upload intent");
  const input = await body(request); const duration = input.duration_seconds; if (typeof duration !== "number" || !Number.isFinite(duration) || duration <= 0 || duration > 3600) throw new ValidationError("duration_seconds must be a positive number no greater than 3600"); const suppliedChecksum = checksum(input.checksum); const storedChecksum = object.customMetadata?.checksum; if (!storedChecksum || storedChecksum !== suppliedChecksum) throw new HttpError(400, "checksum_mismatch", "Submitted checksum does not match the uploaded object");
  const rights = licensing(input); const width = input.width === undefined ? null : positiveDimension(input.width, "width"); const height = input.height === undefined ? null : positiveDimension(input.height, "height"); const metadata = input.metadata === undefined ? {} : asRecord(input.metadata); const references = input.references === undefined ? [] : input.references; if (!Array.isArray(references)) throw new ValidationError("references must be an array");
  const created = now(); const blockedReason = "malware_scanner_unavailable";
  await db.batch([db.prepare("UPDATE assets SET checksum=?1,duration_seconds=?2,width=?3,height=?4,metadata=?5,license_type=?6,license_id=?7,source_url=?8,rights_confirmed=?9,attribution_required=?10,attribution_text=?11,scan_status='unavailable',licensing_status='valid',status='blocked',blocked_reason=?12,upload_token_hash=NULL,upload_expires_at=NULL,updated_at=?13 WHERE id=?14").bind(suppliedChecksum, duration, width, height, JSON.stringify(metadata), rights.type, rights.licenseId, rights.sourceUrl, rights.rights, rights.attribution, rights.attributionText, blockedReason, created, assetId), ...references.map((reference) => assetReferenceStatement(db, reference, assetId, created))]);
  return json({ data: { ...publicAsset({ ...asset, checksum: suppliedChecksum, duration_seconds: duration, width, height, metadata: JSON.stringify(metadata), license_type: rights.type, license_id: rights.licenseId, source_url: rights.sourceUrl, rights_confirmed: rights.rights, attribution_required: rights.attribution, attribution_text: rights.attributionText, scan_status: "unavailable", licensing_status: "valid", status: "blocked", blocked_reason: blockedReason, updated_at: created }), readiness: "blocked", reason: blockedReason } });
}

function positiveDimension(value: unknown, field: string): number { if (!Number.isInteger(value) || Number(value) < 1 || Number(value) > 100000) throw new ValidationError(`${field} is invalid`); return Number(value); }
function assetReferenceStatement(db: D1Database, reference: unknown, assetId: string, created: string) { const item = asRecord(reference); const source = requiredString(item.source, "references.source", 120); const sourceUrl = item.source_url === undefined ? null : requiredString(item.source_url, "references.source_url", 2048); const licenseId = item.license_id === undefined ? null : requiredString(item.license_id, "references.license_id", 255); const expiresAt = item.expires_at === undefined ? null : requiredString(item.expires_at, "references.expires_at", 80); const attribution = item.attribution_required === undefined ? false : booleanField(item.attribution_required, "references.attribution_required"); const scope = item.usage_scope === undefined ? null : requiredString(item.usage_scope, "references.usage_scope", 255); return db.prepare("INSERT INTO asset_references (id,asset_id,source,source_url,license_id,expires_at,attribution_required,usage_scope,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)").bind(randomId(), assetId, source, sourceUrl, licenseId, expiresAt, attribution ? 1 : 0, scope, created); }

async function listAssets(request: Request, db: D1Database, auth: Auth, workspaceId: string) { await providerAccess(request, db, auth, workspaceId); const rows = await db.prepare("SELECT id,workspace_id,kind,media_type,original_filename,bytes,checksum,duration_seconds,width,height,metadata,license_type,license_id,source_url,rights_confirmed,attribution_required,attribution_text,scan_status,licensing_status,status,blocked_reason,created_by_user_id,created_at,updated_at FROM assets WHERE workspace_id=?1 ORDER BY created_at DESC").bind(workspaceId).all<AssetRow>(); return json({ data: rows.results.map(publicAsset) }); }
async function getAsset(request: Request, db: D1Database, auth: Auth, assetId: string) { const asset = await db.prepare("SELECT id,workspace_id,kind,media_type,original_filename,bytes,checksum,duration_seconds,width,height,metadata,license_type,license_id,source_url,rights_confirmed,attribution_required,attribution_text,scan_status,licensing_status,status,blocked_reason,created_by_user_id,created_at,updated_at FROM assets WHERE id=?1").bind(assetId).first<AssetRow>(); if (!asset) throw new HttpError(404, "asset_not_found", "Asset not found"); await providerAccess(request, db, auth, asset.workspace_id); const references = await db.prepare("SELECT id,source,source_url,license_id,expires_at,attribution_required,usage_scope,created_at FROM asset_references WHERE asset_id=?1 ORDER BY created_at ASC").bind(assetId).all(); return json({ data: { ...publicAsset(asset), references: references.results } }); }
async function downloadAsset(request: Request, db: D1Database, auth: Auth, env: Env, assetId: string) { if (!env.ASSETS) throw new HttpError(503, "storage_unavailable", "Private asset storage is not configured"); const asset = await db.prepare("SELECT id,workspace_id,storage_key,media_type,original_filename,status FROM assets WHERE id=?1").bind(assetId).first<{ id: string; workspace_id: string; storage_key: string; media_type: string; original_filename: string; status: string }>(); if (!asset) throw new HttpError(404, "asset_not_found", "Asset not found"); await providerAccess(request, db, auth, asset.workspace_id); if (asset.status !== "ready") throw new HttpError(409, "asset_not_ready", "This asset is not ready for download"); const object = await env.ASSETS.get(asset.storage_key); if (!object) throw new HttpError(404, "asset_content_not_found", "Asset content not found"); return new Response(object.body, { headers: { "cache-control": "private, no-store", "content-type": asset.media_type, "content-disposition": `inline; filename="${asset.original_filename.replaceAll(/["\\\r\n]/g, "_")}"` } }); }

type PublishingConnection = { id: string; workspace_id: string; platform: PublishingPlatform; account_id: string | null; channel_id: string | null; scopes: string; encrypted_access_token: string | null; encrypted_refresh_token: string | null; access_expires_at: string | null; credential_status: string; last_verified_at: string | null; last_error_code: string | null; created_at: string; updated_at: string };
const publishingConnectionSelect = "SELECT id,workspace_id,platform,account_id,channel_id,scopes,encrypted_access_token,encrypted_refresh_token,access_expires_at,credential_status,last_verified_at,last_error_code,created_at,updated_at FROM publishing_connections";

function publishingRole(role: unknown): boolean { return ["owner", "admin"].includes(String(role)); }
function callbackUrl(request: Request, env: Env): string { if (!env.PUBLIC_BASE_URL) throw new HttpError(503, "platform_client_not_configured", "OAuth callback base URL is not configured"); return `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/v1/publishing/oauth/callback`; }
function clientConfig(env: Env, target: PublishingPlatform): { id: string; secret: string } {
  const id = target === "youtube" ? env.YOUTUBE_CLIENT_ID : env.INSTAGRAM_CLIENT_ID;
  const secret = target === "youtube" ? env.YOUTUBE_CLIENT_SECRET : env.INSTAGRAM_CLIENT_SECRET;
  if (!id || !secret) throw new HttpError(503, "platform_client_not_configured", `The ${target} OAuth client is not configured`);
  return { id, secret };
}
function publicPublishingConnection(row: PublishingConnection) { return publicConnection(row); }

async function publishingConnections(request: Request, db: D1Database, auth: Auth, workspaceId: string) {
  await providerAccess(request, db, auth, workspaceId);
  const rows = await db.prepare(`${publishingConnectionSelect} WHERE workspace_id=?1 ORDER BY platform`).bind(workspaceId).all<PublishingConnection>();
  return json({ data: rows.results.map(publicPublishingConnection) });
}

async function startPublishingOAuth(request: Request, db: D1Database, auth: Auth, env: Env, workspaceId: string) {
  const member = await providerAccess(request, db, auth, workspaceId, true);
  if (!publishingRole(member.role)) throw new HttpError(403, "forbidden", "Only workspace owners and admins can manage publishing connections");
  const input = await body(request); const target = input.platform;
  if (target !== "youtube" && target !== "instagram") throw new ValidationError("platform must be youtube or instagram");
  const platform = target as PublishingPlatform; const nonce = randomToken(); const state = `${randomToken()}.${nonce}`; const created = now(); const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  let status: "pending" | "blocked" = "pending"; let errorCode: string | null = null; let url: string | null = null;
  try { const client = clientConfig(env, platform); url = oauthAuthorizationUrl(platform, client.id, callbackUrl(request, env), state, nonce); } catch (error) { if (!(error instanceof HttpError)) throw error; status = "blocked"; errorCode = error.code; }
  await db.prepare("INSERT INTO publishing_oauth_states (id,workspace_id,user_id,platform,state_hash,nonce_hash,expires_at,status,error_code,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)").bind(randomId(), workspaceId, auth.user.id, platform, await sha256(state), await sha256(nonce), expires, status, errorCode, created).run();
  if (!url) throw new HttpError(503, errorCode ?? "platform_client_not_configured", "Publishing OAuth cannot start until platform credentials are configured");
  return json({ data: { platform, authorization_url: url, expires_at: expires } }, 201);
}

async function oauthJson(response: Response): Promise<Record<string, unknown>> { try { return asRecord(await response.json()); } catch { throw new HttpError(503, "platform_api_unavailable", "The platform returned an invalid OAuth response"); } }
async function exchangeCode(platform: PublishingPlatform, code: string, redirectUri: string, env: Env): Promise<{ access: string; refresh: string | null; expiresAt: string | null; accountId: string | null; channelId: string | null; scopes: string[] }> {
  const client = clientConfig(env, platform);
  const tokenUrl = platform === "youtube" ? "https://oauth2.googleapis.com/token" : "https://graph.facebook.com/v21.0/oauth/access_token";
  const values: Record<string, string> = platform === "youtube" ? { code, client_id: client.id, client_secret: client.secret, redirect_uri: redirectUri, grant_type: "authorization_code" } : { code, client_id: client.id, client_secret: client.secret, redirect_uri: redirectUri };
  const response = await fetch(tokenUrl, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(values) });
  if (!response.ok) throw new HttpError(response.status >= 500 ? 503 : 422, response.status >= 500 ? "platform_api_unavailable" : "oauth_authorization_required", "The platform rejected OAuth authorization");
  const result = await oauthJson(response); const access = typeof result.access_token === "string" ? result.access_token : null;
  if (!access) throw new HttpError(503, "platform_api_unavailable", "The platform did not return an access token");
  const expiresAt = typeof result.expires_in === "number" ? new Date(Date.now() + result.expires_in * 1000).toISOString() : null;
  let accountId: string | null = typeof result.user_id === "string" ? result.user_id : null; let channelId: string | null = null; let scopes = PLATFORM_RULES[platform].scopes;
  if (platform === "youtube") {
    const channels = await fetch("https://www.googleapis.com/youtube/v3/channels?part=id,snippet&mine=true", { headers: { authorization: `Bearer ${access}` } });
    if (!channels.ok) throw new HttpError(503, "platform_api_unavailable", "YouTube channel discovery is unavailable");
    const data = await oauthJson(channels); const items = Array.isArray(data.items) ? data.items : []; const channel = items[0];
    if (!channel || typeof channel !== "object" || typeof (channel as Record<string, unknown>).id !== "string") throw new HttpError(422, "oauth_authorization_required", "The Google account has no accessible YouTube channel");
    channelId = String((channel as Record<string, unknown>).id); accountId = accountId ?? channelId;
    if (typeof result.scope === "string") scopes = result.scope.split(" ").filter(Boolean);
  } else {
    const account = await fetch(`https://graph.facebook.com/v21.0/me?fields=id,username,account_type&access_token=${encodeURIComponent(access)}`);
    if (!account.ok) throw new HttpError(503, "platform_api_unavailable", "Instagram account discovery is unavailable");
    const data = await oauthJson(account); if (data.account_type !== "BUSINESS" && data.account_type !== "CREATOR") throw new HttpError(422, "capability_unsupported", "Instagram publishing requires a professional account"); accountId = typeof data.id === "string" ? data.id : accountId;
  }
  return { access, refresh: typeof result.refresh_token === "string" ? result.refresh_token : null, expiresAt, accountId, channelId, scopes };
}

async function oauthCallback(request: Request, db: D1Database, env: Env) {
  const query = new URL(request.url).searchParams; const state = query.get("state"); const code = query.get("code"); if (!state) throw new HttpError(400, "oauth_state_invalid", "OAuth state is required");
  const pending = await db.prepare("SELECT * FROM publishing_oauth_states WHERE state_hash=?1").bind(await sha256(state)).first<{ id: string; workspace_id: string; user_id: string; platform: PublishingPlatform; nonce_hash: string; expires_at: string; status: string }>();
  const stateNonce = state.split(".").at(-1) ?? "";
  if (!pending || pending.status !== "pending" || pending.expires_at <= now() || !(await sha256(stateNonce) === pending.nonce_hash)) throw new HttpError(400, "oauth_state_invalid", "OAuth state or nonce is invalid or expired");
  if (query.get("error") || !code) { await db.prepare("UPDATE publishing_oauth_states SET status='error',error_code='oauth_authorization_required',used_at=?1 WHERE id=?2").bind(now(), pending.id).run(); throw new HttpError(422, "oauth_authorization_required", "The user did not authorize the platform"); }
  let tokens: Awaited<ReturnType<typeof exchangeCode>>;
  try { tokens = await exchangeCode(pending.platform, code, callbackUrl(request, env), env); } catch (error) { const codeValue = error instanceof HttpError ? error.code : "platform_api_unavailable"; await db.prepare("UPDATE publishing_oauth_states SET status='error',error_code=?1,used_at=?2 WHERE id=?3").bind(codeValue, now(), pending.id).run(); throw error; }
  let encryptedAccess: string; let encryptedRefresh: string | null = null;
  try { encryptedAccess = await encryptSecret(tokens.access, env.CREDENTIAL_ENCRYPTION_KEY); if (tokens.refresh) encryptedRefresh = await encryptSecret(tokens.refresh, env.CREDENTIAL_ENCRYPTION_KEY); } catch { await db.prepare("UPDATE publishing_oauth_states SET status='blocked',error_code='credential_encryption_not_configured',used_at=?1 WHERE id=?2").bind(now(), pending.id).run(); throw new HttpError(503, "credential_encryption_not_configured", "Credential encryption is not configured correctly"); }
  const timestamp = now();
  await db.batch([
    db.prepare("UPDATE publishing_oauth_states SET status='used',used_at=?1 WHERE id=?2").bind(timestamp, pending.id),
    db.prepare("INSERT INTO publishing_connections (id,workspace_id,platform,account_id,channel_id,scopes,encrypted_access_token,encrypted_refresh_token,access_expires_at,credential_status,last_verified_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'active',?10,?10,?10) ON CONFLICT(workspace_id,platform) DO UPDATE SET account_id=excluded.account_id,channel_id=excluded.channel_id,scopes=excluded.scopes,encrypted_access_token=excluded.encrypted_access_token,encrypted_refresh_token=excluded.encrypted_refresh_token,access_expires_at=excluded.access_expires_at,credential_status='active',last_error_code=NULL,last_verified_at=excluded.last_verified_at,updated_at=excluded.updated_at").bind(randomId(), pending.workspace_id, pending.platform, tokens.accountId, tokens.channelId, JSON.stringify(tokens.scopes), encryptedAccess, encryptedRefresh, tokens.expiresAt, timestamp),
  ]);
  return json({ data: { connected: true, platform: pending.platform } });
}

async function revokePublishingConnection(request: Request, db: D1Database, auth: Auth, env: Env, id: string) {
  const connection = await db.prepare(`${publishingConnectionSelect} WHERE id=?1`).bind(id).first<PublishingConnection>(); if (!connection) throw new HttpError(404, "publishing_connection_not_found", "Publishing connection not found"); const member = await providerAccess(request, db, auth, connection.workspace_id, true); if (!publishingRole(member.role)) throw new HttpError(403, "forbidden", "Only workspace owners and admins can revoke publishing connections");
  if (!connection.encrypted_access_token || !env.CREDENTIAL_ENCRYPTION_KEY) throw new HttpError(409, "connection_not_active", "The publishing connection has no active credential");
  let token: string; try { token = await decryptSecret(connection.encrypted_access_token, env.CREDENTIAL_ENCRYPTION_KEY); } catch { throw new HttpError(503, "credential_encryption_not_configured", "Stored platform credential cannot be decrypted"); }
  const response = connection.platform === "youtube" ? await fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`, { method: "POST" }) : await fetch(`https://graph.facebook.com/v21.0/${encodeURIComponent(connection.account_id ?? "me")}/permissions?access_token=${encodeURIComponent(token)}`, { method: "DELETE" });
  if (!response.ok) { await db.prepare("UPDATE publishing_connections SET credential_status='error',last_error_code='platform_api_unavailable',updated_at=?1 WHERE id=?2").bind(now(), id).run(); throw new HttpError(503, "platform_api_unavailable", "The platform did not confirm credential revocation"); }
  await db.prepare("UPDATE publishing_connections SET encrypted_access_token=NULL,encrypted_refresh_token=NULL,credential_status='revoked',last_error_code=NULL,updated_at=?1 WHERE id=?2").bind(now(), id).run(); return json({ data: { id, credential_status: "revoked" } });
}

type PublishRequestRow = { id: string; workspace_id: string; production_job_id: string; quality_gate_run_id: string; connection_id: string; asset_id: string; scheduled_for: string; idempotency_key: string; payload: string; platform_payload_hash: string; status: string; attempts: number; next_attempt_at: string | null; last_error_code: string | null; last_error_message: string | null; created_by_user_id: string; created_at: string; updated_at: string };
function publicPublishRequest(row: PublishRequestRow) { return { ...row, payload: JSON.parse(row.payload) }; }

async function createPublishRequest(request: Request, db: D1Database, auth: Auth, workspaceId: string) {
  const member = await providerAccess(request, db, auth, workspaceId); if (!member || !["owner", "admin", "editor"].includes(String(member.role))) throw new HttpError(403, "forbidden", "Only active editors can schedule publishing");
  const idempotencyKey = requiredString(request.headers.get("Idempotency-Key"), "Idempotency-Key", 200); const input = await body(request);
  const target = input.platform; if (target !== "youtube" && target !== "instagram") throw new ValidationError("platform must be youtube or instagram"); const platform = target as PublishingPlatform;
  const productionJobId = requiredString(input.production_job_id, "production_job_id", 100); const assetId = requiredString(input.asset_id, "asset_id", 100); const connectionId = requiredString(input.connection_id, "connection_id", 100); const scheduledFor = requiredString(input.scheduled_for, "scheduled_for", 80); const scheduledDate = new Date(scheduledFor); if (Number.isNaN(scheduledDate.getTime())) throw new ValidationError("scheduled_for must be an ISO timestamp");
  const title = requiredString(input.title, "title", 500); const description = requiredString(input.description ?? input.caption, "description", 6000); const tags = input.tags === undefined ? [] : input.tags; if (!Array.isArray(tags) || tags.some((tag) => typeof tag !== "string" || tag.trim().length === 0 || tag.length > 100)) throw new ValidationError("tags must be non-empty strings no longer than 100 characters");
  const job = await db.prepare("SELECT id,status,asset_ids FROM production_jobs WHERE id=?1 AND workspace_id=?2").bind(productionJobId, workspaceId).first<{ id: string; status: string; asset_ids: string }>(); if (!job) throw new HttpError(404, "production_job_not_found", "Production job not found"); if (job.status !== "completed") throw new HttpError(409, "production_not_approved", "A completed production job is required before publishing");
  let assetIds: unknown; try { assetIds = JSON.parse(job.asset_ids); } catch { throw new HttpError(500, "internal_error", "Production asset metadata is invalid"); } if (!Array.isArray(assetIds) || !assetIds.includes(assetId)) throw new HttpError(422, "asset_not_in_production", "The selected asset is not part of the production job");
  const asset = await db.prepare("SELECT id,duration_seconds,status,scan_status,licensing_status,rights_confirmed,license_type FROM assets WHERE id=?1 AND workspace_id=?2").bind(assetId, workspaceId).first<{ id: string; duration_seconds: number; status: string; scan_status: string; licensing_status: string; rights_confirmed: number; license_type: string | null }>(); if (!asset) throw new HttpError(422, "asset_not_found", "The asset does not belong to this workspace"); if (asset.status !== "ready" || asset.scan_status !== "clean" || asset.licensing_status !== "valid" || !asset.rights_confirmed) throw new HttpError(409, asset.scan_status === "unavailable" ? "malware_scanner_unavailable" : "asset_not_ready", "The real-footage asset has not passed readiness and licensing checks");
  const quality = await db.prepare("SELECT id FROM quality_gate_runs WHERE idempotency_key IS NOT NULL AND production_job_id=?1 AND workspace_id=?2 AND status='passed' ORDER BY created_at DESC LIMIT 1").bind(productionJobId, workspaceId).first<{ id: string }>(); if (!quality) throw new HttpError(409, "quality_gate_blocked", "A passed quality gate is required before publishing"); const decision = await db.prepare("SELECT id FROM quality_gate_decisions WHERE quality_gate_run_id=?1 AND decision='approved'").bind(quality.id).first(); if (!decision) throw new HttpError(409, "approval_required", "A reviewer approval is required before publishing");
  const connection = await db.prepare(`${publishingConnectionSelect} WHERE id=?1 AND workspace_id=?2 AND platform=?3`).bind(connectionId, workspaceId, platform).first<PublishingConnection>(); if (!connection) throw new HttpError(404, "publishing_connection_not_found", "Publishing connection not found"); if (connection.credential_status !== "active") throw new HttpError(409, connection.credential_status === "expired" ? "connection_expired" : "connection_not_active", "The publishing connection is not active"); if (connection.access_expires_at && connection.access_expires_at <= now()) throw new HttpError(409, "connection_expired", "The publishing access token has expired"); const requiredScopes = PLATFORM_RULES[platform].scopes; const grantedScopes = JSON.parse(connection.scopes) as string[]; if (!requiredScopes.every((scope) => grantedScopes.includes(scope))) throw new HttpError(409, "scope_missing", "The publishing connection is missing required platform scopes");
  const policy = await db.prepare("SELECT enabled_capabilities,stop_switch FROM automation_policies WHERE workspace_id=?1").bind(workspaceId).first<{ enabled_capabilities: string; stop_switch: number }>(); if (!policy || policy.stop_switch || !JSON.parse(policy.enabled_capabilities).includes("publishing")) throw new HttpError(409, "policy_blocked", "Workspace automation policy does not permit publishing");
  const errors = validatePublishPayload(platform, { title, description, durationSeconds: asset.duration_seconds }); if (errors.length) throw new HttpError(422, "platform_constraints_invalid", "Publishing metadata does not satisfy platform constraints", { platform, errors });
  const payload = { platform, title, description, tags, asset_id: assetId, scheduled_for: scheduledDate.toISOString() }; const hash = await sha256(JSON.stringify(payload)); const existing = await db.prepare("SELECT * FROM publish_requests WHERE workspace_id=?1 AND idempotency_key=?2").bind(workspaceId, idempotencyKey).first<PublishRequestRow>(); if (existing) { if (existing.platform_payload_hash !== hash) throw new HttpError(409, "idempotency_conflict", "Idempotency key was used for different publishing metadata"); return json({ data: publicPublishRequest(existing) }); }
  const timestamp = now(); const id = randomId(); await db.batch([db.prepare("INSERT INTO publish_requests (id,workspace_id,production_job_id,quality_gate_run_id,connection_id,asset_id,scheduled_for,idempotency_key,payload,platform_payload_hash,status,next_attempt_at,created_by_user_id,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'queued',?7,?11,?12,?12) ON CONFLICT(workspace_id,idempotency_key) DO NOTHING").bind(id, workspaceId, productionJobId, quality.id, connectionId, assetId, scheduledDate.toISOString(), idempotencyKey, JSON.stringify(payload), hash, auth.user.id, timestamp), db.prepare("INSERT INTO publish_request_events (id,publish_request_id,status,reason_code,attempt,created_at) VALUES (?1,?2,'queued',NULL,0,?3)").bind(randomId(), id, timestamp)]); const created = await db.prepare("SELECT * FROM publish_requests WHERE workspace_id=?1 AND idempotency_key=?2").bind(workspaceId, idempotencyKey).first<PublishRequestRow>(); if (!created) throw new HttpError(500, "internal_error", "Publish request could not be recorded"); return json({ data: publicPublishRequest(created) }, 201);
}

async function performYouTubeUpload(env: Env, connection: PublishingConnection, asset: { storage_key: string; media_type: string; bytes: number }, payload: { title: string; description: string; tags: string[]; scheduled_for: string }, token: string): Promise<{ id: string; url: string }> {
  if (!env.ASSETS) throw new HttpError(503, "media_upload_unavailable", "Private asset storage is not configured for platform upload"); const object = await env.ASSETS.get(asset.storage_key); if (!object) throw new HttpError(503, "media_upload_unavailable", "The source media is unavailable");
  const initiate = await fetch("https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status", { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json; charset=UTF-8", "x-upload-content-type": asset.media_type, "x-upload-content-length": String(asset.bytes) }, body: JSON.stringify({ snippet: { title: payload.title, description: payload.description, tags: payload.tags }, status: { privacyStatus: new Date(payload.scheduled_for) > new Date() ? "private" : "public", ...(new Date(payload.scheduled_for) > new Date() ? { publishAt: payload.scheduled_for } : {}) } }) });
  if (!initiate.ok) throw new HttpError(initiate.status === 429 || initiate.status >= 500 ? 503 : 422, initiate.status === 429 || initiate.status >= 500 ? "platform_api_unavailable" : "platform_rejected", "YouTube rejected the upload request"); const location = initiate.headers.get("location"); if (!location) throw new HttpError(503, "platform_api_unavailable", "YouTube did not return an upload location");
  const uploaded = await fetch(location, { method: "PUT", headers: { authorization: `Bearer ${token}`, "content-type": asset.media_type, "content-length": String(asset.bytes) }, body: object.body }); if (!uploaded.ok) throw new HttpError(uploaded.status === 429 || uploaded.status >= 500 ? 503 : 422, uploaded.status === 429 || uploaded.status >= 500 ? "platform_api_unavailable" : "platform_rejected", "YouTube rejected the media upload"); const data = await oauthJson(uploaded); if (typeof data.id !== "string") throw new HttpError(503, "platform_api_unavailable", "YouTube did not return a video identifier"); return { id: data.id, url: `https://www.youtube.com/shorts/${data.id}` };
}

async function attemptPublish(request: Request, db: D1Database, auth: Auth, env: Env, id: string) {
  const publish = await db.prepare("SELECT * FROM publish_requests WHERE id=?1").bind(id).first<PublishRequestRow>(); if (!publish) throw new HttpError(404, "publish_request_not_found", "Publish request not found"); await providerAccess(request, db, auth, publish.workspace_id); if (!["queued", "retry_scheduled"].includes(publish.status) || (publish.next_attempt_at && publish.next_attempt_at > now())) throw new HttpError(409, "publish_not_due", "The publish request is not due");
  const connection = await db.prepare(`${publishingConnectionSelect} WHERE id=?1`).bind(publish.connection_id).first<PublishingConnection>(); if (!connection) throw new HttpError(409, "publishing_connection_not_found", "Publishing connection no longer exists"); const payload = JSON.parse(publish.payload) as { platform: PublishingPlatform; title: string; description: string; tags: string[]; scheduled_for: string };
  if (payload.platform === "instagram") { await db.prepare("UPDATE publish_requests SET status='blocked',last_error_code='media_upload_unavailable',last_error_message='Instagram Graph API requires a publicly reachable media URL; the asset store is private and no official media delivery capability is configured',updated_at=?1 WHERE id=?2").bind(now(), id).run(); throw new HttpError(409, "media_upload_unavailable", "Instagram publishing is blocked until an official public media delivery capability is configured"); }
  if (!env.CREDENTIAL_ENCRYPTION_KEY || !connection.encrypted_access_token) throw new HttpError(409, "credential_required", "The publishing credential is unavailable"); if (connection.access_expires_at && connection.access_expires_at <= now()) { await db.prepare("UPDATE publishing_connections SET credential_status='expired',last_error_code='connection_expired',updated_at=?1 WHERE id=?2").bind(now(), connection.id).run(); throw new HttpError(409, "connection_expired", "The publishing access token has expired"); }
  let token: string; try { token = await decryptSecret(connection.encrypted_access_token, env.CREDENTIAL_ENCRYPTION_KEY); } catch { throw new HttpError(503, "credential_encryption_not_configured", "Stored publishing credential cannot be decrypted"); }
  const asset = await db.prepare("SELECT storage_key,media_type,bytes FROM assets WHERE id=?1 AND workspace_id=?2 AND status='ready'").bind(publish.asset_id, publish.workspace_id).first<{ storage_key: string; media_type: string; bytes: number }>(); if (!asset) throw new HttpError(409, "asset_not_ready", "The source asset is no longer ready");
  // Reserve at the last possible point before the sole platform side effect.
  const timestamp = now(); const reservation = await reserveUsage(db, { workspaceId: publish.workspace_id, userId: publish.created_by_user_id, boundary: 'publish', idempotencyKey: `publish:${publish.id}`, requestHash: publish.platform_payload_hash, estimateMicrousd: 0, at: timestamp, id: randomId(), ledgerId: randomId() });
  if (!reservation.ok) { await db.prepare("UPDATE publish_requests SET status='blocked',last_error_code=?1,last_error_message=?2,updated_at=?3 WHERE id=?4").bind(reservation.code, 'Publishing is blocked until verified billing, pricing, entitlement, and cost evidence are available', timestamp, id).run(); throw new HttpError(409, reservation.code, 'Publishing is blocked before the platform call'); }
  const attempt = publish.attempts + 1; await db.prepare("UPDATE publish_requests SET status='processing',attempts=?1,updated_at=?2 WHERE id=?3").bind(attempt, now(), id).run();
  try { const result = await performYouTubeUpload(env, connection, asset, payload, token); const timestamp = now(); await db.batch([db.prepare("INSERT INTO published_posts (id,workspace_id,publish_request_id,platform,platform_post_id,url,published_at) VALUES (?1,?2,?3,'youtube',?4,?5,?6)").bind(randomId(), publish.workspace_id, id, result.id, result.url, timestamp), db.prepare("UPDATE publish_requests SET status='succeeded',last_error_code=NULL,last_error_message=NULL,updated_at=?1 WHERE id=?2").bind(timestamp, id)]); return json({ data: { id, status: "succeeded", platform_post_id: result.id, url: result.url } }); } catch (error) { await releaseUsage(db,reservation.reservation_id,'provider_call_failed',now(),randomId()); const http = error instanceof HttpError ? error : new HttpError(503, "platform_api_unavailable", "The platform could not complete the upload"); const retryable = http.code === "platform_api_unavailable"; const next = retryable ? new Date(Date.now() + retryDelaySeconds(attempt) * 1000).toISOString() : null; await db.prepare("UPDATE publish_requests SET status=?1,next_attempt_at=?2,last_error_code=?3,last_error_message=?4,updated_at=?5 WHERE id=?6").bind(retryable ? "retry_scheduled" : "failed", next, http.code, http.message, now(), id).run(); throw http; }
}

type AnalyticsRun = { id: string; workspace_id: string; created_by_user_id: string; idempotency_key: string; request_hash: string; platform: AnalyticsPlatform; connection_id: string | null; window_start: string; window_end: string; status: string; blocker_code: string | null; error_message: string | null; policy_snapshot: string; provider_snapshot: string; fetch_started_at: string | null; fetch_completed_at: string | null; created_at: string; updated_at: string };
const analyticsRequiredScopes: Record<AnalyticsPlatform, string[]> = { youtube: ANALYTICS_SCOPES.youtube, instagram: ["instagram_basic", ...ANALYTICS_SCOPES.instagram] };
function publicAnalyticsRun(run: AnalyticsRun, metrics: unknown[]) { return { id: run.id, workspace_id: run.workspace_id, platform: run.platform, window: { start: run.window_start, end: run.window_end }, status: run.status, blocker: run.blocker_code ? { code: run.blocker_code, message: run.error_message } : null, provider_snapshot: JSON.parse(run.provider_snapshot), metrics, fetch_started_at: run.fetch_started_at, fetch_completed_at: run.fetch_completed_at, created_at: run.created_at }; }
async function analyticsRunResponse(db: D1Database, run: AnalyticsRun, status = 200) { const metrics = await db.prepare("SELECT platform,account_id,content_id,metric,value,observed_at,source_ref FROM analytics_metrics WHERE run_id=?1 ORDER BY content_id,metric").bind(run.id).all(); return json({ data: publicAnalyticsRun(run, metrics.results) }, status); }
function analyticsDates(input: Record<string, unknown>): { start: string; end: string } { const start = requiredString(input.start_date, "start_date", 10); const end = requiredString(input.end_date, "end_date", 10); if (!/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end) || start > end) throw new ValidationError("start_date and end_date must be ordered ISO dates"); return { start, end }; }
function providerSnapshot(policy: Record<string, unknown>, connection: PublishingConnection | null) { return { platform: connection?.platform ?? null, account_id: connection?.account_id ?? null, channel_id: connection?.channel_id ?? null, scopes: connection ? JSON.parse(connection.scopes) : [], credential_status: connection?.credential_status ?? "unconfigured", captured_at: now(), policy_version: policy.version ?? null }; }
async function fetchAnalytics(platform: AnalyticsPlatform, connection: PublishingConnection, dates: { start: string; end: string }, token: string): Promise<{ metrics: NormalizedMetric[]; endpoint: string; raw: unknown }> {
  const observedAt = now();
  if (platform === "youtube") {
    const endpoint = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel%3D%3D${encodeURIComponent(connection.channel_id ?? connection.account_id ?? "")}&startDate=${dates.start}&endDate=${dates.end}&metrics=views%2Clikes%2Ccomments%2Cshares%2CestimatedMinutesWatched%2CaverageViewDuration%2CaverageViewPercentage%2CsubscribersGained&dimensions=video&sort=-views&maxResults=200`;
    const response = await fetch(endpoint, { headers: { authorization: `Bearer ${token}` } });
    if (!response.ok) throw new HttpError(response.status === 429 ? 429 : 503, response.status === 429 ? "rate_limited" : "platform_api_unavailable", "YouTube Analytics did not return data");
    const raw = await oauthJson(response); const rows = Array.isArray(raw.rows) ? raw.rows : [];
    return { metrics: normalizeYouTubeRows(rows, connection.account_id ?? connection.channel_id ?? "", observedAt, ""), endpoint, raw };
  }
  const endpoint = `https://graph.facebook.com/v21.0/${encodeURIComponent(connection.account_id ?? "")}/insights?metric=impressions%2Creach%2Clikes%2Ccomments%2Csaved%2Cshares%2Cplays%2Ctotal_interactions&period=day&since=${dates.start}&until=${dates.end}`;
  const response = await fetch(endpoint, { headers: { authorization: `Bearer ${token}` } });
  if (!response.ok) throw new HttpError(response.status === 429 ? 429 : 503, response.status === 429 ? "rate_limited" : "platform_api_unavailable", "Instagram Insights did not return data");
  const raw = await oauthJson(response); return { metrics: normalizeInstagramMetrics(Array.isArray(raw.data) ? raw.data : [], connection.account_id ?? "", observedAt, ""), endpoint, raw };
}
async function createAnalyticsRun(request: Request, db: D1Database, auth: Auth, env: Env, workspaceId: string) {
  const member = await providerAccess(request, db, auth, workspaceId); if (!['owner','admin','editor'].includes(String(member.role))) throw new HttpError(403, 'forbidden', 'Only workspace editors can start analytics runs');
  const key = requiredString(request.headers.get('Idempotency-Key'), 'Idempotency-Key', 200); const input = await body(request); const platform = input.platform; if (platform !== 'youtube' && platform !== 'instagram') throw new ValidationError('platform must be youtube or instagram'); const target = platform as AnalyticsPlatform; const dates = analyticsDates(input); const hash = await sha256(JSON.stringify({ platform: target, ...dates }));
  const existing = await db.prepare('SELECT * FROM analytics_runs WHERE workspace_id=?1 AND idempotency_key=?2').bind(workspaceId, key).first<AnalyticsRun>(); if (existing) { if (existing.request_hash !== hash) throw new HttpError(409, 'idempotency_conflict', 'Idempotency key was used for a different analytics window'); return analyticsRunResponse(db, existing); }
  const policy = await db.prepare('SELECT * FROM automation_policies WHERE workspace_id=?1').bind(workspaceId).first<Record<string, unknown>>(); if (!policy) throw new HttpError(409, 'policy_not_found', 'Automation policy not found');
  const connection = await db.prepare(`${publishingConnectionSelect} WHERE workspace_id=?1 AND platform=?2`).bind(workspaceId, target).first<PublishingConnection>(); const scopes = connection ? JSON.parse(connection.scopes) as string[] : []; const blocker = analyticsBlocker({ active: member.status === 'active', stopped: Boolean(policy.stop_switch), enabled: JSON.parse(String(policy.enabled_capabilities)), connected: connection?.credential_status === 'active', expired: Boolean(connection?.access_expires_at && connection.access_expires_at <= now()), revoked: connection?.credential_status === 'revoked', credential: Boolean(connection?.encrypted_access_token && env.CREDENTIAL_ENCRYPTION_KEY), scopes, requiredScopes: analyticsRequiredScopes[target] });
  const id = randomId(); const timestamp = now(); const snapshot = providerSnapshot(policy, connection); await db.prepare("INSERT INTO analytics_runs (id,workspace_id,created_by_user_id,idempotency_key,request_hash,platform,connection_id,window_start,window_end,status,blocker_code,policy_snapshot,provider_snapshot,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14)").bind(id, workspaceId, auth.user.id, key, hash, target, connection?.id ?? null, dates.start, dates.end, blocker ? 'blocked' : 'running', blocker, JSON.stringify(policy), JSON.stringify(snapshot), timestamp).run();
  if (blocker) return analyticsRunResponse(db, (await db.prepare('SELECT * FROM analytics_runs WHERE id=?1').bind(id).first<AnalyticsRun>())!, 201);
  let token: string; try { token = await decryptSecret(connection!.encrypted_access_token!, env.CREDENTIAL_ENCRYPTION_KEY); } catch { await db.prepare("UPDATE analytics_runs SET status='blocked',blocker_code='credential_unavailable',error_message='The encrypted publishing credential could not be read',updated_at=?1 WHERE id=?2").bind(now(), id).run(); return analyticsRunResponse(db, (await db.prepare('SELECT * FROM analytics_runs WHERE id=?1').bind(id).first<AnalyticsRun>())!, 201); }
  try { const fetched = await fetchAnalytics(target, connection!, dates, token); const sourceId = randomId(); const ref = `analytics-source:${sourceId}`; const metrics = fetched.metrics.map((metric) => ({ ...metric, source_ref: ref })); if (!metrics.length) throw new HttpError(422, 'data_unavailable', 'The platform returned no usable analytics'); await db.batch([db.prepare("INSERT INTO analytics_provider_snapshots (id,run_id,workspace_id,platform,account_id,channel_id,captured_at,snapshot_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)").bind(randomId(), id, workspaceId, target, connection!.account_id, connection!.channel_id, now(), JSON.stringify({ account_id: connection!.account_id, channel_id: connection!.channel_id, window: dates })), db.prepare("INSERT INTO analytics_source_refs (id,run_id,workspace_id,provider,endpoint,fetched_at,attribution,response_hash) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)").bind(sourceId, id, workspaceId, target, fetched.endpoint, now(), `${target} official API`, await sha256(JSON.stringify(fetched.raw))), ...metrics.map((metric) => db.prepare("INSERT INTO analytics_metrics (id,run_id,workspace_id,platform,account_id,content_id,metric,value,observed_at,source_ref) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)").bind(randomId(), id, workspaceId, metric.platform, metric.account_id, metric.content_id, metric.metric, metric.value, metric.observed_at, metric.source_ref)), db.prepare("UPDATE analytics_runs SET status='succeeded',fetch_started_at=?1,fetch_completed_at=?1,updated_at=?1 WHERE id=?2").bind(now(), id)]); } catch (error) { const http = error instanceof HttpError ? error : new HttpError(503, 'platform_api_unavailable', 'The platform analytics request failed'); await db.prepare("UPDATE analytics_runs SET status=?1,blocker_code=?2,error_message=?3,fetch_completed_at=?4,updated_at=?4 WHERE id=?5").bind(http.code === 'data_unavailable' ? 'blocked' : 'failed', http.code, http.message, now(), id).run(); }
  return analyticsRunResponse(db, (await db.prepare('SELECT * FROM analytics_runs WHERE id=?1').bind(id).first<AnalyticsRun>())!, 201);
}
async function getAnalyticsRun(request: Request, db: D1Database, auth: Auth, id: string) { const run = await db.prepare('SELECT * FROM analytics_runs WHERE id=?1').bind(id).first<AnalyticsRun>(); if (!run) throw new HttpError(404, 'analytics_run_not_found', 'Analytics run not found'); await providerAccess(request, db, auth, run.workspace_id); return analyticsRunResponse(db, run); }
async function listAnalytics(request: Request, db: D1Database, auth: Auth, workspaceId: string) { await providerAccess(request, db, auth, workspaceId); const runs = await db.prepare('SELECT * FROM analytics_runs WHERE workspace_id=?1 ORDER BY created_at DESC LIMIT 100').bind(workspaceId).all<AnalyticsRun>(); return json({ data: await Promise.all(runs.results.map(async (run) => { const response = await analyticsRunResponse(db, run); return response.json(); })) }); }
async function createSuggestion(request: Request, db: D1Database, auth: Auth, env: Env, workspaceId: string) {
  const member = await providerAccess(request, db, auth, workspaceId); if (!['owner','admin','editor'].includes(String(member.role))) throw new HttpError(403, 'forbidden', 'Only workspace editors can request suggestions'); const key = requiredString(request.headers.get('Idempotency-Key'), 'Idempotency-Key', 200); const existing = await db.prepare('SELECT * FROM analytics_suggestions WHERE workspace_id=?1 AND idempotency_key=?2').bind(workspaceId, key).first<Record<string, unknown>>(); if (existing) return json({ data: { ...existing, evidence_run_ids: JSON.parse(String(existing.evidence_run_ids)), provider_snapshot: JSON.parse(String(existing.provider_snapshot)) } });
  const metrics = await db.prepare("SELECT run_id,metric,value,content_id,observed_at,source_ref FROM analytics_metrics WHERE workspace_id=?1 ORDER BY observed_at DESC LIMIT 500").bind(workspaceId).all<Record<string, unknown>>(); const runs = [...new Set(metrics.results.map((row) => String(row.run_id)))]; const ai = await db.prepare("SELECT * FROM ai_provider_connections WHERE workspace_id=?1 AND provider='openai'").bind(workspaceId).first<ProviderConnection>(); const policy = await db.prepare('SELECT * FROM automation_policies WHERE workspace_id=?1').bind(workspaceId).first<Record<string, unknown>>(); const blocker = !suggestionEvidence(metrics.results as never) ? 'data_unavailable' : (!ai?.encrypted_secret ? 'credential_required' : ai.status !== 'verified' ? 'ai_provider_unverified' : !ai.selected_model ? 'ai_model_not_selected' : (policy?.stop_switch ? 'policy_blocked' : null)); const id = randomId(); const snapshot = { provider: ai?.provider ?? null, model: ai?.selected_model ?? null, verified_at: ai?.last_verified_at ?? null, captured_at: now() }; if (blocker) { await db.prepare("INSERT INTO analytics_suggestions (id,workspace_id,created_by_user_id,idempotency_key,evidence_run_ids,provider_snapshot,status,blocker_code,created_at) VALUES (?1,?2,?3,?4,?5,?6,'blocked',?7,?8)").bind(id, workspaceId, auth.user.id, key, JSON.stringify(runs), JSON.stringify(snapshot), blocker, now()).run(); return json({ data: { id, status: 'blocked', blocker: { code: blocker }, evidence_run_ids: runs, provider_snapshot: snapshot } }, 201); }
  let token: string; try { token = await decryptSecret(ai!.encrypted_secret!, env.CREDENTIAL_ENCRYPTION_KEY); } catch { throw new HttpError(409, 'credential_unavailable', 'The AI provider credential is unavailable'); } const prompt = `Using only this persisted analytics evidence, return one concise next-short recommendation as JSON with keys hypothesis, proposed_change, expected_signal. Do not invent facts. Evidence: ${JSON.stringify(metrics.results)}`; const response = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: ai!.selected_model, temperature: 0, response_format: { type: 'json_object' }, messages: [{ role: 'system', content: 'You are a conservative growth analyst. Use only supplied evidence.' }, { role: 'user', content: prompt }] }) }); if (!response.ok) throw new HttpError(503, 'platform_api_unavailable', 'The verified AI provider did not return a suggestion'); const result = await oauthJson(response); const choice = Array.isArray(result.choices) ? result.choices[0] as Record<string, unknown> : null; const message = choice?.message as Record<string, unknown> | undefined; let suggestion: unknown; try { suggestion = JSON.parse(String(message?.content ?? '')); } catch { throw new HttpError(503, 'data_unavailable', 'The AI provider returned an invalid suggestion'); } await db.prepare("INSERT INTO analytics_suggestions (id,workspace_id,created_by_user_id,idempotency_key,evidence_run_ids,provider_snapshot,status,suggestion,created_at) VALUES (?1,?2,?3,?4,?5,?6,'succeeded',?7,?8)").bind(id, workspaceId, auth.user.id, key, JSON.stringify(runs), JSON.stringify(snapshot), JSON.stringify(suggestion), now()).run(); return json({ data: { id, status: 'succeeded', evidence_run_ids: runs, provider_snapshot: snapshot, suggestion } }, 201);
}

type IdeaRun = { id: string; workspace_id: string; created_by_user_id: string; idempotency_key: string; request_hash: string; provider_snapshot: string; policy_snapshot: string; status: string; blocker_code: string | null; usage_json: string | null; cost_json: string | null; created_at: string; completed_at: string };

function publicIdeaRun(run: IdeaRun, ideas: unknown[]) {
  return { id: run.id, workspace_id: run.workspace_id, status: run.status, blocker: run.blocker_code ? { code: run.blocker_code, retryable: false } : null, provider_snapshot: JSON.parse(run.provider_snapshot), policy_snapshot: JSON.parse(run.policy_snapshot), usage: run.usage_json ? JSON.parse(run.usage_json) : null, cost: run.cost_json ? JSON.parse(run.cost_json) : null, created_at: run.created_at, completed_at: run.completed_at, ideas };
}

async function ideaRunResponse(db: D1Database, run: IdeaRun, status = 200) {
  const ideas = await db.prepare("SELECT id,title,premise,evidence_json,trend_signals_json,created_at FROM idea_candidates WHERE run_id=?1 AND workspace_id=?2 ORDER BY created_at,id").bind(run.id, run.workspace_id).all<{ id: string; title: string; premise: string; evidence_json: string; trend_signals_json: string; created_at: string }>();
  return json({ data: publicIdeaRun(run, ideas.results.map(({ evidence_json, trend_signals_json, ...idea }) => ({ ...idea, evidence: JSON.parse(evidence_json), trend_signals: JSON.parse(trend_signals_json) }))) }, status);
}

async function createIdeaRun(request: Request, db: D1Database, auth: Auth, workspaceId: string) {
  const member = await providerAccess(request, db, auth, workspaceId);
  if (!["owner", "admin", "editor"].includes(String(member.role))) throw new HttpError(403, "forbidden", "Only owners, admins and editors can start Idea Scout runs");
  const key = requiredString(request.headers.get("Idempotency-Key"), "Idempotency-Key", 200);
  const input = await body(request);
  if (Object.keys(input).some((key) => key !== "provider")) throw new ValidationError("Only provider is accepted");
  const provider = requiredString(input.provider, "provider", 80);
  if (!providerDefinition(provider)) throw new HttpError(422, "provider_unsupported", "The provider is not in the supported catalog");
  const hash = await sha256(JSON.stringify({ provider }));
  const existing = await db.prepare("SELECT * FROM idea_scout_runs WHERE workspace_id=?1 AND idempotency_key=?2").bind(workspaceId, key).first<IdeaRun>();
  if (existing) { if (existing.request_hash !== hash) throw new HttpError(409, "idempotency_conflict", "Idempotency key was used for a different request"); return ideaRunResponse(db, existing); }
  const policy = await db.prepare("SELECT * FROM automation_policies WHERE workspace_id=?1").bind(workspaceId).first<Record<string, unknown>>();
  if (!policy) throw new HttpError(409, "policy_not_found", "Automation policy not found");
  const connection = await connectionFor(db, workspaceId, provider);
  const snapshot = { provider, model: connection?.selected_model ?? null, verified_at: connection?.last_verified_at ?? null };
  const enabled = JSON.parse(String(policy.enabled_capabilities));
  const blocker = ideaScoutBlocker({ active: member.status === "active", stopped: Boolean(policy.stop_switch), enabled, credential: Boolean(connection?.encrypted_secret), verified: connection?.status === "verified" && Boolean(connection.last_verified_at), modelSupported: Boolean(connection?.selected_model && modelDefinition(providerDefinition(provider)!, connection.selected_model)?.capabilities.includes("text_generation")) });
  const id = randomId(); const timestamp = now();
  await db.prepare("INSERT INTO idea_scout_runs (id,workspace_id,created_by_user_id,idempotency_key,request_hash,provider_snapshot,policy_snapshot,status,blocker_code,created_at,completed_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'blocked',?8,?9,?9) ON CONFLICT(workspace_id,idempotency_key) DO NOTHING").bind(id, workspaceId, auth.user.id, key, hash, JSON.stringify(snapshot), JSON.stringify(policy), blocker, timestamp).run();
  const run = await db.prepare("SELECT * FROM idea_scout_runs WHERE workspace_id=?1 AND idempotency_key=?2").bind(workspaceId, key).first<IdeaRun>();
  if (!run) throw new HttpError(500, "internal_error", "The run could not be recorded");
  if (run.request_hash !== hash) throw new HttpError(409, "idempotency_conflict", "Idempotency key was used for a different request");
  return ideaRunResponse(db, run, run.id === id ? 201 : 200);
}

async function getIdeaRun(request: Request, db: D1Database, auth: Auth, id: string) {
  const run = await db.prepare("SELECT * FROM idea_scout_runs WHERE id=?1").bind(id).first<IdeaRun>();
  if (!run) throw new HttpError(404, "idea_run_not_found", "Idea Scout run not found");
  await providerAccess(request, db, auth, run.workspace_id);
  return ideaRunResponse(db, run);
}

type ProductionJob = { id: string; workspace_id: string; request_hash: string; status: string; [key: string]: unknown };
async function productionResponse(db: D1Database, job: ProductionJob, status = 200) {
  const events = await db.prepare('SELECT status,reason,actor_id,created_at FROM production_job_events WHERE job_id=?1 ORDER BY rowid').bind(job.id).all();
  const ledger = await db.prepare('SELECT provider,model,usage_json,actual_microusd,created_at FROM production_cost_ledger WHERE job_id=?1 ORDER BY rowid').bind(job.id).all();
  const attempts = await db.prepare('SELECT id,idempotency_key,provider,status,blocker_code,provider_job_id,output_asset_id,estimate_microusd,actual_microusd,error_code,created_at,updated_at FROM production_render_attempts WHERE production_job_id=?1 ORDER BY rowid').bind(job.id).all();
  const capabilities = await db.prepare('SELECT provider,capability,status,blocker_code,checked_at FROM production_provider_capabilities WHERE workspace_id=?1 AND provider=?2 ORDER BY capability').bind(job.workspace_id, JSON.parse(String(job.provider_snapshot)).provider ?? '').all();
  return json({ data: { ...job, asset_ids: JSON.parse(String(job.asset_ids)), policy_snapshot: JSON.parse(String(job.policy_snapshot)), provider_snapshot: JSON.parse(String(job.provider_snapshot)), capabilities: capabilities.results, render_attempts: attempts.results, events: events.results, ledger: ledger.results } }, status);
}

type QualityRun = { id: string; workspace_id: string; production_job_id: string; created_by_user_id: string; idempotency_key: string; request_hash: string; provider_snapshot: string; policy_snapshot: string; evidence_refs: string; findings: string; score: number | null; status: string; blocker_code: string | null; created_at: string };
function publicQualityRun(run: QualityRun, decisions: unknown[]) { return { id: run.id, workspace_id: run.workspace_id, production_job_id: run.production_job_id, status: run.status, score: run.score, blocker: run.blocker_code ? { code: run.blocker_code, retryable: false } : null, provider_snapshot: JSON.parse(run.provider_snapshot), policy_snapshot: JSON.parse(run.policy_snapshot), evidence_refs: JSON.parse(run.evidence_refs), findings: JSON.parse(run.findings), decisions, created_at: run.created_at }; }
async function qualityGateResponse(db: D1Database, run: QualityRun, status = 200) { const decisions = await db.prepare('SELECT id,decision,reviewer_id,reason,created_at FROM quality_gate_decisions WHERE quality_gate_run_id=?1 ORDER BY rowid').bind(run.id).all(); return json({ data: publicQualityRun(run, decisions.results) }, status); }

async function createQualityGate(request: Request, db: D1Database, auth: Auth, jobId: string) {
  const job = await db.prepare('SELECT * FROM production_jobs WHERE id=?1').bind(jobId).first<ProductionJob>();
  if (!job) throw new HttpError(404, 'production_job_not_found', 'Production job not found');
  const member = await providerAccess(request, db, auth, String(job.workspace_id));
  if (!['owner', 'admin', 'editor', 'reviewer'].includes(String(member.role))) throw new HttpError(403, 'forbidden', 'Only workspace reviewers can start a quality gate');
  const key = requiredString(request.headers.get('Idempotency-Key'), 'Idempotency-Key', 200); const input = await body(request);
  if (Object.keys(input).length) throw new ValidationError('Quality gate requests do not accept body fields');
  const hash = await sha256(JSON.stringify({ production_job_id: jobId }));
  const existing = await db.prepare('SELECT * FROM quality_gate_runs WHERE workspace_id=?1 AND idempotency_key=?2').bind(job.workspace_id, key).first<QualityRun>();
  if (existing) { if (existing.request_hash !== hash) throw new HttpError(409, 'idempotency_conflict', 'Idempotency key was used for a different quality gate request'); return qualityGateResponse(db, existing); }
  const policy = await db.prepare('SELECT * FROM automation_policies WHERE workspace_id=?1').bind(job.workspace_id).first<Record<string, unknown>>();
  if (!policy) throw new HttpError(409, 'policy_not_found', 'Automation policy not found');
  const providerSnapshot = JSON.parse(String(job.provider_snapshot)); const assetIds = JSON.parse(String(job.asset_ids)) as string[];
  const assets = assetIds.length ? await db.prepare(`SELECT id,storage_key,kind,media_type,duration_seconds,width,height,metadata,status,scan_status,licensing_status,rights_confirmed,license_type FROM assets WHERE workspace_id=?1 AND id IN (${assetIds.map(() => '?').join(',')})`).bind(job.workspace_id, ...assetIds).all<QualityAsset>() : { results: [] as QualityAsset[] };
  const assetMap = new Map(assets.results.map((asset) => [asset.id, asset]));
  const findings: QualityFinding[] = assetIds.filter((id) => !assetMap.has(id)).map((id) => ({ code: 'asset_not_found', severity: 'blocking', message: 'A production asset could not be loaded for review', evidence_refs: [`asset:${id}`] }));
  findings.push(...evaluateDeterministicQuality(job, assetIds.flatMap((id) => assetMap.get(id) ? [assetMap.get(id)!] : []), now()));
  let blocker: string | null = findings.some((item) => item.severity === 'blocking') ? 'quality_checks_failed' : null;
  let status = blocker ? 'failed' : 'blocked';
  if (!blocker && (member.status !== 'active' || Boolean(policy.stop_switch))) blocker = 'policy_blocked';
  const connection = providerSnapshot.provider ? await connectionFor(db, String(job.workspace_id), String(providerSnapshot.provider)) : null;
  const provider = providerSnapshot.provider ? providerDefinition(String(providerSnapshot.provider)) : undefined;
  const snapshotModel = typeof providerSnapshot.model === 'string' ? providerSnapshot.model : null;
  const model = snapshotModel && provider ? modelDefinition(provider, snapshotModel) : undefined;
  if (!blocker && (!connection?.encrypted_secret || connection.status !== 'verified' || !connection.last_verified_at)) blocker = 'quality_provider_unavailable';
  if (!blocker && (!model || !model.capabilities.includes('vision'))) blocker = 'quality_model_capability_unavailable';
  if (!blocker) blocker = 'media_inspection_capability_unavailable';
  const timestamp = now(); const id = randomId(); const evidenceRefs = [...new Set(findings.flatMap((item) => item.evidence_refs))];
  await db.prepare("INSERT INTO quality_gate_runs (id,workspace_id,production_job_id,created_by_user_id,idempotency_key,request_hash,provider_snapshot,policy_snapshot,evidence_refs,findings,score,status,blocker_code,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) ON CONFLICT(workspace_id,idempotency_key) DO NOTHING").bind(id, job.workspace_id, jobId, auth.user.id, key, hash, JSON.stringify({ provider: providerSnapshot.provider ?? null, model: snapshotModel, verified_at: providerSnapshot.verified_at ?? null }), JSON.stringify(policy), JSON.stringify(evidenceRefs), JSON.stringify(findings), blocker ? null : qualityScore(findings), status, blocker, timestamp).run();
  const run = await db.prepare('SELECT * FROM quality_gate_runs WHERE workspace_id=?1 AND idempotency_key=?2').bind(job.workspace_id, key).first<QualityRun>();
  if (!run) throw new HttpError(500, 'internal_error', 'Quality gate could not be recorded');
  if (run.request_hash !== hash) throw new HttpError(409, 'idempotency_conflict', 'Idempotency key was used for a different quality gate request');
  return qualityGateResponse(db, run, run.id === id ? 201 : 200);
}

async function getQualityGate(request: Request, db: D1Database, auth: Auth, id: string) { const run = await db.prepare('SELECT * FROM quality_gate_runs WHERE id=?1').bind(id).first<QualityRun>(); if (!run) throw new HttpError(404, 'quality_gate_not_found', 'Quality gate run not found'); await providerAccess(request, db, auth, run.workspace_id); return qualityGateResponse(db, run); }
async function qualityDecision(request: Request, db: D1Database, auth: Auth, id: string) {
  const run = await db.prepare('SELECT * FROM quality_gate_runs WHERE id=?1').bind(id).first<QualityRun>(); if (!run) throw new HttpError(404, 'quality_gate_not_found', 'Quality gate run not found');
  const member = await providerAccess(request, db, auth, run.workspace_id); if (!['owner', 'admin', 'reviewer'].includes(String(member.role))) throw new HttpError(403, 'forbidden', 'Only workspace reviewers can decide a quality gate');
  const input = await body(request); const decision = requiredString(input.decision, 'decision', 20); if (!['approved', 'rejected'].includes(decision)) throw new ValidationError('decision must be approved or rejected');
  const reason = input.reason === undefined ? null : requiredString(input.reason, 'reason', 2000); if (decision === 'approved' && (run.status !== 'passed' || run.score === null)) throw new HttpError(409, 'quality_gate_not_passed', 'Only a successful quality gate with a real score can be approved');
  if (await db.prepare('SELECT id FROM quality_gate_decisions WHERE quality_gate_run_id=?1').bind(id).first()) throw new HttpError(409, 'decision_already_recorded', 'A quality gate decision is immutable and already exists');
  await db.prepare('INSERT INTO quality_gate_decisions (id,quality_gate_run_id,workspace_id,decision,reviewer_id,reason,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)').bind(randomId(), id, run.workspace_id, decision, auth.user.id, reason, now()).run(); return qualityGateResponse(db, run, 201);
}
async function approveBrief(request: Request, db: D1Database, auth: Auth, ideaId: string) {
  const idea = await db.prepare('SELECT * FROM idea_candidates WHERE id=?1').bind(ideaId).first<{ workspace_id: string; run_id: string; evidence_json: string }>();
  if (!idea) throw new HttpError(404, 'idea_not_found', 'Idea not found');
  const member = await providerAccess(request, db, auth, idea.workspace_id);
  if (member.status !== 'active' || !['owner','admin','editor'].includes(String(member.role))) throw new HttpError(403, 'forbidden', 'Active editors can approve briefs');
  const run = await db.prepare("SELECT id FROM idea_scout_runs WHERE id=?1 AND workspace_id=?2 AND status='succeeded'").bind(idea.run_id, idea.workspace_id).first();
  const evidence = JSON.parse(idea.evidence_json);
  if (!run || !Array.isArray(evidence) || evidence.length === 0) throw new HttpError(409, 'idea_not_eligible', 'A successful evidence-backed Idea Scout candidate is required');
  const input = await body(request); const content = requiredString(input.content, 'content', 20000);
  const id = randomId(); const timestamp = now();
  await db.prepare('INSERT INTO content_briefs (id,workspace_id,idea_id,content,approved_by_user_id,approved_at) VALUES (?1,?2,?3,?4,?5,?6)').bind(id, idea.workspace_id, ideaId, content, auth.user.id, timestamp).run();
  return json({ data: { id, workspace_id: idea.workspace_id, idea_id: ideaId, content, approved_by_user_id: auth.user.id, approved_at: timestamp } }, 201);
}
async function createProduction(request: Request, db: D1Database, auth: Auth, workspaceId: string) {
  const member = await providerAccess(request, db, auth, workspaceId);
  if (!['owner','admin','editor'].includes(String(member.role))) throw new HttpError(403, 'forbidden', 'Only editors can start production');
  const key = requiredString(request.headers.get('Idempotency-Key'), 'Idempotency-Key', 200);
  const input = await body(request);
  if (Object.keys(input).some(k => !['brief_id','asset_ids','provider'].includes(k))) throw new ValidationError('Unexpected production field');
  const brief = requiredString(input.brief_id, 'brief_id', 100); const provider = requiredString(input.provider, 'provider', 80);
  if (!providerDefinition(provider)) throw new HttpError(422, 'provider_unsupported', 'Unsupported provider');
  if (!Array.isArray(input.asset_ids) || input.asset_ids.length < 1 || input.asset_ids.length > 100 || input.asset_ids.some(x => typeof x !== 'string' || !x || x.length > 100) || new Set(input.asset_ids).size !== input.asset_ids.length) throw new ValidationError('asset_ids must contain unique asset IDs');
  const assetIds = [...input.asset_ids].sort() as string[];
  const hash = await sha256(JSON.stringify({ brief, provider, assetIds }));
  const existing = await db.prepare('SELECT * FROM production_jobs WHERE workspace_id=?1 AND idempotency_key=?2').bind(workspaceId,key).first<ProductionJob>();
  if (existing) { if (existing.request_hash !== hash) throw new HttpError(409,'idempotency_conflict','Idempotency key already used'); return productionResponse(db,existing); }
  const approved = await db.prepare('SELECT id FROM content_briefs WHERE id=?1 AND workspace_id=?2').bind(brief,workspaceId).first();
  if (!approved) throw new HttpError(422,'brief_not_approved','An approved workspace brief is required');
  const policy = await db.prepare('SELECT * FROM automation_policies WHERE workspace_id=?1').bind(workspaceId).first<Record<string, unknown>>();
  if (!policy) throw new HttpError(409,'policy_not_found','Automation policy not found');
  // The render adapter is a chargeable provider boundary. With no verified
  // billing/pricing/entitlement evidence, stop here before it can be called.
  const billing = await usageSummary(db, workspaceId, now());
  const connection = await connectionFor(db,workspaceId,provider);
  const snapshot = { provider, model: connection?.selected_model ?? null, verified_at: connection?.last_verified_at ?? null };
  let blocker: string | null = null;
  let enabled: unknown; try { enabled = JSON.parse(String(policy.enabled_capabilities)); } catch { enabled = null; }
  if (member.status !== 'active' || policy.stop_switch || !Array.isArray(enabled) || !enabled.includes('production')) blocker = 'policy_blocked';
  if (!blocker && billing.billing_status === 'billing_unavailable') blocker = 'billing_unavailable';
  for (const assetId of assetIds) {
    const asset = await db.prepare('SELECT status,scan_status,licensing_status,rights_confirmed,license_type FROM assets WHERE id=?1 AND workspace_id=?2').bind(assetId,workspaceId).first<{status:string;scan_status:string;licensing_status:string;rights_confirmed:number;license_type:string | null}>();
    if (!asset) throw new HttpError(422,'asset_not_found','A selected asset does not belong to this workspace');
    if (!blocker && asset.scan_status === 'unavailable') blocker = 'malware_scanner_unavailable';
    if (!blocker && (asset.licensing_status !== 'valid' || !asset.rights_confirmed || !asset.license_type)) blocker = 'license_invalid';
    if (!blocker && (asset.status !== 'ready' || asset.scan_status !== 'clean')) blocker = 'asset_not_ready';
    const expired = await db.prepare('SELECT id FROM asset_references WHERE asset_id=?1 AND expires_at IS NOT NULL AND expires_at<=?2 LIMIT 1').bind(assetId,now()).first();
    if (!blocker && expired) blocker = 'license_expired';
  }
  if (!blocker && !connection?.encrypted_secret) blocker = 'credential_required';
  if (!blocker && (connection?.status !== 'verified' || !connection.last_verified_at)) blocker = 'connection_not_verified';
  if (!blocker && (!connection?.selected_model || !modelDefinition(providerDefinition(provider)!,connection.selected_model)?.capabilities.includes('text_generation'))) blocker = 'model_not_selected';
  const adapter = renderAdapterFor(provider);
  if (!blocker && !adapter) blocker = 'provider_unavailable';
  const ceiling = ceilingMicros(policy.per_job_cost_limit);
  if (!blocker) blocker = costBlocker(ceiling, null);
  const estimateReason = blocker ?? 'render_estimate_unavailable';
  // No provider invocation is permitted without an adapter and a bounded estimate.
  const id = randomId(); const timestamp = now();
  const capabilities = capabilitySnapshots(provider, timestamp);
  await db.batch([
    db.prepare("INSERT INTO production_jobs (id,workspace_id,created_by_user_id,brief_id,asset_ids,idempotency_key,request_hash,policy_snapshot,provider_snapshot,ceiling_microusd,estimate_microusd,estimate_reason,status,blocker_code,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,?11,'blocked',?12,?13,?13) ON CONFLICT(workspace_id,idempotency_key) DO NOTHING").bind(id,workspaceId,auth.user.id,brief,JSON.stringify(assetIds),key,hash,JSON.stringify(policy),JSON.stringify({ ...snapshot, render_adapter: adapter ? provider : null }),ceiling,estimateReason,blocker,timestamp),
    db.prepare("INSERT INTO production_job_events (id,job_id,status,reason,actor_id,created_at) SELECT ?1,id,'planning',NULL,?2,?3 FROM production_jobs WHERE id=?4").bind(randomId(),auth.user.id,timestamp,id),
    db.prepare("INSERT INTO production_job_events (id,job_id,status,reason,actor_id,created_at) SELECT ?1,id,'blocked',blocker_code,?2,?3 FROM production_jobs WHERE id=?4").bind(randomId(),auth.user.id,timestamp,id),
    ...capabilities.map((capability) => db.prepare("INSERT INTO production_provider_capabilities (id,workspace_id,provider,capability,status,blocker_code,checked_at) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(workspace_id,provider,capability) DO UPDATE SET status=excluded.status,blocker_code=excluded.blocker_code,checked_at=excluded.checked_at").bind(randomId(), workspaceId, capability.provider, capability.capability, capability.status, capability.blocker_code, capability.checked_at)),
    db.prepare("INSERT INTO production_render_attempts (id,workspace_id,production_job_id,idempotency_key,request_hash,provider,status,blocker_code,estimate_microusd,created_at,updated_at) SELECT ?1,workspace_id,id,?2,?3,?4,'blocked',?5,NULL,?6,?6 FROM production_jobs WHERE id=?7 ON CONFLICT(workspace_id,idempotency_key) DO NOTHING").bind(randomId(), `${key}:render`, hash, provider, blocker, timestamp, id),
  ]);
  const job = await db.prepare('SELECT * FROM production_jobs WHERE workspace_id=?1 AND idempotency_key=?2').bind(workspaceId,key).first<ProductionJob>();
  if (!job) throw new HttpError(500,'internal_error','Job could not be recorded');
  if (job.request_hash !== hash) throw new HttpError(409,'idempotency_conflict','Idempotency key already used');
  return productionResponse(db,job,job.id === id ? 201 : 200);
}
async function productionJob(request: Request, db: D1Database, auth: Auth, id: string, cancel: boolean) {
  const job = await db.prepare('SELECT * FROM production_jobs WHERE id=?1').bind(id).first<ProductionJob>();
  if (!job) throw new HttpError(404,'production_job_not_found','Production job not found');
  const member = await providerAccess(request,db,auth,job.workspace_id);
  if (!cancel) return productionResponse(db,job);
  if (member.status !== 'active' || !['owner','admin','editor'].includes(String(member.role))) throw new HttpError(403,'forbidden','Only active editors can cancel production');
  if (!canTransition(job.status as ProductionState,'cancelled')) throw new HttpError(409,'invalid_transition','Job cannot be cancelled');
  const timestamp = now(); const eventId = randomId();
  const results = await db.batch([
    db.prepare("UPDATE production_jobs SET status='cancelled',updated_at=?1 WHERE id=?2 AND status=?3").bind(timestamp,id,job.status),
    db.prepare("INSERT INTO production_job_events (id,job_id,status,reason,actor_id,created_at) SELECT ?1,id,'cancelled','user_cancelled',?2,?3 FROM production_jobs WHERE id=?4 AND status='cancelled' AND updated_at=?3 AND changes()=1").bind(eventId,auth.user.id,timestamp,id),
  ]);
  if (!results[0].meta.changes) throw new HttpError(409,'invalid_transition','Job state changed');
  return productionResponse(db,(await db.prepare('SELECT * FROM production_jobs WHERE id=?1').bind(id).first<ProductionJob>())!);
}

type AutomationSchedule = { id: string; workspace_id: string; created_by_user_id: string; name: string; cadence_minutes: number; provider: string; configuration: string; status: string; blocker_code: string | null; next_run_at: string; last_run_at: string | null; created_at: string; updated_at: string };
type AutomationRun = { id: string; schedule_id: string; workspace_id: string; idempotency_key: string; scheduled_for: string; policy_snapshot: string; configuration_snapshot: string; status: string; current_step: AutomationStep | null; blocker_code: string | null; attempt: number; next_attempt_at: string | null; lease_owner: string | null; lease_expires_at: string | null; cancel_requested_at: string | null; started_at: string | null; completed_at: string | null; created_at: string; updated_at: string };
const publicSchedule = (row: AutomationSchedule) => ({ ...row, configuration: JSON.parse(row.configuration) });
async function publicAutomationRun(db: D1Database, row: AutomationRun) { const steps = await db.prepare('SELECT step,ordinal,status,boundary_resource_id,blocker_code,attempt,next_attempt_at,started_at,completed_at FROM automation_run_steps WHERE run_id=?1 ORDER BY ordinal').bind(row.id).all(); const events = await db.prepare('SELECT event,reason_code,attempt,occurred_at FROM automation_run_events WHERE run_id=?1 ORDER BY occurred_at').bind(row.id).all(); return { ...row, policy_snapshot: JSON.parse(row.policy_snapshot), configuration_snapshot: JSON.parse(row.configuration_snapshot), steps: steps.results, events: events.results }; }

async function automationSchedules(request: Request, db: D1Database, auth: Auth, env: Env, workspaceId: string) {
  const member = await providerAccess(request, db, auth, workspaceId);
  if (request.method === 'GET') { const rows = await db.prepare('SELECT * FROM automation_schedules WHERE workspace_id=?1 ORDER BY created_at DESC').bind(workspaceId).all<AutomationSchedule>(); return json({ data: rows.results.map(publicSchedule) }); }
  if (!['owner','admin'].includes(String(member.role))) throw new HttpError(403, 'forbidden', 'Only workspace owners and admins can create schedules');
  const input = await body(request); if (Object.keys(input).some((key) => !['name','cadence_minutes','provider','configuration'].includes(key))) throw new ValidationError('Unexpected schedule field');
  const name = requiredString(input.name, 'name', 120); const provider = requiredString(input.provider, 'provider', 80); if (!providerDefinition(provider)) throw new HttpError(422, 'provider_unsupported', 'Unsupported provider');
  const cadence = Number(input.cadence_minutes); if (!Number.isSafeInteger(cadence) || cadence < 5 || cadence > 10080) throw new ValidationError('cadence_minutes must be an integer from 5 to 10080');
  const configuration = input.configuration === undefined ? {} : asRecord(input.configuration); const forbiddenConfigurationKey=(value:unknown):boolean => Boolean(value && typeof value==='object' && Object.entries(value).some(([key,nested]) => /^(api[_-]?key|access[_-]?token|refresh[_-]?token|credential|secret|password)$/i.test(key) || forbiddenConfigurationKey(nested))); if (forbiddenConfigurationKey(configuration)) throw new ValidationError('Schedule configuration must reference stored connections and cannot contain credentials'); const timestamp = now(); const available = env.AUTOMATION_SCHEDULER_ENABLED === 'true'; const id = randomId();
  await db.prepare("INSERT INTO automation_schedules (id,workspace_id,created_by_user_id,name,cadence_minutes,provider,configuration,status,blocker_code,next_run_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10,?10)").bind(id,workspaceId,auth.user.id,name,cadence,provider,JSON.stringify(configuration),available ? 'active' : 'blocked',available ? null : 'scheduler_unavailable',timestamp).run();
  return json({ data: publicSchedule((await db.prepare('SELECT * FROM automation_schedules WHERE id=?1').bind(id).first<AutomationSchedule>())!) }, 201);
}
async function cancelEligibleAutomationRuns(db:D1Database, workspaceId:string, reason:string, timestamp:string, scheduleId?:string) {
  const target=scheduleId ?? workspaceId; const scope=scheduleId ? 'schedule_id' : 'workspace_id'; const eligible=await db.prepare(`SELECT id,attempt FROM automation_runs WHERE ${scope}=?1 AND status IN ('queued','retry_scheduled')`).bind(target).all<{id:string;attempt:number}>(); if (!eligible.results.length) return;
  await db.batch(eligible.results.flatMap((run)=>[
    db.prepare("INSERT INTO automation_run_events(id,run_id,event,reason_code,attempt,occurred_at) SELECT ?1,id,'cancelled',?2,attempt,?3 FROM automation_runs WHERE id=?4 AND status IN ('queued','retry_scheduled')").bind(randomId(),reason,timestamp,run.id),
    db.prepare("UPDATE automation_run_steps SET status='cancelled',completed_at=?1,lease_owner=NULL,lease_expires_at=NULL,updated_at=?1 WHERE run_id=?2 AND status IN ('pending','retry_scheduled') AND EXISTS(SELECT 1 FROM automation_runs WHERE id=?2 AND status IN ('queued','retry_scheduled'))").bind(timestamp,run.id),
    db.prepare("UPDATE automation_runs SET status='cancelled',blocker_code=?1,cancel_requested_at=?2,completed_at=?2,lease_owner=NULL,lease_expires_at=NULL,updated_at=?2 WHERE id=?3 AND status IN ('queued','retry_scheduled')").bind(reason,timestamp,run.id),
  ]));
  // Cancellation is a terminal boundary for queued automation: return any
  // budget reservation exactly once so a stop switch cannot strand allowance.
  for (const run of eligible.results) {
    const reservations=await db.prepare("SELECT r.id,r.workspace_id,r.budget_date,r.estimate_microusd FROM automation_budget_reservations r WHERE r.run_id=?1 AND r.status='reserved'").bind(run.id).all<{id:string;workspace_id:string;budget_date:string;estimate_microusd:number}>();
    const releases=reservations.results.flatMap((reservation)=>[
      db.prepare('UPDATE automation_budget_accounts SET reserved_microusd=reserved_microusd-?1,version=version+1,updated_at=?2 WHERE workspace_id=?3 AND budget_date=?4 AND reserved_microusd>=?1').bind(reservation.estimate_microusd,timestamp,reservation.workspace_id,reservation.budget_date),
      db.prepare("UPDATE automation_budget_reservations SET status='released',reconciled_at=?1 WHERE id=?2 AND status='reserved'").bind(timestamp,reservation.id),
    ]);
    if (releases.length) await db.batch(releases);
  }
}
async function controlAutomationSchedule(request: Request, db: D1Database, auth: Auth, env:Env, id: string) {
  const row = await db.prepare('SELECT * FROM automation_schedules WHERE id=?1').bind(id).first<AutomationSchedule>(); if (!row) throw new HttpError(404,'schedule_not_found','Automation schedule not found');
  const member = await providerAccess(request,db,auth,row.workspace_id); if (!['owner','admin'].includes(String(member.role))) throw new HttpError(403,'forbidden','Only workspace owners and admins can control schedules');
  const input = await body(request); const action = requiredString(input.action,'action',20); if (!['pause','resume','cancel'].includes(action)) throw new ValidationError('action must be pause, resume, or cancel');
  if (row.status === 'cancelled') throw new HttpError(409,'invalid_transition','A cancelled schedule cannot be resumed');
  if (action==='resume' && env.AUTOMATION_SCHEDULER_ENABLED!=='true') throw new HttpError(409,'scheduler_unavailable','The durable scheduler is not configured');
  const timestamp=now(); if (action!=='resume') await cancelEligibleAutomationRuns(db,row.workspace_id,action==='pause'?'schedule_paused':'schedule_cancelled',timestamp,id);
  await db.prepare('UPDATE automation_schedules SET status=?1,blocker_code=?2,updated_at=?3 WHERE id=?4').bind(action === 'pause' ? 'paused' : action === 'cancel' ? 'cancelled' : 'active',action==='resume'?null:row.blocker_code,timestamp,id).run();
  return json({ data: publicSchedule((await db.prepare('SELECT * FROM automation_schedules WHERE id=?1').bind(id).first<AutomationSchedule>())!) });
}
async function automationRuns(request: Request, db: D1Database, auth: Auth, workspaceId: string) { await providerAccess(request,db,auth,workspaceId); const rows = await db.prepare('SELECT * FROM automation_runs WHERE workspace_id=?1 ORDER BY created_at DESC LIMIT 100').bind(workspaceId).all<AutomationRun>(); return json({ data: await Promise.all(rows.results.map((row) => publicAutomationRun(db,row))) }); }
async function automationRun(request: Request, db: D1Database, auth: Auth, id: string, cancel: boolean) {
  const row = await db.prepare('SELECT * FROM automation_runs WHERE id=?1').bind(id).first<AutomationRun>(); if (!row) throw new HttpError(404,'automation_run_not_found','Automation run not found'); const member = await providerAccess(request,db,auth,row.workspace_id);
  if (!cancel) return json({ data: await publicAutomationRun(db,row) }); if (!['owner','admin','editor'].includes(String(member.role))) throw new HttpError(403,'forbidden','Only workspace editors can cancel runs');
  if (['succeeded','blocked','failed','cancelled'].includes(row.status)) throw new HttpError(409,'invalid_transition','Terminal runs cannot be cancelled'); const timestamp = now();
  await db.batch([db.prepare("UPDATE automation_runs SET status='cancelled',cancel_requested_at=?1,completed_at=?1,lease_owner=NULL,lease_expires_at=NULL,updated_at=?1 WHERE id=?2 AND status NOT IN ('succeeded','blocked','failed','cancelled')").bind(timestamp,id),db.prepare("UPDATE automation_run_steps SET status='cancelled',completed_at=?1,lease_owner=NULL,lease_expires_at=NULL,updated_at=?1 WHERE run_id=?2 AND status NOT IN ('succeeded','blocked','failed','cancelled')").bind(timestamp,id),db.prepare("INSERT INTO automation_run_events (id,run_id,event,reason_code,attempt,occurred_at) VALUES (?1,?2,'cancelled','user_cancelled',?3,?4)").bind(randomId(),id,row.attempt,timestamp)]);
  return json({ data: await publicAutomationRun(db,(await db.prepare('SELECT * FROM automation_runs WHERE id=?1').bind(id).first<AutomationRun>())!) });
}
async function approveAutomationRun(request: Request, db: D1Database, auth: Auth, id: string) {
  const run=await db.prepare("SELECT * FROM automation_runs WHERE id=?1 AND status='waiting_review'").bind(id).first<AutomationRun>(); if (!run) throw new HttpError(409,'run_not_waiting_review','Automation run is not waiting for review');
  const member=await providerAccess(request,db,auth,run.workspace_id); if (!['owner','admin','reviewer'].includes(String(member.role))) throw new HttpError(403,'forbidden','Only workspace reviewers can approve automation checkpoints');
  const policy=await db.prepare('SELECT * FROM automation_policies WHERE workspace_id=?1').bind(run.workspace_id).first<Record<string,unknown>>(); if (!policy || policy.stop_switch) throw new HttpError(409,'policy_blocked','Live workspace policy blocks resumption');
  const step=await db.prepare("SELECT * FROM automation_run_steps WHERE run_id=?1 AND status='waiting_review' ORDER BY ordinal LIMIT 1").bind(id).first<{id:string;step:string;blocker_code:string}>(); if (!step) throw new HttpError(409,'review_step_not_found','No step is awaiting review');
  const input=await body(request); const reason=input.reason === undefined ? null : requiredString(input.reason,'reason',2000); if (step.blocker_code === 'review_required' && policy.review_mode === 'every_short') await db.prepare("INSERT INTO automation_review_counters (workspace_id,shorts_since_review,version,updated_at) VALUES (?1,0,1,?2) ON CONFLICT(workspace_id) DO NOTHING").bind(run.workspace_id,now()).run(); const counter=await db.prepare('SELECT shorts_since_review,version FROM automation_review_counters WHERE workspace_id=?1').bind(run.workspace_id).first<{shorts_since_review:number;version:number}>();
  const kind=step.blocker_code === 'review_required' ? 'cadence' : 'assisted'; const threshold=kind === 'cadence' ? (policy.review_mode === 'every_short' ? 0 : Number(policy.review_after_count)) : null; if (kind === 'cadence' && (!counter || !Number.isSafeInteger(threshold) || counter.shorts_since_review < threshold!)) throw new HttpError(409,'review_checkpoint_stale','Review cadence no longer requires approval');
  const timestamp=now(); const checkpoint=randomId();
  if (kind === 'cadence') {
    await db.batch([
      db.prepare("INSERT INTO automation_review_checkpoints (id,run_id,step_id,workspace_id,kind,counter_version,threshold,shorts_reviewed,approved_by_user_id,reason,created_at) SELECT ?1,?2,?3,?4,'cadence',version,?5,shorts_since_review,?6,?7,?8 FROM automation_review_counters WHERE workspace_id=?4 AND version=?9 AND shorts_since_review>=?5").bind(checkpoint,id,step.id,run.workspace_id,threshold,auth.user.id,reason,timestamp,counter!.version),
      db.prepare('UPDATE automation_review_counters SET shorts_since_review=0,version=version+1,updated_at=?1 WHERE workspace_id=?2 AND version=?3 AND EXISTS (SELECT 1 FROM automation_review_checkpoints WHERE id=?4)').bind(timestamp,run.workspace_id,counter!.version,checkpoint),
      db.prepare("UPDATE automation_run_steps SET status='pending',blocker_code=NULL,completed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,updated_at=?1 WHERE id=?2 AND status='waiting_review' AND EXISTS (SELECT 1 FROM automation_review_checkpoints WHERE id=?3)").bind(timestamp,step.id,checkpoint),
      db.prepare("UPDATE automation_runs SET status='queued',blocker_code=NULL,completed_at=NULL,next_attempt_at=NULL,lease_owner=NULL,lease_expires_at=NULL,updated_at=?1 WHERE id=?2 AND status='waiting_review' AND EXISTS (SELECT 1 FROM automation_review_checkpoints WHERE id=?3)").bind(timestamp,id,checkpoint),
      db.prepare("INSERT INTO automation_run_events (id,run_id,step_id,event,reason_code,attempt,occurred_at) SELECT ?1,?2,?3,'review_approved','cadence',?4,?5 WHERE EXISTS (SELECT 1 FROM automation_review_checkpoints WHERE id=?6)").bind(randomId(),id,step.id,run.attempt,timestamp,checkpoint),
    ]);
  } else {
    await db.batch([
      db.prepare("INSERT INTO automation_review_checkpoints (id,run_id,step_id,workspace_id,kind,counter_version,threshold,shorts_reviewed,approved_by_user_id,reason,created_at) VALUES (?1,?2,?3,?4,'assisted',NULL,NULL,NULL,?5,?6,?7)").bind(checkpoint,id,step.id,run.workspace_id,auth.user.id,reason,timestamp),
      db.prepare("UPDATE automation_run_steps SET status='pending',blocker_code=NULL,completed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,updated_at=?1 WHERE id=?2 AND status='waiting_review' AND EXISTS (SELECT 1 FROM automation_review_checkpoints WHERE id=?3)").bind(timestamp,step.id,checkpoint),
      db.prepare("UPDATE automation_runs SET status='queued',blocker_code=NULL,completed_at=NULL,next_attempt_at=NULL,lease_owner=NULL,lease_expires_at=NULL,updated_at=?1 WHERE id=?2 AND status='waiting_review' AND EXISTS (SELECT 1 FROM automation_review_checkpoints WHERE id=?3)").bind(timestamp,id,checkpoint),
      db.prepare("INSERT INTO automation_run_events (id,run_id,step_id,event,reason_code,attempt,occurred_at) SELECT ?1,?2,?3,'review_approved','assisted',?4,?5 WHERE EXISTS (SELECT 1 FROM automation_review_checkpoints WHERE id=?6)").bind(randomId(),id,step.id,run.attempt,timestamp,checkpoint),
    ]);
  }
  if (!await db.prepare('SELECT id FROM automation_review_checkpoints WHERE id=?1').bind(checkpoint).first()) throw new HttpError(409,'review_checkpoint_stale','Counter or run changed during approval'); return json({data:await publicAutomationRun(db,(await db.prepare('SELECT * FROM automation_runs WHERE id=?1').bind(id).first<AutomationRun>())!)});
}

async function createDueRuns(db: D1Database, at: string) {
  const schedules = await db.prepare("SELECT * FROM automation_schedules WHERE status='active' AND next_run_at<=?1 ORDER BY next_run_at LIMIT 50").bind(at).all<AutomationSchedule>();
  for (const schedule of schedules.results) { const policy = await db.prepare('SELECT * FROM automation_policies WHERE workspace_id=?1').bind(schedule.workspace_id).first<Record<string, unknown>>(); if (!policy) continue; const id = randomId(); const scheduledFor = schedule.next_run_at; const next = new Date(new Date(scheduledFor).getTime() + schedule.cadence_minutes * 60000).toISOString(); const key = `schedule:${schedule.id}:${scheduledFor}`; await db.batch([db.prepare("INSERT INTO automation_runs (id,schedule_id,workspace_id,idempotency_key,scheduled_for,policy_snapshot,configuration_snapshot,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'queued',?8,?8) ON CONFLICT(schedule_id,scheduled_for) DO NOTHING").bind(id,schedule.id,schedule.workspace_id,key,scheduledFor,JSON.stringify(policy),schedule.configuration,at),db.prepare('UPDATE automation_schedules SET last_run_at=?1,next_run_at=?2,updated_at=?3 WHERE id=?4 AND next_run_at=?1').bind(scheduledFor,next,at,schedule.id)]); }
}
type BoundaryOutcome={id:string;status:string;blocker_code:string|null};
async function responseData(response:Response):Promise<Record<string,unknown>> { const value=await response.json() as {data?:Record<string,unknown>}; return value.data ?? {}; }
async function callAutomationBoundary(db:D1Database,env:Env,row:AutomationRun,step:AutomationStep,stepKey:string,stepId:string,fence:number,auth:Auth,config:Record<string,unknown>):Promise<BoundaryOutcome> {
  const request=(payload:Record<string,unknown>)=>new Request('https://internal.vantaforge/v1/automation',{method:'POST',headers:{'content-type':'application/json','idempotency-key':stepKey},body:JSON.stringify(payload)});
  if (step==='idea_scout') { const data=await responseData(await createIdeaRun(request({provider:config.provider}),db,auth,row.workspace_id)); if (data.status!=='succeeded') return {id:String(data.id),status:String(data.status),blocker_code:(data.blocker as {code?:string}|null)?.code ?? null}; const candidate=await db.prepare('SELECT id,title,premise,evidence_json FROM idea_candidates WHERE run_id=?1 AND workspace_id=?2 ORDER BY created_at,id LIMIT 1').bind(data.id,row.workspace_id).first<{id:string;title:string;premise:string;evidence_json:string}>(); if (!candidate) return {id:String(data.id),status:'blocked',blocker_code:'idea_candidates_unavailable'}; const briefContent=JSON.stringify({title:candidate.title,premise:candidate.premise,evidence:JSON.parse(candidate.evidence_json)}); const brief=await responseData(await approveBrief(request({content:briefContent}),db,auth,candidate.id)); return {id:String(brief.id),status:'succeeded',blocker_code:null}; }
  if (step==='production') { const idea=await db.prepare("SELECT boundary_resource_id FROM automation_run_steps WHERE run_id=?1 AND step='idea_scout' AND status='succeeded'").bind(row.id).first<{boundary_resource_id:string}>(); if (!idea?.boundary_resource_id) throw new HttpError(409,'upstream_resource_unavailable','An approved brief from Idea Scout is required'); const data=await responseData(await createProduction(request({brief_id:idea.boundary_resource_id,asset_ids:config.asset_ids,provider:config.provider}),db,auth,row.workspace_id)); return {id:String(data.id),status:String(data.status),blocker_code:data.blocker_code ? String(data.blocker_code) : null}; }
  const production=await db.prepare("SELECT boundary_resource_id FROM automation_run_steps WHERE run_id=?1 AND step='production' AND status='succeeded'").bind(row.id).first<{boundary_resource_id:string}>(); if (!production?.boundary_resource_id) throw new HttpError(409,'upstream_resource_unavailable','A successful production boundary is required');
  if (step==='quality') { const data=await responseData(await createQualityGate(request({}),db,auth,production.boundary_resource_id)); return {id:String(data.id),status:String(data.status),blocker_code:(data.blocker as {code?:string}|null)?.code ?? null}; }
  const payload=asRecord(config.publishing); const created=await responseData(await createPublishRequest(request({...payload,production_job_id:production.boundary_resource_id}),db,auth,row.workspace_id)); const publishId=String(created.id);
  const claim=await db.prepare("INSERT INTO automation_publish_claims(publish_request_id,run_id,step_id,lease_fence,status,claimed_at) VALUES(?1,?2,?3,?4,'claimed',?5) ON CONFLICT DO NOTHING").bind(publishId,row.id,stepId,fence,now()).run();
  if (!claim.meta.changes) { const existing=await db.prepare('SELECT c.status,p.status AS publish_status,p.last_error_code FROM automation_publish_claims c JOIN publish_requests p ON p.id=c.publish_request_id WHERE c.publish_request_id=?1').bind(publishId).first<{status:string;publish_status:string;last_error_code:string|null}>(); return {id:publishId,status:existing?.status==='completed'?existing.publish_status:'blocked',blocker_code:existing?.status==='completed'?existing.last_error_code:'publish_claim_in_progress'}; }
  const attempted=await responseData(await attemptPublish(new Request('https://internal.vantaforge/v1/automation',{method:'POST'}),db,auth,env,publishId));
  await db.prepare("UPDATE automation_publish_claims SET status='completed',completed_at=?1 WHERE publish_request_id=?2 AND lease_fence=?3 AND status='claimed'").bind(now(),publishId,fence).run(); return {id:publishId,status:String(attempted.status),blocker_code:null};
}
async function reserveBudget(db:D1Database,row:AutomationRun,stepId:string,step:AutomationStep,config:Record<string,unknown>,policy:Record<string,unknown>,at:string):Promise<string|null> {
  const estimates=asRecord(config.cost_estimates_microusd); const estimate=Number(estimates[step] ?? 0); if (!Number.isSafeInteger(estimate) || estimate < 0) return 'cost_estimate_unavailable'; const perJob=ceilingMicros(policy.per_job_cost_limit); if (perJob===null) return 'job_cost_ceiling_required'; if (estimate>perJob) return 'job_cost_ceiling_exceeded';
  const existing=await db.prepare('SELECT id FROM automation_budget_reservations WHERE step_id=?1').bind(stepId).first<{id:string}>(); if (existing) return null; const date=at.slice(0,10); const daily=ceilingMicros(policy.daily_spend_limit); if (daily===null) return 'daily_cost_ceiling_required'; const id=randomId();
  await db.batch([db.prepare("INSERT INTO automation_budget_accounts (workspace_id,budget_date,limit_microusd,reserved_microusd,actual_microusd,updated_at) VALUES (?1,?2,?3,0,0,?4) ON CONFLICT(workspace_id,budget_date) DO UPDATE SET limit_microusd=excluded.limit_microusd,updated_at=excluded.updated_at WHERE actual_microusd+reserved_microusd<=excluded.limit_microusd").bind(row.workspace_id,date,daily,at),db.prepare('UPDATE automation_budget_accounts SET reserved_microusd=reserved_microusd+?1,version=version+1,updated_at=?2 WHERE workspace_id=?3 AND budget_date=?4 AND actual_microusd+reserved_microusd+?1<=limit_microusd').bind(estimate,at,row.workspace_id,date),db.prepare("INSERT INTO automation_budget_reservations (id,run_id,step_id,workspace_id,budget_date,estimate_microusd,status,created_at) SELECT ?1,?2,?3,?4,?5,?6,'reserved',?7 WHERE changes()=1").bind(id,row.id,stepId,row.workspace_id,date,estimate,at)]);
  return await db.prepare('SELECT id FROM automation_budget_reservations WHERE step_id=?1').bind(stepId).first() ? null : 'daily_cost_ceiling_exceeded';
}
async function reconcileBudget(db:D1Database,stepId:string,step:AutomationStep,boundaryId:string|null,at:string) { const reservation=await db.prepare("SELECT * FROM automation_budget_reservations WHERE step_id=?1 AND status='reserved'").bind(stepId).first<{id:string;workspace_id:string;budget_date:string;estimate_microusd:number}>(); if (!reservation) return; let actual=0; if (boundaryId && step==='production') { const ledger=await db.prepare('SELECT COALESCE(SUM(actual_microusd),0) AS amount FROM production_cost_ledger WHERE job_id=?1').bind(boundaryId).first<{amount:number}>(); actual=Number(ledger?.amount ?? 0); } else if (step==='idea_scout') { const run=await db.prepare('SELECT r.cost_json FROM idea_scout_runs r JOIN automation_run_steps s ON s.workspace_id=r.workspace_id AND s.idempotency_key=r.idempotency_key WHERE s.id=?1').bind(stepId).first<{cost_json:string|null}>(); if (run?.cost_json) { const cost=JSON.parse(run.cost_json) as Record<string,unknown>; actual=Number(cost.microusd ?? cost.actual_microusd ?? 0); } } if (!Number.isSafeInteger(actual) || actual<0) throw new HttpError(500,'cost_reconciliation_invalid','Provider cost evidence is invalid'); await db.batch([db.prepare('UPDATE automation_budget_accounts SET reserved_microusd=reserved_microusd-?1,actual_microusd=actual_microusd+?2,version=version+1,updated_at=?3 WHERE workspace_id=?4 AND budget_date=?5').bind(reservation.estimate_microusd,actual,at,reservation.workspace_id,reservation.budget_date),db.prepare("UPDATE automation_budget_reservations SET status='reconciled',actual_microusd=?1,reconciled_at=?2 WHERE id=?3 AND status='reserved'").bind(actual,at,reservation.id)]); }
async function executeAutomationRun(db: D1Database, env:Env, row: AutomationRun, worker: string, at: string) {
  const leaseUntil = new Date(new Date(at).getTime() + 60000).toISOString(); const claim = await db.prepare("UPDATE automation_runs SET status='running',attempt=attempt+1,lease_owner=?1,lease_expires_at=?2,lease_fence=lease_fence+1,started_at=COALESCE(started_at,?3),updated_at=?3 WHERE id=?4 AND cancel_requested_at IS NULL AND status IN ('queued','retry_scheduled','running') AND (lease_owner IS NULL OR lease_expires_at<=?3)").bind(worker,leaseUntil,at,row.id).run(); if (!claim.meta.changes) return;
  const schedule=await db.prepare('SELECT * FROM automation_schedules WHERE id=?1').bind(row.schedule_id).first<AutomationSchedule>(); if (!schedule) return; const auth:Auth={user:{id:schedule.created_by_user_id,email:'',display_name:'automation',status:'active'},token:''}; const config={...JSON.parse(row.configuration_snapshot) as Record<string,unknown>,provider:schedule.provider};
  for (let ordinal=1; ordinal<=AUTOMATION_STEPS.length; ordinal++) { const step = AUTOMATION_STEPS[ordinal-1]; const existing = await db.prepare('SELECT * FROM automation_run_steps WHERE run_id=?1 AND step=?2').bind(row.id,step).first<{status:string}>(); if (existing?.status === 'succeeded') continue; if (existing && ['blocked','failed','cancelled','waiting_review'].includes(existing.status)) return;
    const stepId=randomId(); const stepKey=`${row.id}:${step}`; await db.prepare("INSERT INTO automation_run_steps (id,run_id,workspace_id,step,ordinal,idempotency_key,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,'pending',?7,?7) ON CONFLICT(run_id,step) DO NOTHING").bind(stepId,row.id,row.workspace_id,step,ordinal,stepKey,at).run(); const stored = await db.prepare('SELECT id,status,attempt,lease_fence FROM automation_run_steps WHERE run_id=?1 AND step=?2').bind(row.id,step).first<{id:string;status:string;attempt:number;lease_fence:number}>(); if (!stored || stored.status === 'succeeded') continue; const stepClaim=await db.prepare("UPDATE automation_run_steps SET status='running',attempt=attempt+1,lease_owner=?1,lease_expires_at=?2,lease_fence=lease_fence+1,started_at=COALESCE(started_at,?3),updated_at=?3 WHERE id=?4 AND status IN ('pending','retry_scheduled','running') AND (lease_owner IS NULL OR lease_expires_at<=?3)").bind(worker,leaseUntil,at,stored.id).run(); if (!stepClaim.meta.changes) return;
    // Policy and the durable review counter are re-read immediately before every boundary.
    const policyRow = await db.prepare('SELECT * FROM automation_policies WHERE workspace_id=?1').bind(row.workspace_id).first<Record<string, unknown>>(); if (!policyRow) return; let enabled: unknown = null; try { enabled=JSON.parse(String(policyRow.enabled_capabilities)); } catch { /* policyBlocker fails closed */ } const livePolicy = { ...policyRow, enabled_capabilities: enabled } as unknown as AutomationPolicy;
    const counter = await db.prepare('SELECT shorts_since_review FROM automation_review_counters WHERE workspace_id=?1').bind(row.workspace_id).first<{shorts_since_review:number}>();
    const dayStart = `${at.slice(0,10)}T00:00:00.000Z`; const spend = await db.prepare('SELECT COALESCE(SUM(l.actual_microusd),0) AS amount FROM production_cost_ledger l JOIN production_jobs j ON j.id=l.job_id WHERE j.workspace_id=?1 AND l.created_at>=?2').bind(row.workspace_id,dayStart).first<{amount:number}>();
    const approved=Boolean(await db.prepare('SELECT id FROM automation_review_checkpoints WHERE run_id=?1 AND step_id=?2').bind(row.id,stored.id).first()); const blocker=policyBlocker(livePolicy,step,Number(counter?.shorts_since_review ?? 0),Number(spend?.amount ?? 0),approved);
    // Scheduler/autopilot must re-check the verified billing boundary directly
    // before a chargeable render or platform-delivery boundary.
    const billing= ['production','publishing'].includes(step) ? await usageSummary(db,row.workspace_id,at) : null;
    const billingBlocker=billing?.billing_status === 'billing_unavailable' ? 'billing_unavailable' : null;
    const budgetBlocker=blocker ?? billingBlocker ?? await reserveBudget(db,row,stored.id,step,config,policyRow,at); if (budgetBlocker) { const terminal=terminalState(budgetBlocker); await db.batch([db.prepare('UPDATE automation_run_steps SET status=?1,blocker_code=?2,completed_at=?3,lease_owner=NULL,lease_expires_at=NULL,updated_at=?3 WHERE id=?4').bind(terminal,budgetBlocker,at,stored.id),db.prepare('UPDATE automation_runs SET status=?1,current_step=?2,blocker_code=?3,completed_at=?4,lease_owner=NULL,lease_expires_at=NULL,updated_at=?4 WHERE id=?5').bind(terminal,step,budgetBlocker,at,row.id),db.prepare("INSERT INTO automation_run_events (id,run_id,step_id,event,reason_code,attempt,occurred_at) VALUES (?1,?2,?3,'blocked',?4,?5,?6)").bind(randomId(),row.id,stored.id,budgetBlocker,row.attempt+1,at)]); return; }
    const boundaryGuard=await db.prepare("UPDATE automation_runs SET updated_at=?1 WHERE id=?2 AND lease_owner=?3 AND cancel_requested_at IS NULL AND status='running' AND EXISTS (SELECT 1 FROM automation_policies p WHERE p.workspace_id=automation_runs.workspace_id AND p.stop_switch=0)").bind(at,row.id,worker).run(); if (!boundaryGuard.meta.changes) { await reconcileBudget(db,stored.id,step,null,at); return; }
    try { const renewedUntil=new Date(Date.now()+300000).toISOString(); const renewed=await db.prepare("UPDATE automation_run_steps SET lease_expires_at=?1 WHERE id=?2 AND lease_owner=?3 AND status='running'").bind(renewedUntil,stored.id,worker).run(); await db.prepare("UPDATE automation_runs SET lease_expires_at=?1 WHERE id=?2 AND lease_owner=?3 AND status='running'").bind(renewedUntil,row.id,worker).run(); if (!renewed.meta.changes) { await reconcileBudget(db,stored.id,step,null,at); return; } const fenced=await db.prepare('SELECT lease_fence FROM automation_run_steps WHERE id=?1').bind(stored.id).first<{lease_fence:number}>(); const outcome=await callAutomationBoundary(db,env,row,step,stepKey,stored.id,Number(fenced?.lease_fence),auth,config); await reconcileBudget(db,stored.id,step,outcome.id,at); if (outcome.status!=='succeeded') { const code=outcome.blocker_code ?? `${step}_blocked`; await db.batch([db.prepare("UPDATE automation_run_steps SET status='blocked',boundary_resource_id=?1,blocker_code=?2,completed_at=?3,lease_owner=NULL,lease_expires_at=NULL,updated_at=?3 WHERE id=?4 AND lease_owner=?5 AND lease_fence=?6").bind(outcome.id,code,at,stored.id,worker,fenced?.lease_fence),db.prepare("UPDATE automation_runs SET status='blocked',current_step=?1,blocker_code=?2,completed_at=?3,lease_owner=NULL,lease_expires_at=NULL,updated_at=?3 WHERE id=?4 AND lease_owner=?5").bind(step,code,at,row.id,worker)]); return; } await db.prepare("UPDATE automation_run_steps SET status='succeeded',boundary_resource_id=?1,blocker_code=NULL,completed_at=?2,lease_owner=NULL,lease_expires_at=NULL,updated_at=?2 WHERE id=?3 AND lease_owner=?4 AND lease_fence=?5").bind(outcome.id,at,stored.id,worker,fenced?.lease_fence).run(); }
    catch(error) { if (!(error instanceof HttpError) && !(error instanceof ValidationError)) console.error(error); await reconcileBudget(db,stored.id,step,null,at); const http=error instanceof HttpError ? error : error instanceof ValidationError ? new HttpError(400,'validation_error',error.message) : new HttpError(500,'internal_error','Automation boundary failed'); const attempt=stored.attempt+1; const retry=retryableAutomationCode(http.code) && attempt<MAX_AUTOMATION_ATTEMPTS; const next=retry ? new Date(new Date(at).getTime()+automationRetryDelay(attempt)*1000).toISOString() : null; const state=retry?'retry_scheduled':'failed'; await db.batch([db.prepare('UPDATE automation_run_steps SET status=?1,blocker_code=?2,next_attempt_at=?3,completed_at=?4,lease_owner=NULL,lease_expires_at=NULL,updated_at=?4 WHERE id=?5').bind(state,http.code,next,retry?null:at,stored.id),db.prepare('UPDATE automation_runs SET status=?1,current_step=?2,blocker_code=?3,next_attempt_at=?4,completed_at=?5,lease_owner=NULL,lease_expires_at=NULL,updated_at=?6 WHERE id=?7').bind(state,step,http.code,next,retry?null:at,at,row.id),db.prepare("INSERT INTO automation_run_events (id,run_id,step_id,event,reason_code,attempt,occurred_at) VALUES (?1,?2,?3,?4,?5,?6,?7)").bind(randomId(),row.id,stored.id,state,http.code,attempt,at)]); return; }
  }
  await db.prepare("UPDATE automation_runs SET status='succeeded',current_step=NULL,blocker_code=NULL,completed_at=?1,lease_owner=NULL,lease_expires_at=NULL,updated_at=?1 WHERE id=?2 AND lease_owner=?3").bind(at,row.id,worker).run();
}
async function runScheduler(env:Env, at = now()) { await createDueRuns(env.DB,at); const runs=await env.DB.prepare("SELECT * FROM automation_runs WHERE cancel_requested_at IS NULL AND (status='queued' OR (status='retry_scheduled' AND next_attempt_at<=?1) OR (status='running' AND lease_expires_at<=?1)) ORDER BY scheduled_for LIMIT 25").bind(at).all<AutomationRun>(); const worker=randomId(); for (const run of runs.results) await executeAutomationRun(env.DB,env,run,worker,at); }

export default { async scheduled(_controller: ScheduledController, env: Env): Promise<void> { if (env.AUTOMATION_SCHEDULER_ENABLED === 'true') await runScheduler(env); }, async fetch(request: Request, env: Env): Promise<Response> {
  const headers: HeadersInit = {};
  if (env.ALLOWED_ORIGIN) Object.assign(headers, { "access-control-allow-origin": env.ALLOWED_ORIGIN, "access-control-allow-headers": "authorization,content-type,idempotency-key", "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS" });
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
  try {
    const url = new URL(request.url); const path = url.pathname.replace(/\/+$/, "") || "/";
    if (path === "/health" && request.method === "GET") return json({ data: { status: "ok" } }, 200, headers);
    if (path === "/v1/auth/signup" && request.method === "POST") return await signup(request, env.DB);
    if (path === "/v1/auth/login" && request.method === "POST") return await login(request, env.DB);
    const uploadContentMatch = path.match(/^\/v1\/assets\/uploads\/([^/]+)\/content$/); if (uploadContentMatch && request.method === "PUT") return await uploadAssetContent(request, env.DB, env, uploadContentMatch[1]);
    if (path === "/v1/publishing/oauth/callback" && request.method === "GET") return await oauthCallback(request, env.DB, env);
    const auth = requireAuth(await authenticate(request, env.DB));
    if (path === "/v1/auth/me" && request.method === "GET") return json({ data: { user: auth.user } }, 200, headers);
    if (path === "/v1/auth/logout" && request.method === "POST") { await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(await sha256(auth.token)).run(); return json({ data: { logged_out: true } }, 200, headers); }
    if (path === "/v1/workspaces" && request.method === "GET") return json({ data: await env.DB.prepare("SELECT w.*, m.role FROM workspaces w JOIN memberships m ON m.workspace_id=w.id WHERE m.user_id=?1 AND m.status='active' ORDER BY w.created_at DESC").bind(auth.user.id).all() }, 200, headers);
    if (path === "/v1/workspaces" && request.method === "POST") return await createWorkspace(request, env.DB, auth);
    const usageMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/usage$/); if (usageMatch && request.method === 'GET') return await workspaceUsage(request, env.DB, auth, usageMatch[1]);
    const usagePolicyMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/usage-policy$/); if (usagePolicyMatch && request.method === 'PUT') return await usagePolicy(request, env.DB, auth, usagePolicyMatch[1]);
    const schedulesMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/automation-schedules$/); if (schedulesMatch && ['GET','POST'].includes(request.method)) return await automationSchedules(request,env.DB,auth,env,schedulesMatch[1]);
    const scheduleControlMatch = path.match(/^\/v1\/automation-schedules\/([^/]+)\/control$/); if (scheduleControlMatch && request.method === 'POST') return await controlAutomationSchedule(request,env.DB,auth,env,scheduleControlMatch[1]);
    const automationRunsMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/automation-runs$/); if (automationRunsMatch && request.method === 'GET') return await automationRuns(request,env.DB,auth,automationRunsMatch[1]);
    const automationRunMatch = path.match(/^\/v1\/automation-runs\/([^/]+)(?:\/(cancel))?$/); if (automationRunMatch && ((!automationRunMatch[2] && request.method === 'GET') || (automationRunMatch[2] && request.method === 'POST'))) return await automationRun(request,env.DB,auth,automationRunMatch[1],Boolean(automationRunMatch[2]));
    const automationApproveMatch = path.match(/^\/v1\/automation-runs\/([^/]+)\/approve$/); if (automationApproveMatch && request.method === 'POST') return await approveAutomationRun(request,env.DB,auth,automationApproveMatch[1]);
    const publishingConnectionsMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/publishing-connections$/); if (publishingConnectionsMatch && request.method === "GET") return await publishingConnections(request, env.DB, auth, publishingConnectionsMatch[1]);
    const publishingOAuthMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/publishing-connections\/oauth$/); if (publishingOAuthMatch && request.method === "POST") return await startPublishingOAuth(request, env.DB, auth, env, publishingOAuthMatch[1]);
    const publishingRevokeMatch = path.match(/^\/v1\/publishing-connections\/([^/]+)\/revoke$/); if (publishingRevokeMatch && request.method === "POST") return await revokePublishingConnection(request, env.DB, auth, env, publishingRevokeMatch[1]);
    const analyticsCreateMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/analytics-runs$/); if (analyticsCreateMatch && request.method === "POST") return await createAnalyticsRun(request, env.DB, auth, env, analyticsCreateMatch[1]);
    const analyticsListMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/analytics$/); if (analyticsListMatch && request.method === "GET") return await listAnalytics(request, env.DB, auth, analyticsListMatch[1]);
    const suggestionCreateMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/experiment-suggestions$/); if (suggestionCreateMatch && request.method === "POST") return await createSuggestion(request, env.DB, auth, env, suggestionCreateMatch[1]);
    const analyticsRunMatch = path.match(/^\/v1\/analytics-runs\/([^/]+)$/); if (analyticsRunMatch && request.method === "GET") return await getAnalyticsRun(request, env.DB, auth, analyticsRunMatch[1]);
    const publishCreateMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/publish-requests$/); if (publishCreateMatch && request.method === "POST") return await createPublishRequest(request, env.DB, auth, publishCreateMatch[1]);
    const publishAttemptMatch = path.match(/^\/v1\/publish-requests\/([^/]+)\/attempt$/); if (publishAttemptMatch && request.method === "POST") return await attemptPublish(request, env.DB, auth, env, publishAttemptMatch[1]);
    const publishGetMatch = path.match(/^\/v1\/publish-requests\/([^/]+)$/); if (publishGetMatch && request.method === "GET") { const item = await env.DB.prepare("SELECT * FROM publish_requests WHERE id=?1").bind(publishGetMatch[1]).first<PublishRequestRow>(); if (!item) throw new HttpError(404, "publish_request_not_found", "Publish request not found"); await providerAccess(request, env.DB, auth, item.workspace_id); return json({ data: publicPublishRequest(item) }); }
    const approveBriefMatch = path.match(/^\/v1\/ideas\/([^/]+)\/approve-brief$/); if (approveBriefMatch && request.method === 'POST') return await approveBrief(request,env.DB,auth,approveBriefMatch[1]);
    const productionCreateMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/production-jobs$/); if (productionCreateMatch && request.method === 'POST') return await createProduction(request,env.DB,auth,productionCreateMatch[1]);
    const productionMatch = path.match(/^\/v1\/production-jobs\/([^/]+)(?:\/(cancel))?$/); if (productionMatch && ((!productionMatch[2] && request.method === 'GET') || (productionMatch[2] && request.method === 'POST'))) return await productionJob(request,env.DB,auth,productionMatch[1],Boolean(productionMatch[2]));
    const qualityCreateMatch = path.match(/^\/v1\/production-jobs\/([^/]+)\/quality-gate$/); if (qualityCreateMatch && request.method === 'POST') return await createQualityGate(request, env.DB, auth, qualityCreateMatch[1]);
    const qualityDecisionMatch = path.match(/^\/v1\/quality-gates\/([^/]+)\/decision$/); if (qualityDecisionMatch && request.method === 'POST') return await qualityDecision(request, env.DB, auth, qualityDecisionMatch[1]);
    const qualityMatch = path.match(/^\/v1\/quality-gates\/([^/]+)$/); if (qualityMatch && request.method === 'GET') return await getQualityGate(request, env.DB, auth, qualityMatch[1]);
    const ideaRunsMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/idea-runs$/); if (ideaRunsMatch && request.method === "POST") return await createIdeaRun(request, env.DB, auth, ideaRunsMatch[1]);
    const ideaRunMatch = path.match(/^\/v1\/idea-runs\/([^/]+)$/); if (ideaRunMatch && request.method === "GET") return await getIdeaRun(request, env.DB, auth, ideaRunMatch[1]);
    const assetsMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/assets$/); if (assetsMatch && request.method === "GET") return await listAssets(request, env.DB, auth, assetsMatch[1]);
    const uploadIntentMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/assets\/uploads$/); if (uploadIntentMatch && request.method === "POST") return await createUploadIntent(request, env.DB, auth, env, uploadIntentMatch[1]);
    const assetMatch = path.match(/^\/v1\/assets\/([^/]+)(?:\/(complete|download))?$/); if (assetMatch) { if (!assetMatch[2] && request.method === "GET") return await getAsset(request, env.DB, auth, assetMatch[1]); if (assetMatch[2] === "complete" && request.method === "POST") return await completeAsset(request, env.DB, auth, env, assetMatch[1]); if (assetMatch[2] === "download" && request.method === "GET") return await downloadAsset(request, env.DB, auth, env, assetMatch[1]); }
    const providerListMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers$/);
    if (providerListMatch && request.method === "GET") return await listProviders(request, env.DB, auth, providerListMatch[1]);
    const providerModelsMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers\/models$/);
    if (providerModelsMatch && request.method === "GET") return await listModels(request, env.DB, auth, providerModelsMatch[1]);
    const providerCredentialMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers\/([^/]+)\/credentials$/);
    if (providerCredentialMatch && request.method === "PUT") return await saveCredential(request, env.DB, auth, env, providerCredentialMatch[1], providerCredentialMatch[2]);
    if (providerCredentialMatch && request.method === "DELETE") return await deleteCredential(request, env.DB, auth, providerCredentialMatch[1], providerCredentialMatch[2]);
    const providerModelMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers\/([^/]+)\/models$/);
    if (providerModelMatch && request.method === "PATCH") return await selectModel(request, env.DB, auth, providerModelMatch[1], providerModelMatch[2]);
    const providerVerifyMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers\/([^/]+)\/verify$/);
    if (providerVerifyMatch && request.method === "POST") return await verifyProvider(request, env.DB, auth, env, providerVerifyMatch[1], providerVerifyMatch[2]);
    const providerIdMatch = path.match(/^\/v1\/ai-providers\/([^/]+)\/(credentials|models|verify)$/);
    if (providerIdMatch) {
      const connection = await env.DB.prepare("SELECT id,workspace_id,provider,credential_kind,encrypted_secret,selected_model,status,last_verified_at,last_error_code,created_at,updated_at FROM ai_provider_connections WHERE id=?1").bind(providerIdMatch[1]).first<ProviderConnection>();
      if (!connection) throw new HttpError(404, "provider_connection_not_found", "Provider connection not found");
      if (providerIdMatch[2] === "credentials" && request.method === "PUT") return await saveCredential(request, env.DB, auth, env, connection.workspace_id, connection.provider);
      if (providerIdMatch[2] === "credentials" && request.method === "DELETE") return await deleteCredential(request, env.DB, auth, connection.workspace_id, connection.id);
      if (providerIdMatch[2] === "models" && request.method === "PATCH") return await selectModel(request, env.DB, auth, connection.workspace_id, connection.id);
      if (providerIdMatch[2] === "verify" && request.method === "POST") return await verifyProvider(request, env.DB, auth, env, connection.workspace_id, connection.id);
    }
    const match = path.match(/^\/v1\/workspaces\/([^/]+)(?:\/(policy))?$/); if (match) { if (match[2] === "policy") return await policy(request, env.DB, auth, match[1]); if (request.method === "PUT") return await updateWorkspace(request, env.DB, auth, match[1]); if (request.method === "GET") { const item = await workspace(request, env.DB, auth.user.id, match[1]); if (!item) throw new HttpError(404, "workspace_not_found", "Workspace not found"); return json({ data: item }, 200, headers); } }
    return fail(404, "not_found", "Route not found");
  } catch (error) { if (error instanceof HttpError) return fail(error.status, error.code, error.message, error.details); if (error instanceof ValidationError) return fail(400, "validation_error", error.message); console.error(error); return fail(500, "internal_error", "The request could not be completed"); }
} };
