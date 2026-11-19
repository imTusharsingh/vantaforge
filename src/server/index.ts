import { canTransition, ceilingMicros, costBlocker, type ProductionState } from './production';
import { ideaScoutBlocker } from "./idea-scout";
import { decryptSecret, encryptSecret, hashPassword, randomId, randomToken, sha256, verifyPassword } from "./crypto";
import { modelDefinition, PROVIDERS, providerDefinition } from "./providers";
import { asRecord, email, password, requiredString, slug, ValidationError } from "./validation";
import { evaluateDeterministicQuality, qualityScore, type QualityAsset, type QualityFinding } from './quality';

export interface Env { DB: D1Database; ASSETS?: R2Bucket; ALLOWED_ORIGIN?: string; CREDENTIAL_ENCRYPTION_KEY?: string }
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

class HttpError extends Error { constructor(public status: number, public code: string, message: string) { super(message); } }

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
  const current = await db.prepare("SELECT * FROM automation_policies WHERE workspace_id=?1").bind(id).first<Record<string, unknown>>(); if (!current) throw new HttpError(404, "policy_not_found", "Automation policy not found");
  const next = { mode: input.mode ?? current.mode, enabled: input.enabled_capabilities ?? JSON.parse(String(current.enabled_capabilities)), review: input.review_mode ?? current.review_mode, after: input.review_after_count ?? current.review_after_count, daily: input.daily_spend_limit ?? current.daily_spend_limit, perJob: input.per_job_cost_limit ?? current.per_job_cost_limit, stop: input.stop_switch ?? Boolean(current.stop_switch) };
  if (!Array.isArray(next.enabled)) throw new ValidationError("enabled_capabilities is invalid");
  await db.prepare("UPDATE automation_policies SET mode=?1, enabled_capabilities=?2, review_mode=?3, review_after_count=?4, daily_spend_limit=?5, per_job_cost_limit=?6, stop_switch=?7, version=version+1, updated_at=?8 WHERE workspace_id=?9").bind(next.mode, JSON.stringify(next.enabled), next.review, next.after, next.daily, next.perJob, next.stop ? 1 : 0, now(), id).run();
  return json({ data: await db.prepare("SELECT * FROM automation_policies WHERE workspace_id=?1").bind(id).first() });
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
  return json({ data: { ...job, asset_ids: JSON.parse(String(job.asset_ids)), policy_snapshot: JSON.parse(String(job.policy_snapshot)), provider_snapshot: JSON.parse(String(job.provider_snapshot)), events: events.results, ledger: ledger.results } }, status);
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
  const assets = assetIds.length ? await db.prepare(`SELECT id,kind,media_type,duration_seconds,width,height,metadata,status,scan_status,licensing_status,rights_confirmed,license_type FROM assets WHERE workspace_id=?1 AND id IN (${assetIds.map(() => '?').join(',')})`).bind(job.workspace_id, ...assetIds).all<QualityAsset>() : { results: [] as QualityAsset[] };
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
  const connection = await connectionFor(db,workspaceId,provider);
  const snapshot = { provider, model: connection?.selected_model ?? null, verified_at: connection?.last_verified_at ?? null };
  let blocker: string | null = null;
  let enabled: unknown; try { enabled = JSON.parse(String(policy.enabled_capabilities)); } catch { enabled = null; }
  if (member.status !== 'active' || policy.stop_switch || !Array.isArray(enabled) || !enabled.includes('production')) blocker = 'policy_blocked';
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
  const ceiling = ceilingMicros(policy.per_job_cost_limit);
  if (!blocker) blocker = costBlocker(ceiling, null);
  // There is no render adapter or price bound. No provider invocation is permitted.
  const id = randomId(); const timestamp = now();
  await db.batch([
    db.prepare("INSERT INTO production_jobs (id,workspace_id,created_by_user_id,brief_id,asset_ids,idempotency_key,request_hash,policy_snapshot,provider_snapshot,ceiling_microusd,estimate_microusd,estimate_reason,status,blocker_code,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,'render_provider_unavailable','blocked',?11,?12,?12) ON CONFLICT(workspace_id,idempotency_key) DO NOTHING").bind(id,workspaceId,auth.user.id,brief,JSON.stringify(assetIds),key,hash,JSON.stringify(policy),JSON.stringify(snapshot),ceiling,blocker,timestamp),
    db.prepare("INSERT INTO production_job_events (id,job_id,status,reason,actor_id,created_at) SELECT ?1,id,'planning',NULL,?2,?3 FROM production_jobs WHERE id=?4").bind(randomId(),auth.user.id,timestamp,id),
    db.prepare("INSERT INTO production_job_events (id,job_id,status,reason,actor_id,created_at) SELECT ?1,id,'blocked',blocker_code,?2,?3 FROM production_jobs WHERE id=?4").bind(randomId(),auth.user.id,timestamp,id),
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

export default { async fetch(request: Request, env: Env): Promise<Response> {
  const headers: HeadersInit = {};
  if (env.ALLOWED_ORIGIN) Object.assign(headers, { "access-control-allow-origin": env.ALLOWED_ORIGIN, "access-control-allow-headers": "authorization,content-type,idempotency-key", "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS" });
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
  try {
    const url = new URL(request.url); const path = url.pathname.replace(/\/+$/, "") || "/";
    if (path === "/health" && request.method === "GET") return json({ data: { status: "ok" } }, 200, headers);
    if (path === "/v1/auth/signup" && request.method === "POST") return await signup(request, env.DB);
    if (path === "/v1/auth/login" && request.method === "POST") return await login(request, env.DB);
    const uploadContentMatch = path.match(/^\/v1\/assets\/uploads\/([^/]+)\/content$/); if (uploadContentMatch && request.method === "PUT") return await uploadAssetContent(request, env.DB, env, uploadContentMatch[1]);
    const auth = requireAuth(await authenticate(request, env.DB));
    if (path === "/v1/auth/me" && request.method === "GET") return json({ data: { user: auth.user } }, 200, headers);
    if (path === "/v1/auth/logout" && request.method === "POST") { await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(await sha256(auth.token)).run(); return json({ data: { logged_out: true } }, 200, headers); }
    if (path === "/v1/workspaces" && request.method === "GET") return json({ data: await env.DB.prepare("SELECT w.*, m.role FROM workspaces w JOIN memberships m ON m.workspace_id=w.id WHERE m.user_id=?1 AND m.status='active' ORDER BY w.created_at DESC").bind(auth.user.id).all() }, 200, headers);
    if (path === "/v1/workspaces" && request.method === "POST") return await createWorkspace(request, env.DB, auth);
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
  } catch (error) { if (error instanceof HttpError) return fail(error.status, error.code, error.message); if (error instanceof ValidationError) return fail(400, "validation_error", error.message); console.error(error); return fail(500, "internal_error", "The request could not be completed"); }
} };
