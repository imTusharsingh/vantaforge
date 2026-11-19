import { decryptSecret, encryptSecret, hashPassword, randomId, randomToken, sha256, verifyPassword } from "./crypto";
import { modelDefinition, PROVIDERS, providerDefinition } from "./providers";
import { asRecord, email, password, requiredString, slug, ValidationError } from "./validation";

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

export default { async fetch(request: Request, env: Env): Promise<Response> {
  const headers: HeadersInit = {};
  if (env.ALLOWED_ORIGIN) Object.assign(headers, { "access-control-allow-origin": env.ALLOWED_ORIGIN, "access-control-allow-headers": "authorization,content-type", "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS" });
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
