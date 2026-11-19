import { decryptSecret, encryptSecret, hashPassword, randomId, randomToken, sha256, verifyPassword } from "./crypto";
import { modelDefinition, PROVIDERS, providerDefinition } from "./providers";
import { asRecord, email, password, requiredString, slug, ValidationError } from "./validation";

export interface Env { DB: D1Database; ALLOWED_ORIGIN?: string; CREDENTIAL_ENCRYPTION_KEY?: string }
type User = { id: string; email: string; display_name: string; status: string };
type Auth = { user: User; token: string };

const json = (body: unknown, status = 200, headers: HeadersInit = {}) => Response.json(body, { status, headers: { "cache-control": "no-store", ...headers } });
const fail = (status: number, code: string, message: string, details?: Record<string, unknown>) => json({ error: { code, message, ...(details ? { details } : {}) }, request_id: crypto.randomUUID() }, status);
const now = () => new Date().toISOString();

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

export default { async fetch(request: Request, env: Env): Promise<Response> {
  const headers: HeadersInit = {};
  if (env.ALLOWED_ORIGIN) Object.assign(headers, { "access-control-allow-origin": env.ALLOWED_ORIGIN, "access-control-allow-headers": "authorization,content-type", "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS" });
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
  try {
    const url = new URL(request.url); const path = url.pathname.replace(/\/+$/, "") || "/";
    if (path === "/health" && request.method === "GET") return json({ data: { status: "ok" } }, 200, headers);
    if (path === "/v1/auth/signup" && request.method === "POST") return signup(request, env.DB);
    if (path === "/v1/auth/login" && request.method === "POST") return login(request, env.DB);
    const auth = requireAuth(await authenticate(request, env.DB));
    if (path === "/v1/auth/me" && request.method === "GET") return json({ data: { user: auth.user } }, 200, headers);
    if (path === "/v1/auth/logout" && request.method === "POST") { await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(await sha256(auth.token)).run(); return json({ data: { logged_out: true } }, 200, headers); }
    if (path === "/v1/workspaces" && request.method === "GET") return json({ data: await env.DB.prepare("SELECT w.*, m.role FROM workspaces w JOIN memberships m ON m.workspace_id=w.id WHERE m.user_id=?1 AND m.status='active' ORDER BY w.created_at DESC").bind(auth.user.id).all() }, 200, headers);
    if (path === "/v1/workspaces" && request.method === "POST") return createWorkspace(request, env.DB, auth);
    const providerListMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers$/);
    if (providerListMatch && request.method === "GET") return listProviders(request, env.DB, auth, providerListMatch[1]);
    const providerModelsMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers\/models$/);
    if (providerModelsMatch && request.method === "GET") return listModels(request, env.DB, auth, providerModelsMatch[1]);
    const providerCredentialMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers\/([^/]+)\/credentials$/);
    if (providerCredentialMatch && request.method === "PUT") return saveCredential(request, env.DB, auth, env, providerCredentialMatch[1], providerCredentialMatch[2]);
    if (providerCredentialMatch && request.method === "DELETE") return deleteCredential(request, env.DB, auth, providerCredentialMatch[1], providerCredentialMatch[2]);
    const providerModelMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers\/([^/]+)\/models$/);
    if (providerModelMatch && request.method === "PATCH") return selectModel(request, env.DB, auth, providerModelMatch[1], providerModelMatch[2]);
    const providerVerifyMatch = path.match(/^\/v1\/workspaces\/([^/]+)\/ai-providers\/([^/]+)\/verify$/);
    if (providerVerifyMatch && request.method === "POST") return verifyProvider(request, env.DB, auth, env, providerVerifyMatch[1], providerVerifyMatch[2]);
    const providerIdMatch = path.match(/^\/v1\/ai-providers\/([^/]+)\/(credentials|models|verify)$/);
    if (providerIdMatch) {
      const connection = await env.DB.prepare("SELECT id,workspace_id,provider,credential_kind,encrypted_secret,selected_model,status,last_verified_at,last_error_code,created_at,updated_at FROM ai_provider_connections WHERE id=?1").bind(providerIdMatch[1]).first<ProviderConnection>();
      if (!connection) throw new HttpError(404, "provider_connection_not_found", "Provider connection not found");
      if (providerIdMatch[2] === "credentials" && request.method === "PUT") return saveCredential(request, env.DB, auth, env, connection.workspace_id, connection.provider);
      if (providerIdMatch[2] === "credentials" && request.method === "DELETE") return deleteCredential(request, env.DB, auth, connection.workspace_id, connection.id);
      if (providerIdMatch[2] === "models" && request.method === "PATCH") return selectModel(request, env.DB, auth, connection.workspace_id, connection.id);
      if (providerIdMatch[2] === "verify" && request.method === "POST") return verifyProvider(request, env.DB, auth, env, connection.workspace_id, connection.id);
    }
    const match = path.match(/^\/v1\/workspaces\/([^/]+)(?:\/(policy))?$/); if (match) { if (match[2] === "policy") return policy(request, env.DB, auth, match[1]); if (request.method === "PUT") return updateWorkspace(request, env.DB, auth, match[1]); if (request.method === "GET") { const item = await workspace(request, env.DB, auth.user.id, match[1]); if (!item) throw new HttpError(404, "workspace_not_found", "Workspace not found"); return json({ data: item }, 200, headers); } }
    return fail(404, "not_found", "Route not found");
  } catch (error) { if (error instanceof HttpError) return fail(error.status, error.code, error.message); if (error instanceof ValidationError) return fail(400, "validation_error", error.message); console.error(error); return fail(500, "internal_error", "The request could not be completed"); }
} };
