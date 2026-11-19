# VantaForge

VantaForge is an AI-assisted short-form video operating system for high-quality real-footage content. It turns a creator's workspace brief, source assets, channel signals, and cost policy into reviewed, scheduled YouTube Shorts and Instagram Reels.

## Product architecture

- **Identity & workspaces**: account, workspace, roles, onboarding, automation controls.
- **Creative system**: workspace briefs, reusable brand rules, licensed stock/creator uploads, characters, locations, shot recipes, voice and caption presets.
- **Idea Scout**: topic discovery, trend signals, channel gap analysis, briefs, and approval rules.
- **Production pipeline**: script → shot plan → asset retrieval/generation → edit/render → captions/audio → cost ledger.
- **Quality Gate**: safety, factuality, brand fit, pacing, hook strength, audio/visual quality, platform compliance, and human approval policies.
- **Publishing**: YouTube and Instagram connections, scheduling, retries, idempotency, and post-publish status.
- **Growth Analyst**: channel analytics, retention/engagement patterns, experiment suggestions, and next-idea ranking.
- **AI provider settings**: user-owned API keys stored encrypted, model allowlist, capability checks, warning states, quotas, and explicit blocked states. No server-side AI key is assumed.

## Core domain flow

```text
Workspace brief → Idea Scout → Script + shot plan → Real-footage assembly
      ↓                                      ↓
Growth Analyst ← Published analytics ← Quality Gate ← Cost Gate
```

Every job carries a `workspace_id`, `policy_snapshot`, `cost_budget`, `provider_snapshot`, and audit trail. A job cannot publish unless quality and cost gates both pass.

## Automation policy

Automation is explicit and reversible. Each workspace can independently configure:

- idea discovery, script drafting, production, review, and publishing;
- daily/weekly spend limits and per-short maximum cost;
- “review every short”, “review after N shorts”, or full autopilot;
- a stop switch that cancels queued work and prevents new publishing.

## Delivery plan

1. Product shell, workspace dashboard, and architecture contracts.
2. Authentication/workspace persistence and settings.
3. Asset library and upload pipeline.
4. Idea Scout and brief approval flow.
5. Production orchestration with real-footage providers.
6. Quality Gate and cost ledger.
7. YouTube/Instagram publishing adapters.
8. Growth Analyst and automation policy engine.
9. Observability, security hardening, billing/limits, and deployment.

## Security principles

User AI keys are encrypted at rest, never logged, and only decrypted at the provider boundary. OAuth tokens are encrypted and scoped minimally. Uploaded assets are private by default. Every automated action is auditable and cancellable.

## Identity and workspace foundation

The first runnable backend slice is a dependency-light Cloudflare Worker backed
by D1. It lives under [`src/server/`](./src/server/) and does not call an AI
provider or require an AI credential.

Apply [`0001_identity.sql`](./src/server/migrations/0001_identity.sql) to a D1
database, set its ID in [`wrangler.toml`](./wrangler.toml), then run the Worker
with Wrangler. The Worker exposes signup/login/logout, `GET /v1/auth/me`, workspace
CRUD under `/v1/workspaces`, and automation-policy read/update under
`/v1/workspaces/:id/policy`.

Passwords are salted and derived with PBKDF2-SHA-256 using Web Crypto. Session
tokens are random, only their SHA-256 digests are stored, and expired sessions
are rejected. Workspace access is always resolved through an active
membership. Owners and admins can edit workspace settings and change the
automation policy; other members can read resources. Errors are structured
without exposing database or credential details. Workspace creation initializes
an explicit assisted-mode policy, with no mock data or AI fallback involved.

Local verification:

```sh
npm install
npm run check
npx wrangler d1 migrations apply vantaforge --local
npx wrangler dev
```

## AI provider settings

Provider credentials are workspace-scoped and write-only. Before using these
routes, configure the dedicated encryption secret with Wrangler:

```sh
npx wrangler secret put CREDENTIAL_ENCRYPTION_KEY
```

This is an encryption key for VantaForge, not an AI provider key. Users submit
their own provider key through the settings API; only encrypted AES-GCM
ciphertext is stored. The API never returns the raw key or ciphertext.

The provider routes are:

- `GET /v1/workspaces/:id/ai-providers` — catalog plus connection status.
- `GET /v1/workspaces/:id/ai-providers/models?provider=openai` — supported models.
- `PUT/DELETE /v1/workspaces/:id/ai-providers/:provider/credentials` — save or remove a key.
- `POST /v1/workspaces/:id/ai-providers/:provider/verify` — perform a real provider verification.
- `PATCH /v1/workspaces/:id/ai-providers/:provider/models` — select a model after verification.

Missing encryption configuration, missing credentials, invalid keys, unsupported
models, and providers without a live adapter are explicit errors. No provider
response or generated content is mocked.

## AI provider settings API

AI provider settings are workspace-scoped. Owners and admins can manage them
using an authenticated session. The API never returns an API key or its
ciphertext:

```text
GET    /v1/workspaces/:workspace_id/ai-providers
GET    /v1/workspaces/:workspace_id/ai-providers/models?provider=openai
PUT    /v1/workspaces/:workspace_id/ai-providers/:provider/credentials
DELETE /v1/workspaces/:workspace_id/ai-providers/:provider/credentials
POST   /v1/workspaces/:workspace_id/ai-providers/:provider/verify
PATCH  /v1/workspaces/:workspace_id/ai-providers/:provider/models
```

Credential writes accept `{ "api_key": "..." }` once and return only
configuration status. Model selection is restricted to the catalog and is
blocked until the connection has been live-verified. `openai` has a real
`GET /v1/models` verification adapter; `anthropic` is catalogued but returns a
truthful unverified response until an adapter is implemented. Provider errors,
missing credentials, unsupported models, unavailable providers, and missing
encryption configuration are returned as typed errors rather than mock
successes.

Set the dedicated encryption secret before using credential routes. It is not
an AI provider key and must not be placed in source control or ordinary
configuration:

```sh
npx wrangler secret put CREDENTIAL_ENCRYPTION_KEY
```

The value must be a 32-byte base64 secret or a 64-character hexadecimal
secret. Credentials are encrypted with Web Crypto AES-GCM before D1 storage.
Apply [`0002_ai_provider_settings.sql`](./src/server/migrations/0002_ai_provider_settings.sql)
after the identity migration.
