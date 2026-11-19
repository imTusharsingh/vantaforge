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

### Private real-footage asset library

Migration [`0003_assets.sql`](./src/server/migrations/0003_assets.sql) adds
workspace-owned assets and licensing references. Configure the private R2
bucket in [`wrangler.toml`](./wrangler.toml). Upload intents return only an
opaque, expiring Worker URL; storage keys remain server-side. Uploads accept
real video types only, enforce declared bytes, and require a SHA-256 checksum,
positive duration, and explicit licensing/rights fields at completion.

No real malware scanner is configured in this slice, so completion truthfully
leaves the asset `status=blocked` with `scan_status=unavailable`; it never
creates a fake clean scan or ready asset. Metadata and downloads require active
workspace membership, and downloads are streamed through the Worker only for
ready assets. Routes are `POST /v1/workspaces/:id/assets/uploads`,
`PUT /v1/assets/uploads/:id/content?token=...`,
`POST /v1/assets/:id/complete`, `GET /v1/workspaces/:id/assets`,
`GET /v1/assets/:id`, and `GET /v1/assets/:id/download`.

Local verification:

```sh
pnpm install --frozen-lockfile
pnpm run check
pnpm exec wrangler d1 migrations apply vantaforge --local
pnpm exec wrangler dev
```

## AI provider settings

Provider credentials are workspace-scoped and write-only. Before using these
routes, configure the dedicated encryption secret with Wrangler:

```sh
pnpm exec wrangler secret put CREDENTIAL_ENCRYPTION_KEY
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
pnpm exec wrangler secret put CREDENTIAL_ENCRYPTION_KEY
```

The value must be a 32-byte base64 secret or a 64-character hexadecimal
secret. Credentials are encrypted with Web Crypto AES-GCM before D1 storage.
Apply [`0002_ai_provider_settings.sql`](./src/server/migrations/0002_ai_provider_settings.sql)
after the identity migration.

## Idea Scout runs

Apply migration [`0004_idea_scout.sql`](./src/server/migrations/0004_idea_scout.sql)
after the earlier migrations. Owners, admins, and editors can submit
`POST /v1/workspaces/:id/idea-runs` with an `Idempotency-Key` header and JSON
`{"provider":"openai"}` (or another catalogued provider). Active members can
read `GET /v1/idea-runs/:id`. Enable `idea_discovery` in the workspace policy;
the stop switch and suspended workspace block new runs. The selected provider
must have a stored, verified credential and selected text-generation model.
The response records the policy and provider/model snapshot and a typed blocker;
it never includes credentials. The same key and request return the original run;
a changed request returns `idempotency_conflict`. After correcting a blocker,
submit a new key to create a new attempt.

No external trend source or Idea Scout generation adapter is implemented yet.
Even a verified provider therefore produces `trend_source_unavailable`, no
ideas, and null usage and cost. No provider call or spend occurs in this slice.
Real evidence collection, generation, and provider-reported usage are required
before runs can succeed; no trends or candidates are synthesized.

### Real-footage production boundary

`POST /v1/ideas/{idea_id}/approve-brief` accepts `{ "content": "..." }` from
an active workspace editor, admin, or owner. It requires an evidence-backed
candidate from a successful Idea Scout run and records an immutable approval.
`POST /v1/workspaces/{workspace_id}/production-jobs` accepts `brief_id`, a
nonempty `asset_ids` array, and `provider`, with an `Idempotency-Key` header.
`GET /v1/production-jobs/{id}` reads a job and its events and cost ledger;
`POST /v1/production-jobs/{id}/cancel` cancels an eligible job. All require
active workspace membership; creation and cancellation require editor access.
A replay of the same key and input returns the same job; different input returns
`idempotency_conflict`.

Production is currently a **blocked boundary**, not a rendering service. It
checks the workspace policy (`production` capability and stop switch), approved
brief, asset scan and licensing, verified workspace provider/model, and a
positive per-job USD ceiling. The immutable estimate is unknown because no real
render adapter or enforceable price bound exists. No billable calls are made,
no usage is invented, and the actual ledger is empty. The job exposes a typed
blocker and an estimate reason. Idea Scout currently cannot create successful
candidates, and the asset scanner is unavailable; these upstream capabilities,
a real renderer, provider credentials, and bounded pricing are required before
production can proceed. See `docs/architecture.md` for the state and cost contract.

### Quality Gate and cost ledger boundary

Apply [`0006_quality_gate.sql`](./src/server/migrations/0006_quality_gate.sql)
after the production migration. `POST /v1/production-jobs/:id/quality-gate`
records an immutable run and requires an `Idempotency-Key`; `GET
/v1/quality-gates/:id` reads the run and decision history; and `POST
/v1/quality-gates/:id/decision` records one immutable reviewer decision.

The run checks real video assets, 0–60 second duration, the 9:16 aspect range,
explicit audio/caption readiness, scan/licensing/rights readiness, and whether
the job is in `rendering` or `awaiting_review`. Findings include evidence
references and no score is returned when a check blocks. A clean deterministic
run still fails closed with `media_inspection_capability_unavailable`: there is
no media inspection adapter in this repository, so no transcript, thumbnail,
AI score, finding, usage, or approval is fabricated. Provider handoff requires
the workspace's encrypted, live-verified credential and selected vision model.
Production completion is protected by the migration trigger requiring a passed
quality gate; the existing immutable cost ledger and unknown-cost blocker remain
unchanged, so no billable AI call can bypass the ceiling.

## Publishing adapters

Migration [`0007_publishing.sql`](./src/server/migrations/0007_publishing.sql)
adds workspace-scoped YouTube and Instagram OAuth connections and durable
publish requests. OAuth state and nonce values are one-time, hashed in D1, and
expire after ten minutes. Access and refresh tokens use the same AES-GCM
`CREDENTIAL_ENCRYPTION_KEY` mechanism as AI credentials; tokens, ciphertext,
authorization headers, and client secrets are never returned or logged.

Configure platform credentials as dedicated runtime bindings, never as AI
settings: `YOUTUBE_CLIENT_ID`, `YOUTUBE_CLIENT_SECRET`, `INSTAGRAM_CLIENT_ID`,
`INSTAGRAM_CLIENT_SECRET`, and `PUBLIC_BASE_URL`. OAuth is started with
`POST /v1/workspaces/:id/publishing-connections/oauth`, connections are listed
with `GET /v1/workspaces/:id/publishing-connections`, and revoked with
`POST /v1/publishing-connections/:id/revoke`.

`POST /v1/workspaces/:id/publish-requests` requires a completed production job,
a passed and reviewer-approved quality gate, a ready/clean/licensed real-footage
asset, a permitted publishing policy, an active connection with required
scopes, an idempotency key, and platform-valid metadata. Metadata is rejected
when it exceeds official limits: YouTube title 100 characters, description
5000, Shorts duration at most 60 seconds; Instagram Reels caption 2200 and
duration at most 90 seconds. Nothing is silently truncated.

`POST /v1/publish-requests/:id/attempt` is the durable worker boundary. Due
transient failures move to `retry_scheduled` with capped exponential backoff;
platform rejection and capability blockers are persisted as failed/blocked.
The YouTube adapter uses the official resumable upload API and creates a post
record only after the API returns a real video ID. Instagram currently remains
blocked with `media_upload_unavailable`: Instagram Graph publishing requires a
publicly reachable media URL, while this slice deliberately keeps source media
private in R2 and has no configured official media-delivery capability. No
placeholder connection, upload ID, URL, success, or analytics is created.
