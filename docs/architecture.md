# VantaForge backend architecture

This document is the first backend contract. It defines domain models, job
states, provider requirements, error semantics, and API ownership. It is
provider/storage-neutral, but permits no mocks, fixtures, placeholder media,
synthetic analytics, fake provider responses, or silent local fallbacks.

## Invariants

- Every resource is workspace-owned and authorized through an active membership.
- IDs are opaque UUIDs; timestamps are UTC ISO-8601; APIs are authenticated
  HTTPS JSON and return a `request_id`.
- External side effects are asynchronous, audited, idempotent, and cannot
  report success until the side effect actually succeeds.
- Missing, invalid, expired, unauthorized, or insufficiently scoped credentials
  are hard blockers, never optional warnings or mock fallbacks.
- Secrets are encrypted at rest, write-only through APIs, redacted from logs
  and responses, and decrypted only at the provider adapter boundary.
- Retries re-run validation and policy gates and preserve the idempotency key.

Responses use `{ data, request_id }` or `{ error: { code, message, details }, request_id }`.
Collections are cursor-paginated and always workspace-scoped.

## Domain models

```text
User { id, email, display_name, status, created_at, last_seen_at }
Workspace { id, name, slug, owner_user_id, status, timezone, created_at }
Membership { id, workspace_id, user_id, role, status, invited_at, joined_at }
AutomationPolicy { workspace_id, mode, enabled_capabilities, review_mode,
  daily_spend_limit, per_job_cost_limit, stop_switch, version }
AuditEvent { id, workspace_id, actor_type, actor_id, action, resource_type,
  resource_id, request_id, metadata, occurred_at }
WorkspaceBrief { id, workspace_id, objective, audience, regions, languages,
  brand_rules, prohibited_claims, required_disclosures, platform_targets,
  default_duration_seconds, status, version }
BrandProfile { id, workspace_id, voice, visual_rules, caption_rules,
  approved_fonts, approved_colors, prohibited_patterns, version }
CostPolicy { workspace_id, currency, daily_limit, per_job_limit,
  provider_limits, approval_thresholds, version }
```

Roles are `owner`, `admin`, `editor`, `reviewer`, and `viewer`. Owners/admins
manage members, credentials, policy, and publishing connections. Editors run
creative work; reviewers decide quality gates; viewers are read-only.

### Assets

```text
Asset { id, workspace_id, kind, storage_key, media_type, checksum, bytes,
  duration_seconds, dimensions, licensing, metadata, scan_status, status }
AssetReference { id, asset_id, source, source_url, license_id, expires_at,
  attribution_required, usage_scope }
AssetCollection { id, workspace_id, name, asset_ids, status }
```

Assets become usable only after upload, checksum verification, malware scan,
metadata extraction, and licensing checks. Private storage keys are never
returned; downloads use short-lived authorized URLs.

The implemented asset boundary uses an R2 binding named `ASSETS` and D1
migration `0003_assets.sql`. Upload intents persist a hashed, expiring token and
return only an opaque Worker upload URL. The Worker verifies video media type
and byte count, hashes uploaded bytes, and requires the same checksum plus a
positive duration and licensing/rights metadata on completion. List/get routes
expose metadata and references only; the download route authorizes active
membership and streams the private object without revealing its key.

`scan_status`, `licensing_status`, and overall `status` are explicit state
fields. No malware scanner is configured in this slice, so completion sets
`scan_status=unavailable`, `status=blocked`, and
`blocked_reason=malware_scanner_unavailable`. The asset cannot become ready or
downloadable until a real scanner integration changes that state.

### Idea Scout

```text
IdeaScoutRun { id, workspace_id, status, source_set, policy_snapshot,
  provider_snapshot, started_at, completed_at, error }
IdeaCandidate { id, run_id, workspace_id, title, premise, audience,
  evidence, trend_signals, channel_gap, risk_flags, score, status }
ContentBrief { id, workspace_id, idea_id, hook, promise, outline,
  platform_targets, factual_claims, source_urls, approval_status, version }
```

Factual claims require evidence and source URLs. A brief must be approved under
workspace policy before production.

### Production and quality

```text
ProductionPlan { id, workspace_id, brief_id, script, shot_list,
  asset_requirements, narration, captions, platform_variants, status, version }
ProductionJob { id, workspace_id, plan_id, job_type, policy_snapshot,
  provider_snapshot, cost_budget, idempotency_key, status, attempts,
  output_asset_ids, cost_ledger_id, error }
RenderOutput { id, production_job_id, asset_id, platform, technical_checks,
  duration_seconds, status }
CostLedger { id, workspace_id, job_id, currency, reserved, actual,
  line_items, status }
QualityGate { id, workspace_id, production_job_id, checks, score,
  blocking_findings, warning_findings, decision, reviewer_id, decided_at }
QualityCheck { name, status, severity, evidence, provider, checked_at }
```

Quality covers safety, factuality, brand fit, hook/pacing, audio/visual
quality, licensing, cost policy, and platform compliance. A blocking finding or
missing required check blocks the job.

### Publishing and analytics

```text
PublishingConnection { id, workspace_id, platform, account_id, scopes,
  credential_status, expires_at, last_verified_at }
PublishRequest { id, workspace_id, render_output_id, connection_id,
  scheduled_for, idempotency_key, platform_payload_hash, status, error }
PublishedPost { id, workspace_id, publish_request_id, platform,
  platform_post_id, url, published_at, status }
AnalyticsSnapshot { id, workspace_id, published_post_id, captured_at, window,
  impressions, views, watch_time, retention, likes, comments, shares, saves,
  subscribers, raw_provider_reference }
ExperimentSuggestion { id, workspace_id, evidence_snapshot_ids, hypothesis,
  proposed_change, expected_signal, status }
```

Analytics are provider-reported observations. Missing permission or an
unavailable platform API is an integration warning/error, never synthetic data.

The implemented analytics slice stores a durable `analytics_runs` record with
the requested fetch window, policy/provider snapshots, status and blocker;
`analytics_provider_snapshots`, `analytics_source_refs`, and
`analytics_metrics` preserve the account context, official endpoint attribution
and normalized values. YouTube Analytics and Instagram Insights are fetched
only through the encrypted publishing connection. The OAuth flow requests the
additional analytics scopes, while older connections fail closed with
`scope_missing`. Rate limits, unavailable APIs, missing data and expired or
revoked connections are persisted explicitly. `analytics_suggestions` is an
evidence-bound contract: it can call only a verified, selected user AI model
with persisted metrics, and otherwise records a blocker without content.

### AI settings

```text
AIProviderConnection { id, workspace_id, provider, credential_kind,
  encrypted_secret_ref, configured_capabilities, model_allowlist,
  quota_policy, status, last_verified_at, last_error_code }
ProviderCapability { provider, capability, model, region, availability,
  credential_requirements, limits }
ProviderSnapshot { connections, selected_models, capabilities, captured_at }
```

The first settings implementation persists one connection per provider and
workspace in `ai_provider_connections`. The `encrypted_secret` column contains
only AES-GCM output (a random 12-byte IV followed by ciphertext and tag). The
AES key comes from the dedicated `CREDENTIAL_ENCRYPTION_KEY` runtime secret
binding; no provider key is read from an environment variable. Invalid or
missing encryption configuration is a typed hard error.

The allowlist currently contains OpenAI (`gpt-4o-mini`, `gpt-4o`, and
`gpt-4.1-mini`) and Anthropic (`claude-3-5-sonnet-latest`). OpenAI is the only
provider with a live adapter in this slice and is verified with its models
endpoint. Anthropic remains explicitly unverified until a real adapter exists;
the Worker never fabricates a verification result. A connection cannot select
a model until it is verified.

Credential kinds are provider-specific: user API key, OAuth access/refresh
token, or workload identity. Each adapter declares required credential type,
scopes, models, regions, payload limits, timeout, and retry policy. A
connection is selectable only after live verification.

## Job states

```text
queued -> validating -> waiting_for_credentials -> running -> awaiting_review
  |           |                  |                |              |
cancelled  blocked            blocked           failed       rejected
                                                   |              |
                                                cancelled      approved -> running
```

`waiting_for_credentials` and `blocked` require user/operator action; they are
not silent retries. `failed` means an attempted operation did not complete and
is retryable only when its error says so. `cancelled`, `failed`, `succeeded`,
and `rejected` are terminal for that attempt. Every transition records actor,
reason code, and request ID.

Production requires verified credentials, approved inputs, reserved budget,
and immutable provider/policy snapshots. Publishing additionally requires a
passed quality gate, passed cost gate, and a verified platform connection. A
timed-out publish looks up its idempotency key before retrying.

## Provider boundary and credential hard blockers

The resolver checks credential existence, decryption and live verification,
expiry/authorization/scopes, then model/region/quota/payload/cost eligibility.
Failures map to `CREDENTIAL_REQUIRED`, `CREDENTIAL_INVALID`,
`CREDENTIAL_EXPIRED`, `CREDENTIAL_SCOPE_MISSING`, `PROVIDER_UNAVAILABLE`, or
`CAPABILITY_UNSUPPORTED`.

Application code depends only on these adapter interfaces:

```text
verify(connection) -> VerificationResult
discover(request, provider_snapshot) -> DiscoveryResult
generate(request, provider_snapshot) -> GeneratedOutput
transcribe(request, provider_snapshot) -> Transcript
moderate(request, provider_snapshot) -> ModerationResult
render(request, provider_snapshot) -> RenderResult
publish(request, provider_snapshot) -> PublishResult
fetch_analytics(request, provider_snapshot) -> AnalyticsResult
```

Adapters translate provider errors and never fabricate domain data. No server
AI key is assumed. Missing keys/credentials leave a job in
`waiting_for_credentials` or `blocked` and return a hard error.

## Errors and warnings

The API exposes stable `code`, `message`, `retryable`, `severity`, and safe
`details`. Hard errors/blockers are:

```text
AUTH_REQUIRED, FORBIDDEN, WORKSPACE_SUSPENDED,
CREDENTIAL_REQUIRED, CREDENTIAL_INVALID, CREDENTIAL_EXPIRED,
CREDENTIAL_SCOPE_MISSING, CAPABILITY_UNSUPPORTED, PROVIDER_UNAVAILABLE,
INPUT_MISSING, ASSET_NOT_READY, LICENSE_INVALID, SOURCE_EVIDENCE_MISSING,
POLICY_BLOCKED, BUDGET_EXCEEDED, QUALITY_GATE_BLOCKED,
CONNECTION_NOT_VERIFIED, PLATFORM_REJECTED, IDEMPOTENCY_CONFLICT
```

Non-blocking warnings, only where policy permits continuation, are:

```text
PROVIDER_RATE_LIMITED, PROVIDER_DEGRADED, QUOTA_NEAR_LIMIT,
ANALYTICS_DELAYED, OPTIONAL_CHECK_UNAVAILABLE, LOW_CONFIDENCE,
SOURCE_STALE, LICENSE_EXPIRING, RETRY_SCHEDULED
```

Warnings remain visible on the resource and audit trail. An optional-check
warning cannot replace a check configured as required.

## API boundaries

These are ownership boundaries, not necessarily separate deployments. Each
owns authorization, validation, persistence, and events. Cross-boundary calls
use IDs and immutable snapshots, never shared provider secrets.

| Boundary | Example endpoints | Contract |
| --- | --- | --- |
| Identity/workspaces | `GET /v1/me`; `POST /v1/workspaces`; `GET /v1/workspaces/{id}/members`; `PATCH /v1/workspaces/{id}/automation-policy` | Membership, roles, policy, audit |
| Assets | `POST /v1/workspaces/{id}/assets/uploads`; `PUT /v1/assets/uploads/{id}/content`; `POST /v1/assets/{id}/complete`; `GET /v1/workspaces/{id}/assets`; `GET /v1/assets/{id}`; `GET /v1/assets/{id}/download` | Private R2 storage, scanning state, licensing, readiness |
| Idea Scout | `POST /v1/workspaces/{id}/idea-runs`; `GET /v1/idea-runs/{id}`; `POST /v1/ideas/{id}/approve`; `POST /v1/briefs` | Evidence-backed candidates and approved briefs |
| Production | `POST /v1/workspaces/{id}/production-jobs`; `GET /v1/production-jobs/{id}`; `POST /v1/production-jobs/{id}/cancel` | Plan, render, cost ledger, job state |
| Quality Gate | `POST /v1/production-jobs/{id}/quality-gate`; `GET /v1/quality-gates/{id}`; `POST /v1/quality-gates/{id}/decision` | Checks, findings, policy/human decision |
| Publishing | `POST /v1/workspaces/{id}/connections`; `POST /v1/publish-requests`; `POST /v1/publish-requests/{id}/cancel` | Verified connections and idempotent side effects |
| Analytics | `POST /v1/workspaces/{id}/analytics-runs`; `GET /v1/analytics-runs/{id}`; `GET /v1/workspaces/{id}/analytics`; `POST /v1/workspaces/{id}/experiment-suggestions` | Provider snapshots, normalized evidence and fail-closed suggestions |
| AI settings | `GET /v1/workspaces/{id}/ai-providers`; `GET /v1/workspaces/{id}/ai-providers/models`; `PUT|DELETE /v1/workspaces/{id}/ai-providers/{provider}/credentials`; `POST /v1/workspaces/{id}/ai-providers/{provider}/verify`; `PATCH /v1/workspaces/{id}/ai-providers/{provider}/models` | Encrypted credentials and capability/model allowlist |

Mutations creating jobs, credentials, connections, or platform effects require
`Idempotency-Key`. Job endpoints expose status and permitted cancellation, not
queue internals or secret payloads.

## Events and first implementation slice

Use a transactional outbox so events are durable before publication. Events
include `event_id`, `workspace_id`, `resource_id`, `occurred_at`, `request_id`,
and `version`. Minimum events: `credential.verified`, `credential.blocked`,
`asset.ready`, `idea.brief-approved`, `job.state-changed`,
`quality-gate.decided`, `publish.post-published`, and
`analytics.snapshot-updated`.

Logs/metrics include correlation IDs, job IDs, provider, capability, latency,
retry count, and error code; never credential values, auth headers, private
storage URLs, or unredacted prompts/responses.

The first implementation slice is real persistence for users/workspaces/
memberships, encrypted and verified provider connections, shared jobs and
transitions, idempotency/audit/outbox, policy snapshots, and one real provider
adapter. Until credentials and capability checks pass, return
`CREDENTIAL_REQUIRED` or `CONNECTION_NOT_VERIFIED` and never pretend success.

## Implemented identity slice

`src/server/index.ts` is the initial Cloudflare Worker boundary. D1 migration
`src/server/migrations/0001_identity.sql` persists users, sessions, workspaces,
memberships, and automation policies. Authentication is provider-independent:
signup and login use Web Crypto PBKDF2-SHA-256, and the session cookie contains
a random token whose digest is persisted in D1.

All workspace reads and writes call the membership authorization check. Only
owners/admins can update workspace settings or patch its policy. Policy updates
validate mode, review mode, and the stop switch, and increment the policy
version. No AI credentials, provider calls, mock records, or synthetic fallback
behavior are part of this module.

## Implemented provider-settings slice

Migration `0002_ai_provider_settings.sql` stores one workspace-scoped provider
connection per provider. `CREDENTIAL_ENCRYPTION_KEY` is a dedicated runtime
secret used only to encrypt/decrypt user credentials with AES-GCM; it is not an
AI provider key and is never returned by the API. Raw keys and ciphertext are
write-only from the application boundary.

The current catalog exposes OpenAI and Anthropic models. OpenAI verification
uses a real `GET /v1/models` request. Catalog entries without a live adapter
return `provider_unverified`; they do not pretend the credential works. Model
selection is allowed only after a connection is verified. Missing keys,
unsupported models, invalid credentials, and missing encryption configuration
produce typed hard errors.

## Implemented Idea Scout boundary

Migration `0004_idea_scout.sql` adds workspace-scoped runs and candidate storage.
`POST /v1/workspaces/:id/idea-runs` accepts a provider and a required
`Idempotency-Key`; `GET /v1/idea-runs/:id` requires active membership. Owners,
admins, and editors can create runs. The policy must enable `idea_discovery`,
the stop switch must be off, and the workspace must be active. Each attempt
persists the policy and selected provider/model snapshot and its terminal
blocker. Workspace/key uniqueness and a request hash make concurrent replays
stable and reject conflicting requests. A corrected configuration requires a
new key and a new attempt. Usage and cost remain null without a provider call.

The repository has no external trend-source integration or Idea Scout generation
adapter. Runs therefore stop at `trend_source_unavailable` after credential,
verification, model, and policy checks; they cannot currently produce ideas.
The candidate table is a persistence boundary for future evidence-backed work,
not a source of seeded records. A real source integration and generation adapter,
including evidence validation and actual usage/cost accounting, are still needed
before discovery can succeed.

## Implemented real-footage production boundary

Migration `0005_production.sql` follows Idea Scout and adds immutable approved
briefs, workspace-scoped production jobs, append-only state events and an
append-only actual-cost ledger. An editor can approve a brief with
`POST /v1/ideas/{id}/approve-brief` and `{content}` only for an evidence-backed
candidate of a successful run in their active workspace. Creation uses
`POST /v1/workspaces/{id}/production-jobs`, `{brief_id, asset_ids, provider}`,
and `Idempotency-Key`; reads use `GET /v1/production-jobs/{id}` and eligible
jobs can be cancelled with `POST /v1/production-jobs/{id}/cancel`. Access is
membership-scoped; mutation requires owner, admin, or editor. Replays with the
same normalized inputs return the existing job; a different request conflicts.

The state graph is `planning -> provider_preparation -> rendering ->
awaiting_review -> completed`, with `blocked`, `failed`, and `cancelled`
branches; terminal states cannot advance, and a blocked attempt can only be
cancelled. This slice records planning and the resulting blocked state
transactionally. There is no worker or endpoint that advances a job to rendering
or claims review/completion. A new attempt requires a new idempotency key and
rechecks the current prerequisites.

The immutable job snapshot records policy, provider/model and verification
time, selected asset IDs, the ceiling in integer USD millionths, and a nullable
estimate with a reason. Missing/invalid ceilings and unknown or excessive
estimates fail closed. There is no supported estimate or billable call in this
slice: `estimate_microusd` is null and `estimate_reason` is
`render_provider_unavailable`; the actual ledger remains empty. Before adding
any provider call, an adapter must provide a binding upper bound, atomically
reserve the full maximum against the ceiling including prior actuals and
concurrent reservations, enforce provider-side limits, and record real usage and
cost. The current cost helper alone is not a reservation mechanism. Never infer
zero cost from an empty ledger or an unknown estimate.

Current hard blockers include unavailable Idea Scout generation and trend
sources, unavailable asset malware scanning, missing/invalid licensing,
workspace policy, missing or unverified user-owned provider credentials/model,
missing ceiling, and unavailable render pricing/provider. No AI credential is
read from configuration or stored in a job snapshot. No output asset, URL,
usage, or price is fabricated.

## Implemented quality-gate boundary

Migration `0006_quality_gate.sql` adds immutable quality-gate runs and decision
history. The run endpoint records deterministic checks for real footage,
duration/aspect, audio/captions, rights/licensing, and production state, with
evidence references and a nullable score. The AI handoff snapshots only the
workspace's encrypted connection status, verified time, and selected model;
missing verified credentials, unsupported capabilities, and the absent media
inspection adapter are typed blockers. No provider call, transcript,
thumbnail, score, finding, usage, or approval is synthesized. A database
trigger prevents a production job from reaching `completed` without a passed
quality gate, while existing immutable cost-ledger and ceiling rules remain in
force.

## Implemented publishing boundary

Migration `0007_publishing.sql` adds one workspace-scoped connection per
platform, one-time hashed OAuth state/nonce records, durable publish requests,
immutable attempt events, and provider post records. Tokens are encrypted with
the existing credential key and are used only at the official adapter boundary.
Publish creation re-checks membership, the automation stop switch and enabled
capability, completed production, passed quality, reviewer approval, asset
readiness/licensing, connection status/expiry/scopes, idempotency, schedule,
and platform metadata limits. Attempts re-check due state and use capped
exponential backoff for transient provider failures.

The YouTube adapter uses the official resumable upload API and persists a post
only after a real provider video ID is returned. Instagram is explicitly
blocked until an official public media delivery capability exists: Graph API
Reels publishing requires a publicly reachable media URL, and the current R2
asset boundary is private. No synthetic connection, upload ID, URL, success, or
analytics is written.
