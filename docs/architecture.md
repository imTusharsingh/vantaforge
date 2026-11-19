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

### AI settings

```text
AIProviderConnection { id, workspace_id, provider, credential_kind,
  encrypted_secret_ref, configured_capabilities, model_allowlist,
  quota_policy, status, last_verified_at, last_error_code }
ProviderCapability { provider, capability, model, region, availability,
  credential_requirements, limits }
ProviderSnapshot { connections, selected_models, capabilities, captured_at }
```

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
| Assets | `POST /v1/workspaces/{id}/assets/uploads`; `POST /v1/assets/{id}/scan`; `GET /v1/workspaces/{id}/assets` | Storage, scanning, licensing, readiness |
| Idea Scout | `POST /v1/workspaces/{id}/idea-runs`; `GET /v1/idea-runs/{id}`; `POST /v1/ideas/{id}/approve`; `POST /v1/briefs` | Evidence-backed candidates and approved briefs |
| Production | `POST /v1/workspaces/{id}/production-jobs`; `GET /v1/production-jobs/{id}`; `POST /v1/production-jobs/{id}/cancel` | Plan, render, cost ledger, job state |
| Quality Gate | `POST /v1/production-jobs/{id}/quality-gate`; `GET /v1/quality-gates/{id}`; `POST /v1/quality-gates/{id}/decision` | Checks, findings, policy/human decision |
| Publishing | `POST /v1/workspaces/{id}/connections`; `POST /v1/publish-requests`; `POST /v1/publish-requests/{id}/cancel` | Verified connections and idempotent side effects |
| Analytics | `POST /v1/published-posts/{id}/analytics-sync`; `GET /v1/workspaces/{id}/analytics`; `POST /v1/experiment-suggestions` | Provider snapshots and evidence-based suggestions |
| AI settings | `GET /v1/workspaces/{id}/ai-providers`; `PUT /v1/ai-providers/{id}/credentials`; `POST /v1/ai-providers/{id}/verify`; `PATCH /v1/ai-providers/{id}/models` | Encrypted credentials and capability/model allowlist |

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
