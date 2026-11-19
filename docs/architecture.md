# VantaForge architecture contract

## Operating rule

VantaForge never fabricates AI output, analytics, renders, upload results, or publishing success. If a required user-owned key, OAuth connection, provider capability, or asset is missing, the job enters `blocked` with an actionable warning. There is no mock-provider fallback in production.

## Bounded contexts

| Context | Responsibility | Hard dependencies |
| --- | --- | --- |
| Identity | Accounts, sessions, workspace membership and roles | Auth provider |
| Creative | Workspace brief, brand rules, catalog assets, private uploads and licensing metadata | Object storage |
| Idea Scout | Topics, trends, channel gaps, ranked briefs | User AI key; trend/search provider |
| Production | Script, shot plan, real footage, voice, captions and render | User AI key; footage/voice/render providers |
| Quality Gate | Safety, factuality, brand fit, pacing, audio, platform compliance and cost | Render artifact; review model key |
| Publishing | Platform connections, schedules, idempotent upload and status | YouTube/Instagram OAuth |
| Growth Analyst | Metrics, retention patterns, experiments and next-idea ranking | Analytics OAuth; user AI key |
| Provider Settings | Encrypted user keys, model allowlist, capability checks and spend policy | Key vault / encryption boundary |

## Job lifecycle

`draft → queued → running → review → approved → scheduled → publishing → published`; any stage can become `blocked`, `failed` (retryable or terminal), or `cancelled`.

Every job stores `workspace_id`, `policy_snapshot`, `provider_snapshot`, `cost_budget`, `actual_cost`, and an append-only audit log. Publishing requires quality pass, cost pass, a valid destination connection, and an automation policy that permits it.

## Provider gate

Before every provider call, resolve a capability such as `text.generate`, `video.render`, `voice.synthesize`, `youtube.upload`, or `instagram.publish`. Verify the user key/OAuth connection, supported model access, capability, and estimated cost. Failures create a typed `ProviderBlocked` record with `provider`, `capability`, `reason_code`, `action_url`, and timestamp. The UI shows a warning and setup action; it never shows a successful preview or placeholder result.

## API boundaries

- `POST/GET /v1/workspaces` — workspace policy and membership.
- `POST /v1/assets` and `/complete` — private upload intent and verification.
- `POST /v1/ideas/scout`, `GET /v1/ideas` — Idea Scout jobs and ranked briefs.
- `POST /v1/shorts`, `GET /v1/jobs/:id` — production jobs, blockers, costs, and artifacts.
- `POST /v1/reviews/:job_id/approve|request-changes` — human quality decisions.
- `POST /v1/connections/:platform/oauth/start|callback` — scoped platform access.
- `POST/DELETE /v1/publishing/schedules` — idempotent scheduling and cancellation.
- `POST /v1/analytics/sync` — analytics import only with valid OAuth.
- `GET/PUT /v1/settings/providers` — encrypted key references and model selection; raw keys are write-only.

## Security and automation invariants

Uploads and generated assets are private by default and scoped by `workspace_id`. Keys and refresh tokens are encrypted at rest and decrypted only at the provider boundary. Correlation IDs, cost events, and idempotency keys protect auditability and retries. Disabling automation cancels queued work and prevents new publishing. “After N shorts” is evaluated before enqueueing the next job.
