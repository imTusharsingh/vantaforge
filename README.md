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
- **AI provider settings**: user-owned API keys stored encrypted, model allowlist, capability checks, warning states, quotas, and fallback behavior. No server-side AI key is assumed.

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
