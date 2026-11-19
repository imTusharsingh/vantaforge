export const AUTOMATION_STEPS = ['idea_scout', 'production', 'quality', 'publishing'] as const;
export type AutomationStep = typeof AUTOMATION_STEPS[number];
export type RunState = 'queued' | 'running' | 'retry_scheduled' | 'waiting_review' | 'succeeded' | 'blocked' | 'failed' | 'cancelled';

export interface AutomationPolicy {
  mode: unknown;
  enabled_capabilities: unknown;
  review_mode: unknown;
  review_after_count: unknown;
  daily_spend_limit: unknown;
  per_job_cost_limit: unknown;
  stop_switch: unknown;
}

const CAPABILITY: Record<AutomationStep, string> = {
  idea_scout: 'idea_discovery', production: 'production', quality: 'quality', publishing: 'publishing',
};

export function policyBlocker(policy: AutomationPolicy, step: AutomationStep, shortsSinceReview: number, spentTodayMicrousd = 0): string | null {
  if (Boolean(policy.stop_switch)) return 'stop_switch_enabled';
  if (policy.mode !== 'assisted' && policy.mode !== 'autopilot') return 'automation_mode_invalid';
  if (!Array.isArray(policy.enabled_capabilities) || !policy.enabled_capabilities.includes(CAPABILITY[step])) return 'capability_disabled';
  if (typeof policy.daily_spend_limit !== 'number' || !Number.isFinite(policy.daily_spend_limit) || policy.daily_spend_limit <= 0) return 'daily_cost_ceiling_required';
  if (typeof policy.per_job_cost_limit !== 'number' || !Number.isFinite(policy.per_job_cost_limit) || policy.per_job_cost_limit <= 0) return 'job_cost_ceiling_required';
  if (!Number.isSafeInteger(spentTodayMicrousd) || spentTodayMicrousd < 0) return 'daily_cost_unavailable';
  if (spentTodayMicrousd >= Math.round(policy.daily_spend_limit * 1_000_000)) return 'daily_cost_ceiling_exceeded';
  if (policy.mode === 'assisted' && step !== 'idea_scout') return 'assisted_review_required';
  if (step === 'publishing') {
    if (policy.review_mode === 'every_short') return 'review_required';
    if (policy.review_mode === 'after_n_shorts') {
      const threshold = Number(policy.review_after_count);
      if (!Number.isSafeInteger(threshold) || threshold < 1) return 'review_threshold_invalid';
      if (!Number.isSafeInteger(shortsSinceReview) || shortsSinceReview < 0) return 'review_counter_invalid';
      if (shortsSinceReview >= threshold) return 'review_required';
    } else if (policy.review_mode !== 'none') return 'review_mode_invalid';
  }
  return null;
}

export function retryDelaySeconds(attempt: number, entropy = 0): number {
  const capped = Math.min(Math.max(1, attempt), 8);
  return Math.min(3600, 15 * 2 ** (capped - 1)) + Math.max(0, Math.min(14, Math.floor(entropy)));
}

export function canRunStep(previous: RunState | null, state: RunState): boolean {
  if (['succeeded', 'blocked', 'failed', 'cancelled'].includes(state)) return false;
  return previous === null || previous === 'succeeded';
}

export function leaseAvailable(leaseOwner: string | null, leaseExpiresAt: string | null, at: string): boolean {
  return !leaseOwner || !leaseExpiresAt || leaseExpiresAt <= at;
}

export function terminalState(blocker: string): RunState {
  return blocker === 'review_required' || blocker === 'assisted_review_required' ? 'waiting_review' : 'blocked';
}
