export type ProductionState = 'planning' | 'provider_preparation' | 'rendering' | 'awaiting_review' | 'completed' | 'failed' | 'cancelled' | 'blocked';
const transitions: Record<ProductionState, ProductionState[]> = {
  planning: ['provider_preparation', 'blocked', 'failed', 'cancelled'],
  provider_preparation: ['rendering', 'blocked', 'failed', 'cancelled'],
  rendering: ['awaiting_review', 'blocked', 'failed', 'cancelled'],
  awaiting_review: ['completed', 'failed', 'cancelled', 'blocked'],
  blocked: ['cancelled'], completed: [], failed: [], cancelled: [],
};
export function canTransition(from: ProductionState, to: ProductionState): boolean { return transitions[from]?.includes(to) ?? false; }
// USD policy values must be exactly representable in integer millionths.
export function ceilingMicros(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return null;
  const micros = value * 1_000_000;
  return Number.isSafeInteger(micros) ? micros : null;
}
export function costBlocker(ceiling: number | null, estimate: number | null, spent = 0): string | null {
  if (ceiling === null || !Number.isSafeInteger(ceiling) || ceiling <= 0) return 'cost_ceiling_required';
  if (!Number.isSafeInteger(spent) || spent < 0 || estimate === null || !Number.isSafeInteger(estimate) || estimate < 0) return 'cost_estimate_unavailable';
  return spent + estimate > ceiling || !Number.isSafeInteger(spent + estimate) ? 'cost_ceiling_exceeded' : null;
}
