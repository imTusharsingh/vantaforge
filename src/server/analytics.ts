export type AnalyticsPlatform = "youtube" | "instagram";

export type AnalyticsBlocker =
  | "policy_blocked" | "connection_required" | "connection_expired"
  | "connection_revoked" | "scope_missing" | "credential_required"
  | "credential_unavailable" | "platform_api_unavailable" | "rate_limited"
  | "data_unavailable" | "ai_capability_unavailable" | "ai_provider_unverified"
  | "ai_model_not_selected";

export interface NormalizedMetric {
  platform: AnalyticsPlatform;
  account_id: string;
  content_id: string | null;
  metric: string;
  value: number;
  observed_at: string;
  source_ref: string;
}

export function analyticsBlocker(input: {
  active: boolean; stopped: boolean; enabled: unknown; connected: boolean;
  expired: boolean; revoked: boolean; credential: boolean; scopes: string[];
  requiredScopes: string[]; hasData?: boolean;
}): AnalyticsBlocker | null {
  if (!input.active || input.stopped || !Array.isArray(input.enabled) || !input.enabled.includes("analytics")) return "policy_blocked";
  if (!input.connected) return "connection_required";
  if (input.revoked) return "connection_revoked";
  if (input.expired) return "connection_expired";
  if (!input.credential) return "credential_required";
  if (!input.requiredScopes.every((scope) => input.scopes.includes(scope))) return "scope_missing";
  if (input.hasData === false) return "data_unavailable";
  return null;
}

function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return value;
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value)) && Number(value) >= 0) return Number(value);
  return null;
}

export function normalizeYouTubeRows(rows: unknown[], accountId: string, observedAt: string, sourceRef: string): NormalizedMetric[] {
  const result: NormalizedMetric[] = [];
  for (const row of rows) {
    if (!Array.isArray(row) || typeof row[0] !== "string") continue;
    const contentId = row[0];
    const names = ["views", "likes", "comments", "shares", "estimated_minutes_watched", "average_view_duration", "average_view_percentage", "subscribers_gained"];
    names.forEach((metric, index) => { const value = numberValue(row[index + 1]); if (value !== null) result.push({ platform: "youtube", account_id: accountId, content_id: contentId, metric, value, observed_at: observedAt, source_ref: sourceRef }); });
  }
  return result;
}

export function normalizeInstagramMetrics(values: unknown[], accountId: string, observedAt: string, sourceRef: string): NormalizedMetric[] {
  const result: NormalizedMetric[] = [];
  for (const item of values) {
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    const metric = typeof record.name === "string" ? record.name : null;
    const candidates = Array.isArray(record.values) ? record.values : [record];
    for (const candidate of candidates) {
      const value = numberValue((candidate as Record<string, unknown>).value ?? (record.total_value as Record<string, unknown> | undefined)?.value ?? record.value);
      const observed = typeof (candidate as Record<string, unknown>).end_time === "string" ? String((candidate as Record<string, unknown>).end_time) : observedAt;
      if (metric && value !== null) result.push({ platform: "instagram", account_id: accountId, content_id: null, metric, value, observed_at: observed, source_ref: sourceRef });
    }
  }
  return result;
}

export function suggestionEvidence(metrics: Array<Pick<NormalizedMetric, "metric" | "value" | "content_id" | "observed_at" | "source_ref">>): boolean {
  return metrics.length > 0 && metrics.every((metric) => Number.isFinite(metric.value) && metric.source_ref.length > 0 && metric.observed_at.length > 0);
}
