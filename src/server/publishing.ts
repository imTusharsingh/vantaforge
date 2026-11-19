export type PublishingPlatform = "youtube" | "instagram";

export const ANALYTICS_SCOPES: Record<PublishingPlatform, string[]> = {
  youtube: ["https://www.googleapis.com/auth/yt-analytics.readonly"],
  instagram: ["instagram_manage_insights"],
};

export const PLATFORM_RULES: Record<PublishingPlatform, {
  label: string;
  scopes: string[];
  maxTitle: number;
  maxDescription: number;
  maxDurationSeconds: number;
}> = {
  youtube: { label: "YouTube Shorts", scopes: ["https://www.googleapis.com/auth/youtube.upload", "https://www.googleapis.com/auth/youtube.readonly"], maxTitle: 100, maxDescription: 5000, maxDurationSeconds: 60 },
  instagram: { label: "Instagram Reels", scopes: ["instagram_basic", "instagram_content_publish"], maxTitle: 0, maxDescription: 2200, maxDurationSeconds: 90 },
};

export type PlatformBlocker = "platform_client_not_configured" | "oauth_authorization_required" | "platform_api_unavailable" | "media_upload_unavailable" | "platform_constraints_invalid" | "connection_expired" | "connection_revoked" | "scope_missing" | "platform_rejected";

export function platform(value: unknown): PublishingPlatform {
  if (value !== "youtube" && value !== "instagram") throw new Error("platform must be youtube or instagram");
  return value;
}

export function validatePublishPayload(target: PublishingPlatform, payload: { title?: unknown; description?: unknown; durationSeconds?: unknown }): string[] {
  const rules = PLATFORM_RULES[target];
  const errors: string[] = [];
  if (typeof payload.title !== "string" || payload.title.trim().length === 0) errors.push("title_required");
  else if (rules.maxTitle > 0 && payload.title.length > rules.maxTitle) errors.push("title_too_long");
  if (typeof payload.description !== "string") errors.push("description_required");
  else if (payload.description.length > rules.maxDescription) errors.push("description_too_long");
  if (typeof payload.durationSeconds !== "number" || !Number.isFinite(payload.durationSeconds) || payload.durationSeconds <= 0 || payload.durationSeconds > rules.maxDurationSeconds) errors.push("duration_out_of_range");
  return errors;
}

export function retryDelaySeconds(attempt: number): number {
  if (!Number.isInteger(attempt) || attempt < 1) throw new Error("attempt must be a positive integer");
  return Math.min(6 * 60 * 60, 30 * 2 ** (attempt - 1));
}

export function oauthAuthorizationUrl(platformId: PublishingPlatform, clientId: string, redirectUri: string, state: string, nonce: string): string {
  if (platformId === "youtube") {
    const params = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope: [...PLATFORM_RULES.youtube.scopes, ...ANALYTICS_SCOPES.youtube].join(" "), access_type: "offline", prompt: "consent", state });
    return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
  }
  const params = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope: [...PLATFORM_RULES.instagram.scopes, ...ANALYTICS_SCOPES.instagram].join(","), state, nonce });
  return `https://www.facebook.com/v21.0/dialog/oauth?${params}`;
}

export function publicConnection(row: { id: string; workspace_id: string; platform: string; account_id: string | null; channel_id: string | null; scopes: string; credential_status: string; access_expires_at: string | null; last_verified_at: string | null; last_error_code: string | null; created_at: string; updated_at: string }) {
  return { id: row.id, workspace_id: row.workspace_id, platform: row.platform, account_id: row.account_id, channel_id: row.channel_id, scopes: JSON.parse(row.scopes), credential_status: row.credential_status, access_expires_at: row.access_expires_at, last_verified_at: row.last_verified_at, last_error_code: row.last_error_code, created_at: row.created_at, updated_at: row.updated_at };
}
