/**
 * Provider boundary for real-footage production.
 *
 * This module intentionally has no built-in adapter. A provider can only be
 * added when its API, user credential flow, pricing, and inspection evidence
 * are implemented. An empty registry is a supported, explicit state; callers
 * must persist provider_unavailable rather than manufacture a render.
 */
export const REAL_FOOTAGE_CAPABILITIES = [
  "source_ingest",
  "edit_render",
  "captions",
  "voiceover",
  "output_inspection",
] as const;

export type RealFootageCapability = typeof REAL_FOOTAGE_CAPABILITIES[number];
export type CapabilityStatus = "available" | "unavailable";

export type CapabilitySnapshot = {
  provider: string;
  capability: RealFootageCapability;
  status: CapabilityStatus;
  blocker_code: string | null;
  checked_at: string;
};

export type RenderEstimate = {
  amount_microusd: number;
  basis: string;
};

export type RenderRequest = {
  workspace_id: string;
  job_id: string;
  source_asset_ids: string[];
  model: string | null;
};

export type RenderResult = {
  provider_job_id: string;
  output_storage_key: string;
  output_metadata: Record<string, unknown>;
  actual_microusd: number;
};

export interface RealFootageRenderAdapter {
  provider: string;
  capabilities: readonly RealFootageCapability[];
  estimate(request: RenderRequest): Promise<RenderEstimate | null>;
  render(request: RenderRequest): Promise<RenderResult>;
  inspect(output: RenderResult): Promise<Record<string, unknown>>;
}

// No supported provider currently exposes a real-footage render API in the
// catalog. Do not populate this with a mock, local renderer, or placeholder.
export const REAL_FOOTAGE_RENDER_ADAPTERS: readonly RealFootageRenderAdapter[] = [];

export function renderAdapterFor(provider: string): RealFootageRenderAdapter | undefined {
  return REAL_FOOTAGE_RENDER_ADAPTERS.find((adapter) => adapter.provider === provider);
}

export function capabilitySnapshots(provider: string, checkedAt: string): CapabilitySnapshot[] {
  const adapter = renderAdapterFor(provider);
  return REAL_FOOTAGE_CAPABILITIES.map((capability) => ({
    provider,
    capability,
    status: adapter?.capabilities.includes(capability) ? "available" : "unavailable",
    blocker_code: adapter?.capabilities.includes(capability) ? null : "provider_unavailable",
    checked_at: checkedAt,
  }));
}

export type MediaMetadataRole = "source" | "output";
export type MediaMetadataFinding = { code: string; field: string };

/** Only provider/scanner evidence can make these fields true. */
export function validateMediaMetadata(metadata: unknown, role: MediaMetadataRole, expectedStorageKey?: string): MediaMetadataFinding[] {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return [{ code: "metadata_unavailable", field: "metadata" }];
  const value = metadata as Record<string, unknown>;
  const findings: MediaMetadataFinding[] = [];
  const requiredStrings = ["container", "video_codec", "storage_key"];
  for (const field of requiredStrings) if (typeof value[field] !== "string" || !value[field]) findings.push({ code: `${field}_unavailable`, field });
  if (expectedStorageKey && value.storage_key !== expectedStorageKey) findings.push({ code: "storage_identity_mismatch", field: "storage_key" });
  if (typeof value.duration_seconds !== "number" || !Number.isFinite(value.duration_seconds) || value.duration_seconds <= 0) findings.push({ code: "duration_unavailable", field: "duration_seconds" });
  if (!Number.isInteger(value.width) || !Number.isInteger(value.height) || Number(value.width) < 1 || Number(value.height) < 1) findings.push({ code: "dimensions_unavailable", field: "width,height" });
  else if (Math.abs(Number(value.width) / Number(value.height) - 9 / 16) > 0.02) findings.push({ code: "aspect_ratio_invalid", field: "width,height" });
  if (typeof value.frame_rate !== "number" || !Number.isFinite(value.frame_rate) || value.frame_rate <= 0) findings.push({ code: "frame_rate_unavailable", field: "frame_rate" });
  if (value.audio_present !== true) findings.push({ code: "audio_unavailable", field: "audio_present" });
  if (value.integrity_verified !== true) findings.push({ code: "integrity_unverified", field: "integrity_verified" });
  if (role === "output" && value.captions_present !== true) findings.push({ code: "captions_unavailable", field: "captions_present" });
  return findings;
}

export function idempotencyHashInput(request: Pick<RenderRequest, "workspace_id" | "job_id" | "source_asset_ids" | "model">): string {
  return JSON.stringify({ ...request, source_asset_ids: [...request.source_asset_ids].sort() });
}
