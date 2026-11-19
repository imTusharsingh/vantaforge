export type QualitySeverity = "blocking" | "warning";
export type QualityFinding = {
  code: string;
  severity: QualitySeverity;
  message: string;
  evidence_refs: string[];
};

export type QualityAsset = {
  id: string;
  kind: string;
  media_type: string;
  duration_seconds: number | null;
  width: number | null;
  height: number | null;
  metadata: string;
  status: string;
  scan_status: string;
  licensing_status: string;
  rights_confirmed: number;
  license_type: string | null;
};

export type QualityJob = { status: string };

function finding(code: string, message: string, evidence_refs: string[] = []): QualityFinding {
  return { code, severity: "blocking", message, evidence_refs };
}

export function evaluateDeterministicQuality(job: QualityJob, assets: QualityAsset[], nowIso: string): QualityFinding[] {
  const findings: QualityFinding[] = [];
  if (!assets.length) findings.push(finding("real_footage_required", "At least one real-footage asset is required"));
  for (const asset of assets) {
    const ref = [`asset:${asset.id}`];
    if (asset.kind !== "real_footage" || !asset.media_type.startsWith("video/")) findings.push(finding("real_footage_required", "Every production asset must be real video footage", ref));
    if (asset.duration_seconds === null || asset.duration_seconds <= 0 || asset.duration_seconds > 60) findings.push(finding("duration_constraint_failed", "Footage duration must be greater than zero and no longer than 60 seconds", ref));
    if (asset.width === null || asset.height === null) findings.push(finding("aspect_ratio_unavailable", "Video dimensions are required to verify the 9:16 aspect constraint", ref));
    else {
      const ratio = asset.width / asset.height;
      if (ratio < 0.53 || ratio > 0.60) findings.push(finding("aspect_ratio_constraint_failed", "Video aspect ratio must be within the 9:16 short-form range", ref));
    }
    let metadata: Record<string, unknown> = {};
    try { const parsed: unknown = JSON.parse(asset.metadata); if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) metadata = parsed as Record<string, unknown>; } catch { /* malformed metadata is not readiness evidence */ }
    if (metadata.audio_ready !== true) findings.push(finding("audio_readiness_unavailable", "Audio readiness must be explicitly confirmed by a media inspection adapter", ref));
    if (metadata.captions_ready !== true) findings.push(finding("caption_readiness_unavailable", "Caption readiness must be explicitly confirmed by a media inspection adapter", ref));
    if (asset.status !== "ready" || asset.scan_status !== "clean") findings.push(finding("asset_not_production_ready", "The asset is not production eligible until its scan is clean and status is ready", ref));
    if (asset.licensing_status !== "valid" || !asset.rights_confirmed || !asset.license_type) findings.push(finding("rights_or_licensing_not_ready", "Rights confirmation and valid licensing metadata are required", ref));
    // Expiry is checked by the route against asset_references; this evidence marker
    // makes the check explicit without inventing a reference state here.
  }
  if (!['rendering', 'awaiting_review'].includes(job.status)) findings.push(finding("production_state_ineligible", "A quality gate may only review a rendering or awaiting_review production job", [`job:state:${job.status}`]));
  void nowIso;
  return findings;
}

export function qualityScore(findings: QualityFinding[]): number | null {
  return findings.some((item) => item.severity === "blocking") ? null : 100;
}
