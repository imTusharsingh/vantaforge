export function unwrapData(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.results)) return value.results;
  return value;
}

export function normalizeWorkspaces(value) {
  const rows = unwrapData(value);
  return Array.isArray(rows) ? rows : [];
}

export function normalizeAssets(value) {
  const rows = unwrapData(value);
  return Array.isArray(rows) ? rows.map((asset) => ({
    ...asset,
    licensing: asset.licensing && typeof asset.licensing === "object" ? asset.licensing : {},
  })) : [];
}

export function normalizePolicy(value) {
  if (!value || typeof value !== "object") return value;
  let enabled = value.enabled_capabilities;
  if (typeof enabled === "string") {
    try { enabled = JSON.parse(enabled); } catch { enabled = null; }
  }
  return { ...value, enabled_capabilities: Array.isArray(enabled) ? enabled : [] };
}

export function resourceState(status, data = null, error = null) {
  return { status, data, error };
}

export function resourceError(error) {
  return resourceState("error", null, error instanceof Error ? error.message : String(error));
}

export function resourceValue(resource, fallback = null) {
  return resource?.status === "ready" ? resource.data : fallback;
}
