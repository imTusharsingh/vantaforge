export function ideaScoutBlocker(input: { active: boolean; stopped: boolean; enabled: unknown; credential: boolean; verified: boolean; modelSupported: boolean }): string {
  if (!input.active || input.stopped || !Array.isArray(input.enabled) || !input.enabled.includes("idea_discovery")) return "policy_blocked";
  if (!input.credential) return "credential_required";
  if (!input.verified) return "connection_not_verified";
  if (!input.modelSupported) return "model_not_selected";
  return "trend_source_unavailable";
}
