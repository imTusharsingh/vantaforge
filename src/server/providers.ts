export type ProviderStatus = "configured" | "unconfigured" | "unverified" | "unsupported";

export interface ProviderModel { id: string; label: string; capabilities: string[]; }
export interface ProviderVerification { verified: boolean; status: "verified" | "invalid" | "unavailable" | "unsupported"; code?: "credential_invalid" | "provider_unavailable" | "provider_unverified"; }
export interface ProviderDefinition {
  id: string;
  name: string;
  credential_kind: "api_key";
  models: ProviderModel[];
  verify: ((credential: string) => Promise<ProviderVerification>) | null;
}

const openAiModels: ProviderModel[] = [
  { id: "gpt-4o-mini", label: "GPT-4o mini", capabilities: ["text_generation"] },
  { id: "gpt-4o", label: "GPT-4o", capabilities: ["text_generation", "vision"] },
  { id: "gpt-4.1-mini", label: "GPT-4.1 mini", capabilities: ["text_generation", "vision"] },
];

// A model must be listed here before a workspace can select it.
export const PROVIDERS: ProviderDefinition[] = [
  { id: "openai", name: "OpenAI", credential_kind: "api_key", models: openAiModels, verify: verifyOpenAi },
  { id: "anthropic", name: "Anthropic", credential_kind: "api_key", models: [{ id: "claude-3-5-sonnet-latest", label: "Claude 3.5 Sonnet", capabilities: ["text_generation", "vision"] }], verify: null },
];

export function providerDefinition(id: string): ProviderDefinition | undefined { return PROVIDERS.find((provider) => provider.id === id); }
export function modelDefinition(provider: ProviderDefinition, model: string): ProviderModel | undefined { return provider.models.find((candidate) => candidate.id === model); }

async function verifyOpenAi(apiKey: string): Promise<ProviderVerification> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch("https://api.openai.com/v1/models", { method: "GET", headers: { authorization: `Bearer ${apiKey}` }, signal: controller.signal });
    if (response.ok) return { verified: true, status: "verified" };
    if (response.status === 401 || response.status === 403) return { verified: false, status: "invalid", code: "credential_invalid" };
    return { verified: false, status: "unavailable", code: "provider_unavailable" };
  } catch { return { verified: false, status: "unavailable", code: "provider_unavailable" }; }
  finally { clearTimeout(timeout); }
}
