import { getTokenPricing } from './pricing';

export type AIProviderId = 'openai' | 'anthropic' | 'google' | 'deepinfra';

export interface ModelMetadata {
  id: string;
  provider: AIProviderId;
  label: string;
  // Short user-facing blurb shown under the model name in the picker. Should
  // help an org owner choose between models without reading the docs.
  description: string;
  contextWindow: number;
  inputPricePer1M: number;
  outputPricePer1M: number;
  // SWE-Bench Verified score (% solved). Use the publicly reported number
  // for the comparable max-effort/thinking-high configuration. Omit when
  // the model doesn't publish a Verified score (nano-tier, pro variants
  // measured only on Pro, etc.).
  sweBenchVerified?: number;
  // ISO date the model was released. Used for ordering the model picker
  // (newest first). Approximate dates are fine — only the relative order
  // matters for display.
  releasedAt: string;
}

const MODELS: ModelMetadata[] = [
  { id: 'gpt-5.5',                        provider: 'openai',    label: 'GPT-5.5',                 description: 'A new class of intelligence for coding and professional work.', contextWindow: 1_000_000,  inputPricePer1M: 5.00,  outputPricePer1M: 30.00,  sweBenchVerified: 82.7, releasedAt: '2026-04-23' },
  { id: 'gpt-5.5-pro',                    provider: 'openai',    label: 'GPT-5.5 Pro',             description: 'Version of GPT-5.5 with smarter, more precise responses.',    contextWindow: 1_000_000,  inputPricePer1M: 30.00, outputPricePer1M: 180.00,                          releasedAt: '2026-04-23' },
  { id: 'moonshotai/Kimi-K2.6',           provider: 'deepinfra', label: 'Kimi K2.6',               description: 'Open-weight agentic coding leader — ties GPT-5.5 on coding.', contextWindow: 256_000,    inputPricePer1M: 0.75,  outputPricePer1M: 3.50,   sweBenchVerified: 80.2, releasedAt: '2026-04-20' },
  { id: 'claude-opus-4-7',                provider: 'anthropic', label: 'Claude Opus 4.7',         description: "Anthropic's flagship — strongest agentic and tool use.",      contextWindow: 200_000,    inputPricePer1M: 5.00,  outputPricePer1M: 25.00,  sweBenchVerified: 82.0, releasedAt: '2026-04-16' },
  { id: 'Qwen/Qwen3.6-35B-A3B',           provider: 'deepinfra', label: 'Qwen3.6 35B A3B',         description: "Alibaba's open-weight MoE — strong coding at low cost.",       contextWindow: 256_000,    inputPricePer1M: 0.15,  outputPricePer1M: 0.95,   sweBenchVerified: 73.4, releasedAt: '2026-04-16' },
  { id: 'gemini-3.1-pro',                 provider: 'google',    label: 'Gemini 3.1 Pro',          description: "Google's flagship — best for huge 2M-token contexts.",        contextWindow: 2_000_000,  inputPricePer1M: 2.00,  outputPricePer1M: 12.00,  sweBenchVerified: 80.6, releasedAt: '2026-04-10' },
  { id: 'gpt-5.4-nano',                   provider: 'openai',    label: 'GPT-5.4 nano',            description: 'Cheapest GPT-5.4-class model — simple high-volume tasks.',    contextWindow: 256_000,    inputPricePer1M: 0.20,  outputPricePer1M: 1.25,                            releasedAt: '2026-03-17' },
  { id: 'gpt-5.4',                        provider: 'openai',    label: 'GPT-5.4',                 description: 'A more affordable model for coding and professional work.',   contextWindow: 256_000,    inputPricePer1M: 2.50,  outputPricePer1M: 15.00,  sweBenchVerified: 80.0, releasedAt: '2026-03-15' },
  { id: 'deepseek-ai/DeepSeek-V4-Pro',    provider: 'deepinfra', label: 'DeepSeek V4 Pro',         description: 'Open-weight flagship — agentic coding, 1M context.',          contextWindow: 1_000_000,  inputPricePer1M: 1.74,  outputPricePer1M: 3.48,   sweBenchVerified: 80.6, releasedAt: '2026-03-10' },
  { id: 'deepseek-ai/DeepSeek-V4-Flash',  provider: 'deepinfra', label: 'DeepSeek V4 Flash',       description: 'Open-weight, fastest and cheapest — quick chat + light tasks.', contextWindow: 128_000, inputPricePer1M: 0.14,  outputPricePer1M: 0.28,   sweBenchVerified: 79.0, releasedAt: '2026-03-01' },
  { id: 'claude-sonnet-4-6',              provider: 'anthropic', label: 'Claude Sonnet 4.6',       description: "Anthropic's balanced pick — best price-to-capability for Aegis.", contextWindow: 1_000_000, inputPricePer1M: 3.00, outputPricePer1M: 15.00,  sweBenchVerified: 79.6, releasedAt: '2026-02-10' },
  { id: 'gemini-3-flash',                 provider: 'google',    label: 'Gemini 3 Flash',          description: "Google's balanced — solid speed/quality tradeoff.",            contextWindow: 1_000_000,  inputPricePer1M: 0.50,  outputPricePer1M: 3.00,   sweBenchVerified: 78.0, releasedAt: '2025-12-01' },
  { id: 'claude-haiku-4-5-20251001',      provider: 'anthropic', label: 'Claude Haiku 4.5',        description: "Anthropic's fast and cheap — simple tasks, low latency.",      contextWindow: 200_000,    inputPricePer1M: 1.00,  outputPricePer1M: 5.00,   sweBenchVerified: 73.3, releasedAt: '2025-10-01' },
  { id: 'gpt-5-nano',                     provider: 'openai',    label: 'GPT-5 nano',              description: 'Fastest, most cost-efficient version of GPT-5.',              contextWindow: 400_000,    inputPricePer1M: 0.05,  outputPricePer1M: 0.40,                            releasedAt: '2025-08-07' },
];

const MODELS_BY_ID = new Map<string, ModelMetadata>(MODELS.map((m) => [m.id, m]));

const DEFAULT_CONTEXT_WINDOW = 128_000;

export function getAllModels(): ModelMetadata[] {
  return MODELS;
}

export function getModelById(id: string): ModelMetadata | undefined {
  return MODELS_BY_ID.get(id);
}

export function getContextWindow(model: string): number {
  return MODELS_BY_ID.get(model)?.contextWindow ?? DEFAULT_CONTEXT_WINDOW;
}

export const PROVIDER_MODELS: Record<AIProviderId, string[]> = {
  openai:    MODELS.filter((m) => m.provider === 'openai').map((m) => m.id),
  anthropic: MODELS.filter((m) => m.provider === 'anthropic').map((m) => m.id),
  google:    MODELS.filter((m) => m.provider === 'google').map((m) => m.id),
  deepinfra: MODELS.filter((m) => m.provider === 'deepinfra').map((m) => m.id),
};

// Per-provider default model when an org hasn't picked one. Sonnet 4.6 over
// Opus 4.7 (cheaper, still flagship-tier) so cost cap doesn't burn fast.
export const DEFAULT_MODELS: Record<AIProviderId, string> = {
  anthropic: 'claude-sonnet-4-6',
  openai:    'gpt-5.4',
  google:    'gemini-3-flash',
  deepinfra: 'Qwen/Qwen3.6-35B-A3B',
};

// Sanity: every model in MODELS must be priced. (Pricing is the source of
// truth for cost estimation; the table here is the source of truth for UI.)
export function assertPricingCoverage(): void {
  for (const m of MODELS) {
    const p = getTokenPricing(m.id);
    if (p.input <= 0 || p.output <= 0) {
      throw new Error(`Missing pricing for model ${m.id}`);
    }
  }
}
