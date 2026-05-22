const TOKEN_PRICING: Record<string, { input: number; output: number }> = {
  // Anthropic
  'claude-opus-4-7':                       { input: 5.00 / 1_000_000, output: 25.00 / 1_000_000 },
  'claude-sonnet-4-6':                     { input: 3.00 / 1_000_000, output: 15.00 / 1_000_000 },
  'claude-haiku-4-5-20251001':             { input: 1.00 / 1_000_000, output: 5.00 / 1_000_000 },
  // OpenAI
  'gpt-5.5':                               { input: 5.00 / 1_000_000,  output: 30.00 / 1_000_000 },
  'gpt-5.5-pro':                           { input: 30.00 / 1_000_000, output: 180.00 / 1_000_000 },
  'gpt-5.4':                               { input: 2.50 / 1_000_000,  output: 15.00 / 1_000_000 },
  'gpt-5.4-nano':                          { input: 0.20 / 1_000_000,  output: 1.25 / 1_000_000 },
  'gpt-5-nano':                            { input: 0.05 / 1_000_000,  output: 0.40 / 1_000_000 },
  // Google
  'gemini-3.1-pro':                        { input: 2.00 / 1_000_000, output: 12.00 / 1_000_000 },
  'gemini-3-flash':                        { input: 0.50 / 1_000_000, output: 3.00 / 1_000_000 },
  // DeepInfra (open-weight)
  'deepseek-ai/DeepSeek-V4-Pro':           { input: 1.74 / 1_000_000, output: 3.48 / 1_000_000 },
  'deepseek-ai/DeepSeek-V4-Flash':         { input: 0.14 / 1_000_000, output: 0.28 / 1_000_000 },
  'Qwen/Qwen3.6-35B-A3B':                  { input: 0.15 / 1_000_000, output: 0.95 / 1_000_000 },
  'moonshotai/Kimi-K2.6':                  { input: 0.75 / 1_000_000, output: 3.50 / 1_000_000 },
};

const DEFAULT_PRICING = { input: 3.00 / 1_000_000, output: 15.00 / 1_000_000 };

export function getTokenPricing(model: string): { input: number; output: number } {
  return TOKEN_PRICING[model] ?? DEFAULT_PRICING;
}

export function estimateCost(model: string, inputTokens: number, outputTokens: number): number {
  const pricing = getTokenPricing(model);
  return inputTokens * pricing.input + outputTokens * pricing.output;
}

export function estimateInputTokens(messages: Array<{ content: string | null }>): number {
  const totalChars = messages.reduce((sum, m) => sum + (m.content?.length ?? 0), 0);
  return Math.ceil(totalChars / 4);
}

const AI_MARKUP_FACTOR = 2;

export interface AiCost {
  cogCents: number;
  chargedCents: number;
}

export function chargedCentsForAi(model: string, inputTokens: number, outputTokens: number): AiCost {
  const pricing = getTokenPricing(model);
  const cogDollars = inputTokens * pricing.input + outputTokens * pricing.output;
  const cogCents = cogDollars * 100;
  const chargedCents = cogCents * AI_MARKUP_FACTOR;
  return { cogCents, chargedCents };
}
