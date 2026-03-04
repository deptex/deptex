const TOKEN_PRICING: Record<string, { input: number; output: number }> = {
  'gpt-4o':                      { input: 2.50 / 1_000_000, output: 10.00 / 1_000_000 },
  'gpt-4o-mini':                 { input: 0.15 / 1_000_000, output: 0.60 / 1_000_000 },
  'gpt-4-turbo':                 { input: 10.00 / 1_000_000, output: 30.00 / 1_000_000 },
  'gpt-4-turbo-preview':         { input: 10.00 / 1_000_000, output: 30.00 / 1_000_000 },
  'o1':                          { input: 15.00 / 1_000_000, output: 60.00 / 1_000_000 },
  'o1-mini':                     { input: 3.00 / 1_000_000, output: 12.00 / 1_000_000 },
  'claude-sonnet-4-20250514':    { input: 3.00 / 1_000_000, output: 15.00 / 1_000_000 },
  'claude-3-5-sonnet-20241022':  { input: 3.00 / 1_000_000, output: 15.00 / 1_000_000 },
  'claude-3-haiku-20240307':     { input: 0.25 / 1_000_000, output: 1.25 / 1_000_000 },
  'gemini-2.5-flash':            { input: 0.15 / 1_000_000, output: 0.60 / 1_000_000 },
  'gemini-2.0-flash':            { input: 0.10 / 1_000_000, output: 0.40 / 1_000_000 },
  'gemini-1.5-pro':              { input: 1.25 / 1_000_000, output: 5.00 / 1_000_000 },
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
