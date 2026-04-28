/**
 * Multi-provider AI call + strict schema validation for the generated rule
 * payload. Provider-specific request shape lives here; everything downstream
 * (validate.ts, index.ts) treats the parsed result uniformly.
 *
 * Cost estimation uses per-model pricing maintained alongside the EPD module
 * (epd.ts). Token counts come back from each provider's usage metadata when
 * available, and fall back to a coarse char/4 heuristic on the input side.
 */

import { z } from 'zod';

const REQUEST_TIMEOUT_MS = 60_000;

export type AiProviderName = 'anthropic' | 'openai' | 'google';

const REACHABILITY_LEVELS = ['confirmed', 'function'] as const;
const ENTRY_POINT_CLASSES = ['PUBLIC_UNAUTH', 'AUTH_INTERNAL', 'OFFLINE_WORKER'] as const;

export const GeneratedPayloadSchema = z.object({
  rule_yaml: z.string().min(40, 'rule_yaml too short to be a Semgrep rule'),
  vulnerable_fixture: z.string().min(10, 'vulnerable_fixture too short'),
  safe_fixture: z.string().min(10, 'safe_fixture too short'),
  reachability_level: z.enum(REACHABILITY_LEVELS),
  entry_point_class: z.enum(ENTRY_POINT_CLASSES),
  rationale: z.string().optional().default(''),
});

export type GeneratedPayload = z.infer<typeof GeneratedPayloadSchema>;

export interface CallProviderArgs {
  prompt: string;
  provider: AiProviderName;
  model: string;
  apiKey: string;
  signal?: AbortSignal;
  /** Cap on output tokens. Generated rules are small; default is plenty. */
  maxOutputTokens?: number;
  /** OpenAI-compatible endpoint override. When provider='openai' and this is
   *  set, the request goes to this URL instead of api.openai.com. Lets us
   *  point at DeepInfra / OpenRouter / Alibaba / any drop-in OpenAI-compat
   *  host without per-provider SDK work. Ignored for anthropic/google. */
  baseUrl?: string;
}

export interface CallProviderResult {
  payload: GeneratedPayload;
  inputTokens: number;
  outputTokens: number;
  estimatedCostUsd: number;
  rawResponseExcerpt: string;
}

export class GenerationError extends Error {
  readonly code:
    | 'provider_error'
    | 'provider_timeout'
    | 'parse_failed'
    | 'invalid_schema'
    | 'unsupported_provider';

  constructor(code: GenerationError['code'], message: string) {
    super(message);
    this.name = 'GenerationError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Pricing — keep in sync with backend/src/lib/ai/pricing.ts. Numbers are
// USD per token. Models we don't recognize fall back to the cheapest known
// price so extraction-worker doesn't crash on an unfamiliar BYOK model.
// ---------------------------------------------------------------------------

interface ModelPricing {
  input: number;
  output: number;
}

const MODEL_PRICING: Record<string, ModelPricing> = {
  // Anthropic
  'claude-opus-4-7': { input: 15.00 / 1_000_000, output: 75.00 / 1_000_000 },
  'claude-sonnet-4-6': { input: 3.00 / 1_000_000, output: 15.00 / 1_000_000 },
  'claude-sonnet-4-20250514': { input: 3.00 / 1_000_000, output: 15.00 / 1_000_000 },
  'claude-3-5-sonnet-20241022': { input: 3.00 / 1_000_000, output: 15.00 / 1_000_000 },
  'claude-haiku-4-5-20251001': { input: 1.00 / 1_000_000, output: 5.00 / 1_000_000 },
  'claude-3-haiku-20240307': { input: 0.25 / 1_000_000, output: 1.25 / 1_000_000 },
  // OpenAI
  'gpt-4o': { input: 2.50 / 1_000_000, output: 10.00 / 1_000_000 },
  'gpt-4o-mini': { input: 0.15 / 1_000_000, output: 0.60 / 1_000_000 },
  'gpt-4-turbo': { input: 10.00 / 1_000_000, output: 30.00 / 1_000_000 },
  'o1': { input: 15.00 / 1_000_000, output: 60.00 / 1_000_000 },
  'o1-mini': { input: 3.00 / 1_000_000, output: 12.00 / 1_000_000 },
  // Google
  'gemini-2.5-flash': { input: 0.30 / 1_000_000, output: 2.50 / 1_000_000 },
  'gemini-2.0-flash': { input: 0.10 / 1_000_000, output: 0.40 / 1_000_000 },
  'gemini-1.5-pro': { input: 1.25 / 1_000_000, output: 5.00 / 1_000_000 },
  // OpenAI-compatible third parties (provider='openai' + custom baseUrl).
  // Pricing as advertised on the host's pricing page; cross-check before
  // moving any of these to a billing-sensitive default.
  // DeepInfra
  'Qwen/Qwen3-235B-A22B-Instruct-2507': { input: 0.071 / 1_000_000, output: 0.10 / 1_000_000 },
  'Qwen/Qwen3-235B-A22B-Instruct': { input: 0.071 / 1_000_000, output: 0.10 / 1_000_000 },
  'Qwen/Qwen2.5-72B-Instruct': { input: 0.36 / 1_000_000, output: 0.40 / 1_000_000 },
  'deepseek-ai/DeepSeek-V3.1': { input: 0.21 / 1_000_000, output: 0.79 / 1_000_000 },
  'deepseek-ai/DeepSeek-V3': { input: 0.32 / 1_000_000, output: 0.89 / 1_000_000 },
  'meta-llama/Llama-3.3-70B-Instruct-Turbo': { input: 0.10 / 1_000_000, output: 0.32 / 1_000_000 },
  // OpenRouter (auto-routed)
  'deepseek/deepseek-chat-v3.1': { input: 0.15 / 1_000_000, output: 0.75 / 1_000_000 },
  'qwen/qwen3-235b-a22b': { input: 0.455 / 1_000_000, output: 1.82 / 1_000_000 },
  'moonshotai/kimi-k2': { input: 0.57 / 1_000_000, output: 2.30 / 1_000_000 },
};

const FALLBACK_PRICING: ModelPricing = { input: 1.00 / 1_000_000, output: 5.00 / 1_000_000 };

export function estimateCostUsd(model: string, inputTokens: number, outputTokens: number): number {
  const p = MODEL_PRICING[model] ?? FALLBACK_PRICING;
  return inputTokens * p.input + outputTokens * p.output;
}

function estimateInputTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

export async function callProviderAndParse(args: CallProviderArgs): Promise<CallProviderResult> {
  const raw = await callProvider(args);
  const payload = parseAndValidate(raw.text);
  const cost = estimateCostUsd(args.model, raw.inputTokens, raw.outputTokens);
  return {
    payload,
    inputTokens: raw.inputTokens,
    outputTokens: raw.outputTokens,
    estimatedCostUsd: cost,
    rawResponseExcerpt: raw.text.slice(0, 500),
  };
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/**
 * Extracts the first balanced JSON object from `raw` (some providers leak a
 * trailing newline / explanation despite our explicit instructions). Then
 * validates it against the Zod schema.
 */
export function parseAndValidate(raw: string): GeneratedPayload {
  const stripped = stripCodeFence(raw).trim();
  const json = extractFirstJsonObject(stripped);
  if (!json) {
    throw new GenerationError('parse_failed', 'Provider response did not contain a JSON object');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new GenerationError('parse_failed', `Provider response JSON.parse failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  const result = GeneratedPayloadSchema.safeParse(parsed);
  if (!result.success) {
    throw new GenerationError('invalid_schema', `Generated payload failed schema: ${result.error.issues.map((i) => `${i.path.join('.')}=${i.message}`).join('; ')}`);
  }
  return result.data;
}

function stripCodeFence(s: string): string {
  // Some models still wrap in ```json ... ``` despite the instruction not to.
  // Be lenient — strip a leading/trailing fence if it wraps the entire body.
  const trimmed = s.trim();
  const fence = /^```(?:json)?\s*([\s\S]*?)\s*```$/i;
  const m = trimmed.match(fence);
  return m ? m[1] : trimmed;
}

function extractFirstJsonObject(s: string): string | null {
  const start = s.indexOf('{');
  if (start < 0) return null;
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (escape) { escape = false; continue; }
    if (ch === '\\' && inString) { escape = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return s.slice(start, i + 1);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Provider dispatch
// ---------------------------------------------------------------------------

interface RawProviderResponse {
  text: string;
  inputTokens: number;
  outputTokens: number;
}

async function callProvider(args: CallProviderArgs): Promise<RawProviderResponse> {
  switch (args.provider) {
    case 'anthropic':
      return callAnthropic(args);
    case 'openai':
      return callOpenAI(args);
    case 'google':
      return callGoogle(args);
    default:
      throw new GenerationError('unsupported_provider', `Unknown provider: ${args.provider}`);
  }
}

function withRequestTimeout(outerSignal?: AbortSignal): { controller: AbortController; clear: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  if (outerSignal) {
    if (outerSignal.aborted) controller.abort();
    else outerSignal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  return { controller, clear: () => clearTimeout(timer) };
}

const RATE_LIMIT_MAX_ATTEMPTS = 4;
const RATE_LIMIT_BASE_DELAY_MS = 4_000;
const RATE_LIMIT_MAX_DELAY_MS = 60_000;

/**
 * Run `op` and retry on HTTP 429 (rate limit). Used uniformly across all
 * providers — Anthropic returns 429 with `retry-after` (seconds), OpenAI-style
 * hosts (incl. DeepInfra/OpenRouter) and Google use the same header. The
 * inner op signals retry by throwing a RateLimitError carrying the parsed
 * retry-after delay (or undefined → exponential backoff).
 *
 * Concurrency=5 against Anthropic's 30K input-tokens/minute org cap saturates
 * after ~3 simultaneous CVE generations and the rest queue with 429s; without
 * this wrapper they all fail. Cap at 4 attempts with exponential backoff so a
 * sustained outage still surfaces a provider_error rather than spinning.
 */
class RateLimitError extends Error {
  retryAfterMs?: number;
  constructor(message: string, retryAfterMs?: number) {
    super(message);
    this.retryAfterMs = retryAfterMs;
  }
}

async function withRateLimitRetry<T>(
  op: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  let attempt = 0;
  for (;;) {
    try {
      return await op();
    } catch (err) {
      if (!(err instanceof RateLimitError)) throw err;
      attempt++;
      if (attempt >= RATE_LIMIT_MAX_ATTEMPTS) {
        // Surface the last 429 as a provider_error so the per-CVE result has
        // an informative status. The message the wrapper threw already carries
        // the body excerpt.
        throw new GenerationError('provider_error', `Rate-limited after ${attempt} attempts: ${err.message}`);
      }
      const backoff = Math.min(RATE_LIMIT_BASE_DELAY_MS * 2 ** (attempt - 1), RATE_LIMIT_MAX_DELAY_MS);
      const delayMs = err.retryAfterMs ?? backoff;
      // Honor the outer abort signal during the wait so a pipeline timeout
      // doesn't have to wait out the rate-limit sleep.
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, delayMs);
        if (signal) {
          const onAbort = () => { clearTimeout(t); reject(new Error('aborted')); };
          if (signal.aborted) onAbort();
          else signal.addEventListener('abort', onAbort, { once: true });
        }
      });
    }
  }
}

function parseRetryAfter(headerValue: string | null): number | undefined {
  if (!headerValue) return undefined;
  const seconds = Number(headerValue);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, RATE_LIMIT_MAX_DELAY_MS);
  // Some providers send an HTTP date; parse-and-diff
  const ts = Date.parse(headerValue);
  if (Number.isFinite(ts)) {
    const ms = ts - Date.now();
    if (ms > 0) return Math.min(ms, RATE_LIMIT_MAX_DELAY_MS);
  }
  return undefined;
}

async function callAnthropic(args: CallProviderArgs): Promise<RawProviderResponse> {
  return withRateLimitRetry(() => callAnthropicOnce(args), args.signal);
}

async function callAnthropicOnce(args: CallProviderArgs): Promise<RawProviderResponse> {
  const { controller, clear } = withRequestTimeout(args.signal);
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': args.apiKey,
        'anthropic-version': '2023-06-01',
      },
      signal: controller.signal,
      body: JSON.stringify({
        model: args.model,
        temperature: 0.1,
        max_tokens: args.maxOutputTokens ?? 2_500,
        messages: [{ role: 'user', content: [{ type: 'text', text: args.prompt }] }],
      }),
    });
    if (res.status === 429) {
      const errBody = await res.text().catch(() => '');
      throw new RateLimitError(`Anthropic 429: ${errBody.slice(0, 200)}`, parseRetryAfter(res.headers.get('retry-after')));
    }
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new GenerationError('provider_error', `Anthropic returned ${res.status}: ${errBody.slice(0, 200)}`);
    }
    const body = await res.json() as {
      content?: Array<{ type?: string; text?: string }>;
      usage?: { input_tokens?: number; output_tokens?: number };
    };
    const text = body.content?.find((b) => b?.type === 'text')?.text ?? '';
    return {
      text,
      inputTokens: Number(body.usage?.input_tokens ?? estimateInputTokens(args.prompt)),
      outputTokens: Number(body.usage?.output_tokens ?? estimateInputTokens(text)),
    };
  } catch (err) {
    if (err instanceof GenerationError) throw err;
    if (err instanceof Error && err.name === 'AbortError') {
      throw new GenerationError('provider_timeout', `Anthropic request timed out after ${REQUEST_TIMEOUT_MS}ms`);
    }
    throw new GenerationError('provider_error', `Anthropic call failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clear();
  }
}

async function callOpenAI(args: CallProviderArgs): Promise<RawProviderResponse> {
  return withRateLimitRetry(() => callOpenAIOnce(args), args.signal);
}

async function callOpenAIOnce(args: CallProviderArgs): Promise<RawProviderResponse> {
  const { controller, clear } = withRequestTimeout(args.signal);
  // Default to OpenAI; otherwise honor the override and append /chat/completions
  // if the caller passed only the base path. DeepInfra's OpenAI endpoint is
  // https://api.deepinfra.com/v1/openai (note the /openai suffix); OpenRouter
  // is https://openrouter.ai/api/v1; Alibaba dashscope is
  // https://dashscope-intl.aliyuncs.com/compatible-mode/v1 — all expose a
  // /chat/completions sub-route.
  const baseUrl = args.baseUrl?.trim().replace(/\/$/, '') || 'https://api.openai.com/v1';
  const url = baseUrl.endsWith('/chat/completions') ? baseUrl : `${baseUrl}/chat/completions`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${args.apiKey}`,
      },
      signal: controller.signal,
      body: JSON.stringify({
        model: args.model,
        temperature: 0.1,
        max_tokens: args.maxOutputTokens ?? 2_500,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: 'You are a senior application-security engineer. Respond with valid JSON only.' },
          { role: 'user', content: args.prompt },
        ],
      }),
    });
    if (res.status === 429) {
      const errBody = await res.text().catch(() => '');
      throw new RateLimitError(`OpenAI-compat 429 (${url}): ${errBody.slice(0, 200)}`, parseRetryAfter(res.headers.get('retry-after')));
    }
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new GenerationError('provider_error', `OpenAI-compat host returned ${res.status} (${url}): ${errBody.slice(0, 200)}`);
    }
    const body = await res.json() as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };
    const text = body.choices?.[0]?.message?.content ?? '';
    return {
      text,
      inputTokens: Number(body.usage?.prompt_tokens ?? estimateInputTokens(args.prompt)),
      outputTokens: Number(body.usage?.completion_tokens ?? estimateInputTokens(text)),
    };
  } catch (err) {
    if (err instanceof GenerationError) throw err;
    if (err instanceof Error && err.name === 'AbortError') {
      throw new GenerationError('provider_timeout', `OpenAI request timed out after ${REQUEST_TIMEOUT_MS}ms`);
    }
    throw new GenerationError('provider_error', `OpenAI call failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clear();
  }
}

async function callGoogle(args: CallProviderArgs): Promise<RawProviderResponse> {
  return withRateLimitRetry(() => callGoogleOnce(args), args.signal);
}

async function callGoogleOnce(args: CallProviderArgs): Promise<RawProviderResponse> {
  const { controller, clear } = withRequestTimeout(args.signal);
  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(args.model)}:generateContent?key=${encodeURIComponent(args.apiKey)}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: args.maxOutputTokens ?? 2_500,
          responseMimeType: 'application/json',
        },
        contents: [
          { role: 'user', parts: [{ text: args.prompt }] },
        ],
      }),
    });
    if (res.status === 429) {
      const errBody = await res.text().catch(() => '');
      throw new RateLimitError(`Google 429: ${errBody.slice(0, 200)}`, parseRetryAfter(res.headers.get('retry-after')));
    }
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new GenerationError('provider_error', `Google returned ${res.status}: ${errBody.slice(0, 200)}`);
    }
    const body = await res.json() as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number };
    };
    const parts = body.candidates?.[0]?.content?.parts ?? [];
    const text = parts.map((p) => p.text ?? '').join('');
    return {
      text,
      inputTokens: Number(body.usageMetadata?.promptTokenCount ?? estimateInputTokens(args.prompt)),
      outputTokens: Number(body.usageMetadata?.candidatesTokenCount ?? estimateInputTokens(text)),
    };
  } catch (err) {
    if (err instanceof GenerationError) throw err;
    if (err instanceof Error && err.name === 'AbortError') {
      throw new GenerationError('provider_timeout', `Google request timed out after ${REQUEST_TIMEOUT_MS}ms`);
    }
    throw new GenerationError('provider_error', `Google call failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clear();
  }
}
