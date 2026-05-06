// Phase 24 (v2.1a): SPA / classic-runtime detector.
//
// Used by:
//   1. backend/src/routes/dast.ts — POST /dast/targets (initial probe at create
//      time) + POST /dast/targets/:id/recheck-runtime + POST /dast/scan
//      (re-probe when 30-day TTL expires).
//   2. backend/depscanner/src/dast/pipeline.ts (Task 7) — re-probes at scan
//      time when the cached runtime is missing or stale.
//
// Best-effort: a probe failure / non-HTML response / timeout returns
// `{ runtime: 'unknown', confidence: 0, markers: [] }`. The Fly machine-shape
// dispatcher (backend/src/lib/fly-machines.ts:getDastMachineConfig) treats
// 'unknown' as SPA so the perf-4x 16GB shape is provisioned on the first
// scan; once classified, subsequent scans downsize.

export type DetectedRuntime = 'unknown' | 'classic' | 'spa';

export interface DetectRuntimeResult {
  runtime: DetectedRuntime;
  confidence: number; // 0-1; 0 when runtime='unknown'
  markers: string[];  // matched marker names; empty when runtime='unknown'
}

interface FetchableResponse {
  ok: boolean;
  status: number;
  text: () => Promise<string>;
  headers: { get: (name: string) => string | null } | Headers;
}

export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    signal?: AbortSignal;
    redirect?: 'follow' | 'manual';
  },
) => Promise<FetchableResponse>;

export type ValidateUrlFn = (
  url: string,
) => Promise<{ valid: true } | { valid: false; reason: string }>;

export interface DetectRuntimeOptions {
  fetchImpl?: FetchLike;
  // Caller-supplied SSRF / DNS-rebind guard. Optional so depscanner CLI use
  // (no Express layer) still works. Backend route layers validateExternalUrl
  // on top. Worker layers its own pre-flight on top.
  validateUrl?: ValidateUrlFn;
}

export const PROBE_TIMEOUT_MS = 15_000;
export const MAX_REDIRECTS = 3;
export const USER_AGENT = 'Deptex-DAST-Probe/2.1';

// Markers from popular SPA frameworks. Order is ranked by specificity.
// Confidence values reflect how unambiguous the marker is — `data-reactroot`
// only appears in React-rendered HTML; vue-ssr's `data-server-rendered` could
// in principle appear in classic markup so it gets a lower score.
const SPA_MARKER_PATTERNS: Array<{ name: string; re: RegExp; confidence: number }> = [
  { name: 'react', re: /\bdata-reactroot\b/i, confidence: 0.95 },
  { name: 'next', re: /id=["']__next["']/i, confidence: 0.95 },
  { name: 'nuxt', re: /id=["']__nuxt["']/i, confidence: 0.95 },
  { name: 'angular-attr', re: /\bng-version=/i, confidence: 0.95 },
  { name: 'angular-tag', re: /<app-root\b/i, confidence: 0.9 },
  { name: 'svelte', re: /id=["']svelte["']/i, confidence: 0.85 },
  { name: 'vue-ssr', re: /\bdata-server-rendered=["']true["']/i, confidence: 0.8 },
];

const SHELL_BODY_MAX_CHARS = 500;
const SHELL_MIN_SCRIPT_COUNT = 4;
const EMPTY_SHELL_CONFIDENCE = 0.6;
const CLASSIC_DEFAULT_CONFIDENCE = 0.7;

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

function unknownResult(): DetectRuntimeResult {
  return { runtime: 'unknown', confidence: 0, markers: [] };
}

// Cheap built-in scheme check so direct CLI use without a validateUrl
// callback still rejects file:/, javascript:, etc.
function basicSchemeCheck(url: string): boolean {
  try {
    const u = new URL(url);
    return ALLOWED_SCHEMES.has(u.protocol);
  } catch {
    return false;
  }
}

function readHeader(headers: FetchableResponse['headers'], name: string): string | null {
  if (typeof (headers as { get?: unknown }).get === 'function') {
    return (headers as { get: (n: string) => string | null }).get(name);
  }
  return null;
}

export async function detectRuntime(
  targetUrl: string,
  opts: DetectRuntimeOptions = {},
): Promise<DetectRuntimeResult> {
  if (!basicSchemeCheck(targetUrl)) return unknownResult();

  if (opts.validateUrl) {
    const r = await opts.validateUrl(targetUrl);
    if (r.valid === false) return unknownResult();
  }

  const fetchImpl = opts.fetchImpl ?? ((globalThis as { fetch?: FetchLike }).fetch as FetchLike | undefined);
  if (typeof fetchImpl !== 'function') return unknownResult();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  try {
    let currentUrl = targetUrl;
    let res: FetchableResponse | null = null;

    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      res = await fetchImpl(currentUrl, {
        method: 'GET',
        headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,*/*' },
        signal: controller.signal,
        redirect: 'manual',
      });
      const status = res.status;
      if (status >= 300 && status < 400) {
        const loc = readHeader(res.headers, 'location');
        if (!loc) break;
        currentUrl = new URL(loc, currentUrl).toString();
        if (!basicSchemeCheck(currentUrl)) return unknownResult();
        if (opts.validateUrl) {
          const r2 = await opts.validateUrl(currentUrl);
          if (r2.valid === false) return unknownResult();
        }
        continue;
      }
      break;
    }

    if (!res || !res.ok) return unknownResult();

    // Reject non-HTML content-types — JSON / binary endpoints can't be
    // classified by HTML markers. Empty content-type is permitted (some
    // servers omit it; we'll still try to read the body).
    const ct = readHeader(res.headers, 'content-type');
    if (ct && !ct.toLowerCase().includes('text/html')) return unknownResult();

    const body = await res.text();

    const markers: string[] = [];
    let maxConfidence = 0;
    for (const m of SPA_MARKER_PATTERNS) {
      if (m.re.test(body)) {
        markers.push(m.name);
        if (m.confidence > maxConfidence) maxConfidence = m.confidence;
      }
    }
    if (markers.length > 0) {
      return { runtime: 'spa', confidence: maxConfidence, markers };
    }

    // Empty-shell heuristic — common in pre-rendered SPAs that hydrate from
    // JS without leaving a framework-specific marker (custom rollups, lit,
    // older Vue without SSR).
    const bodyMatch = body.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i);
    const innerBody = bodyMatch ? bodyMatch[1] : body;
    const stripped = innerBody.replace(/<script[\s\S]*?<\/script>/gi, '').trim();
    const scriptCount = (body.match(/<script\b/gi) || []).length;
    if (
      scriptCount >= SHELL_MIN_SCRIPT_COUNT &&
      stripped.length <= SHELL_BODY_MAX_CHARS
    ) {
      return {
        runtime: 'spa',
        confidence: EMPTY_SHELL_CONFIDENCE,
        markers: ['empty_shell_heuristic'],
      };
    }

    return { runtime: 'classic', confidence: CLASSIC_DEFAULT_CONFIDENCE, markers: [] };
  } catch {
    return unknownResult();
  } finally {
    clearTimeout(timer);
  }
}

// 30-day TTL — every successful probe extends the cache. 'unknown' results
// are NOT cached so the next scan re-probes.
export const RUNTIME_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export function nextRuntimeTtlIso(): string {
  return new Date(Date.now() + RUNTIME_TTL_MS).toISOString();
}
