// Best-effort SPA / classic-runtime detector. Used by:
//   1. POST /dast/targets (initial probe at create time)
//   2. POST /dast/targets/:targetId/recheck-runtime (manual force-probe)
//   3. POST /dast/scan (re-probe when detected_runtime_ttl_at < NOW())
//
// Task 6 may evolve the heuristic; the contract here stays stable so callers
// don't need to change.

import { validateExternalUrl } from './url-guard';

export type DetectedRuntime = 'unknown' | 'classic' | 'spa';

export interface DetectRuntimeResult {
  runtime: DetectedRuntime;
  // Marker(s) that triggered the SPA classification, for debugging / UI.
  matched_markers?: string[];
  // True when the probe completed without a hard fetch error; false when we
  // bailed (timeout, non-2xx, validateExternalUrl reject) and returned 'unknown'.
  probed: boolean;
  // Error reason when probed=false (network error, 4xx/5xx, etc.).
  error_reason?: string;
}

const PROBE_TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 3;
const USER_AGENT = 'Deptex-DAST-Probe/2.1';

// Markers from popular SPA frameworks. Ordered by specificity.
const SPA_MARKER_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'react', re: /\bdata-reactroot\b/i },
  { name: 'react-flight', re: /\bdata-react-helmet\b/i },
  { name: 'next', re: /id=["']__next["']/i },
  { name: 'nuxt', re: /id=["']__nuxt["']/i },
  { name: 'vue-ssr', re: /\bdata-server-rendered=["']true["']/i },
  { name: 'vue-app', re: /<div[^>]+id=["']app["'][^>]*>\s*<\/div>/i },
  { name: 'angular', re: /<app-root\b[^>]*>\s*<\/app-root>/i },
  { name: 'angular-attr', re: /\bng-version=/i },
  { name: 'svelte', re: /id=["']svelte["']/i },
];

// Heuristic: empty-shell pages with many script tags are almost always SPAs.
const SHELL_BODY_MAX_CHARS = 500;
const SHELL_MIN_SCRIPT_COUNT = 4;

interface FetchableResponse {
  ok: boolean;
  status: number;
  text: () => Promise<string>;
  headers: Headers | { get: (name: string) => string | null };
}

// Allow injection in tests.
export type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string>; signal?: AbortSignal; redirect?: 'follow' | 'manual' },
) => Promise<FetchableResponse>;

export interface DetectRuntimeOptions {
  fetchImpl?: FetchLike;
  validateUrl?: typeof validateExternalUrl;
}

export async function detectRuntime(
  targetUrl: string,
  opts: DetectRuntimeOptions = {},
): Promise<DetectRuntimeResult> {
  const fetchImpl = opts.fetchImpl ?? ((globalThis as any).fetch as FetchLike);
  const guard = opts.validateUrl ?? validateExternalUrl;

  const urlCheck = await guard(targetUrl);
  if (urlCheck.valid === false) {
    return { runtime: 'unknown', probed: false, error_reason: urlCheck.reason };
  }

  if (typeof fetchImpl !== 'function') {
    return { runtime: 'unknown', probed: false, error_reason: 'fetch_unavailable' };
  }

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
        const loc =
          typeof (res.headers as any).get === 'function'
            ? (res.headers as any).get('location')
            : null;
        if (!loc) break;
        currentUrl = new URL(loc, currentUrl).toString();
        const redirCheck = await guard(currentUrl);
        if (redirCheck.valid === false) {
          return { runtime: 'unknown', probed: false, error_reason: 'redirect_to_blocked_url' };
        }
        continue;
      }
      break;
    }

    if (!res || !res.ok) {
      return {
        runtime: 'unknown',
        probed: false,
        error_reason: `non_ok_status_${res?.status ?? 'no_response'}`,
      };
    }

    const body = await res.text();

    const matched: string[] = [];
    for (const m of SPA_MARKER_PATTERNS) {
      if (m.re.test(body)) matched.push(m.name);
    }
    if (matched.length > 0) {
      return { runtime: 'spa', matched_markers: matched, probed: true };
    }

    // Empty-shell heuristic: count <script>s and <body> innerHTML length.
    const bodyMatch = body.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i);
    const innerBody = bodyMatch ? bodyMatch[1] : body;
    const stripped = innerBody.replace(/<script[\s\S]*?<\/script>/gi, '').trim();
    const scriptCount = (body.match(/<script\b/gi) || []).length;
    if (scriptCount >= SHELL_MIN_SCRIPT_COUNT && stripped.length <= SHELL_BODY_MAX_CHARS) {
      return { runtime: 'spa', matched_markers: ['empty_shell_heuristic'], probed: true };
    }

    return { runtime: 'classic', probed: true };
  } catch (e: any) {
    return {
      runtime: 'unknown',
      probed: false,
      error_reason: e?.name === 'AbortError' ? 'probe_timeout' : (e?.message ?? 'probe_error'),
    };
  } finally {
    clearTimeout(timer);
  }
}

// 30-day TTL — matches the plan's cache window.
export const RUNTIME_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export function nextRuntimeTtlIso(): string {
  return new Date(Date.now() + RUNTIME_TTL_MS).toISOString();
}
