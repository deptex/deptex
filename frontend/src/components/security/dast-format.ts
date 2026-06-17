// Shared formatting helpers for displaying DAST findings. ZAP/Nuclei findings
// carry raw HTML descriptions and full attacked URLs (query string = the giant
// injected payload), neither of which is fit to drop straight into the UI.

/**
 * Shorten a DAST endpoint URL for display: drop the origin, keep the path, and
 * elide query-param VALUES — for active-scan findings those values are the
 * injected attack payload (a wall of URL-encoded `<script>…`), pure noise in a
 * table. Keeps the param keys so the injection point is still visible:
 * `https://host/api/preview?layout=<payload>` → `/api/preview?layout=…`.
 * The full payload is shown verbatim in the finding's Request payload block.
 */
export function formatDastEndpointPath(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    const keys = [...new Set([...u.searchParams.keys()])];
    const query = keys.length ? `?${keys.map((k) => `${k}=…`).join('&')}` : '';
    return `${u.pathname}${query}` || rawUrl;
  } catch {
    return rawUrl;
  }
}

/** Just the request path, origin + query stripped: `/api/preview`. The injected
 *  parameter and payload are surfaced separately, so the endpoint field stays a
 *  clean location. */
export function dastEndpointPathOnly(rawUrl: string): string {
  try {
    return new URL(rawUrl).pathname || rawUrl;
  } catch {
    return rawUrl;
  }
}

/** The query parameter a DAST finding was injected into — the key whose decoded
 *  value carries the payload (`layout`, `tpl`, `id`). Null for passive findings
 *  or body/header injections that aren't in the query string. */
export function dastInjectionParam(rawUrl: string, payload: string | null | undefined): string | null {
  if (!payload) return null;
  try {
    const u = new URL(rawUrl);
    for (const [k, v] of u.searchParams) {
      if (v === payload || v.includes(payload)) return k;
    }
  } catch {
    /* not a parseable URL */
  }
  return null;
}

/**
 * Plain-English explanation of what a DAST payload is and what the server's
 * response proved — so the raw probe string (`zj${5407*5469}zj`) isn't a
 * mystery. Keyed off the vulnerability class.
 */
export function dastPayloadExplanation(vulnType: string | null | undefined): string {
  const t = (vulnType ?? '').toLowerCase();
  if (/template injection/.test(t)) {
    return 'A math expression wrapped in template syntax. The server evaluated it (returning the product) instead of treating it as text — proof it runs injected template code, which can escalate to remote code execution.';
  }
  if (/sql injection/.test(t)) {
    return 'A single quote to break out of the SQL string. The server returned a database error, revealing the query is built by string concatenation and is injectable.';
  }
  if (/cross site scripting|cross-site scripting|\bxss\b/.test(t)) {
    return 'A <script> tag. The server reflected it into the page without escaping it, so it would execute in a visitor’s browser.';
  }
  if (/command injection|remote os|remote code/.test(t)) {
    return 'A shell metacharacter / command. The server executed it, proving attacker input reaches an operating-system command.';
  }
  if (/path traversal/.test(t)) {
    return 'A “../” sequence to climb out of the intended directory. The server returned a file from outside it, confirming path traversal.';
  }
  if (/server side request|ssrf/.test(t)) {
    return 'A URL pointing at an internal address. The server fetched it, proving it can be made to call attacker-chosen destinations.';
  }
  return 'The exact test attack the scanner sent. The server’s response confirmed the input was processed unsafely.';
}

/** Documentation URL for a DAST rule. ZAP alert IDs map to zaproxy.org docs
 *  (sub-alerts like `90005-3` share the base plugin's page); other engines have
 *  no stable per-rule doc page, so we don't link them. */
export function dastRuleDocUrl(engine: string | null | undefined, ruleId: string | null | undefined): string | null {
  if (!ruleId) return null;
  const eng = engine === 'nuclei' || engine === 'merged' ? engine : 'zap';
  if (eng === 'zap') {
    const base = ruleId.split('-')[0].replace(/\D/g, '');
    if (base) return `https://www.zaproxy.org/docs/alerts/${base}/`;
  }
  return null;
}

/**
 * ZAP alert descriptions are HTML (`<p>…</p><p>…</p>`). Flatten to readable
 * plain text with paragraph breaks preserved so we never render raw tags.
 * Nuclei messages are plain text already — this is a no-op for them.
 */
export function stripHtmlToText(html: string): string {
  return html
    .replace(/<\/p>\s*<p[^>]*>/gi, '\n\n')
    .replace(/<\/?p[^>]*>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * The handler function name worth showing, or null. Express/etc. route handlers
 * are usually anonymous, and `(anonymous)()` is noise — skip it and let the
 * file:line carry the location.
 */
export function meaningfulHandlerName(name: string | null | undefined): string | null {
  if (!name) return null;
  const trimmed = name.trim();
  if (!trimmed || /^\(?\s*anonymous\s*\)?$/i.test(trimmed)) return null;
  return trimmed;
}
