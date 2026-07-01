/**
 * Constant-host detection for SSRF / open-redirect sink arguments.
 *
 * The taint engine fires an `ssrf` / `open_redirect` hit whenever a tainted
 * local reaches the URL argument of `fetch` / `axios.*` / `res.redirect` / etc.
 * But the overwhelming real-world shape is a URL whose scheme+host are a
 * compile-time constant and whose tainted part is only the PATH or QUERY:
 *
 *     fetch(`https://api.github.com/repos/${repo}`)        // host constant
 *     fetch(`${GITHUB_API_BASE}/app/installations/${id}`)  // host constant (via const)
 *     res.redirect(`${FRONTEND_URL}/settings?m=${msg}`)    // host constant
 *
 * In all of these the attacker cannot re-point the request to another host nor
 * inject `//evil.com` — so they are NOT SSRF / open redirect. A genuinely
 * dangerous flow taints the HOST itself:
 *
 *     fetch(userSuppliedUrl)            // host tainted   → real SSRF
 *     fetch('https://' + attackerHost)  // host tainted   → real SSRF
 *     res.redirect(req.query.returnTo)  // host tainted   → real open redirect
 *
 * `urlHeadIsConstant` answers "does the scheme+authority of this URL argument
 * come entirely from constants?" given a `resolve` callback that maps an
 * identifier to the source text of its (single-assignment) string initializer.
 * It is intentionally conservative: anything it can't prove constant returns
 * false, so the flow is KEPT (no false negatives on real SSRF). Only a provable
 * constant scheme+host suppresses the hit.
 */

/**
 * Matches a string/template literal whose text begins with a literal
 * `scheme://host` — i.e. the host is spelled out, not interpolated. The host
 * char-class excludes `$`, `{`, `'`, `"`, '`', so an interpolation or a closing
 * quote immediately after the scheme (e.g. `'https://' + host`) fails to match,
 * which is exactly the tainted-host case we must NOT suppress.
 */
const SCHEME_HOST_RE = /^['"`]\s*https?:\/\/[A-Za-z0-9._-]+(?::\d+)?(?=$|[/?#`'"\\])/;

/** A bare identifier (the `fetch(url)` shape where `url` names a const). */
const BARE_IDENT_RE = /^[A-Za-z_$][\w$]*$/;

/** Template literal whose first interpolation is a bare identifier: `` `${BASE}/... ``. */
const LEADING_INTERP_RE = /^`\s*\$\{\s*([A-Za-z_$][\w$]*)\s*\}/;

/**
 * True when the scheme+host of `rawArgText` are provably constant.
 *
 * @param rawArgText  Source text of the URL argument expression.
 * @param resolve     Maps an identifier → the source text of its constant
 *                    string initializer (or undefined if unknown / reassigned).
 * @param depth       Recursion guard for chained const resolution.
 */
export function urlHeadIsConstant(
  rawArgText: string,
  resolve: (name: string) => string | undefined,
  depth = 0,
): boolean {
  if (depth > 4) return false;
  const text = rawArgText.trim();
  if (!text) return false;

  // `fetch(url)` — resolve the identifier to its constant init, then re-check.
  if (BARE_IDENT_RE.test(text)) {
    const init = resolve(text);
    if (init === undefined) return false;
    return urlHeadIsConstant(init, resolve, depth + 1);
  }

  // Inline literal host: `'https://h/...'` / `` `https://h/${x}` ``.
  if (SCHEME_HOST_RE.test(text)) return true;

  // `` `${BASE}/path/${x}` `` — the host comes from the FIRST interpolation.
  // If that identifier resolves to a constant-host string, the whole URL's
  // host is constant regardless of later (tainted) interpolations.
  const m = text.match(LEADING_INTERP_RE);
  if (m) {
    const init = resolve(m[1]);
    if (init !== undefined) return urlHeadIsConstant(init, resolve, depth + 1);
  }

  return false;
}
