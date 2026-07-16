/**
 * Shared route-level auth-evidence core (entry-point auth classification, v4).
 *
 * Language-agnostic building blocks the framework detectors call to turn the
 * middleware / decorator / annotation evidence they gather at a route into an
 * `EntryPointClassification` — replacing the old file-level import sniff
 * (`classifyFromAuth(detect*AuthMechanism(imports))`) which flipped every route
 * in a file to AUTH_INTERNAL on a single auth import.
 *
 * Contract (plan Core Semantics 1-5, 8, 10, 11):
 *   - AUTH_INTERNAL / OFFLINE_WORKER require positive route-level evidence.
 *   - Explicit-public overrides always win (Sem 2).
 *   - Conditional / carve-out coverage does NOT cover (Sem 3).
 *   - Optional / parse-only auth is never evidence (Sem 4).
 *   - Machine verifier evidence → OFFLINE_WORKER (Sem 5).
 *   - The public-route-name belt blocks CENTRALIZED demotions only (Sem 10).
 *   - Prefix coverage is path-segment-bounded (Sem 11).
 *
 * The span helpers (`spanOfNode` / `spanContains`) are the join substrate:
 * a taint flow demotes only when its source line falls inside an authed,
 * demotion-eligible handler span (Core Semantics 6). Export / same-file-reference
 * eligibility detection is language-specific and lives in the per-language utils
 * (e.g. `util/javascript.ts`), because it is AST-shaped.
 */
import type { Node } from 'web-tree-sitter';
import type { EntryPointClassification, HandlerSpan } from '../types';

export type { HandlerSpan };

/**
 * A single route's auth facts, as the `ctx.entryPointAuth` map holds them and
 * `matchFlowToRoutes` consumes them. Built per-route (pre-dedupe) at usage
 * extraction; never persisted (project_entry_points carries the coarse row).
 */
export interface RouteAuthRecord {
  classification: EntryPointClassification;
  /** null for wrapped / member / cross-file / mount handlers — those never demote. */
  handlerSpan: HandlerSpan | null;
  /** false when the handler could be re-mounted/called from code we can't see (Sem 6 guard). */
  demotionEligible: boolean;
  routePattern: string | null;
  middlewareChain: string[] | null;
  authMechanism: string | null;
}

/**
 * Evidence a detector gathers at a route, fed to `classifyRoute`. Everything is
 * optional so a detector supplies only what it can see; absence is treated as
 * "no evidence" (fail-safe → public).
 */
export interface RouteAuthEvidence {
  /** Identifiers of auth middleware / guards / decorators applied to this route. */
  authTokens?: readonly string[];
  /**
   * Tokens the detector has ALREADY determined are auth evidence by exact
   * framework semantics (annotation families: `@Secured`, `@RolesAllowed`,
   * `@Authenticated`, non-public `@PreAuthorize` SpEL). Bypass the auth-NAME
   * pattern matching + optional-veto (the detector owns those semantics), but
   * still subject to `optional`, `conditional`, the belt, and public overrides.
   */
  vettedAuthTokens?: readonly string[];
  /** Verifier / internal-key evidence (Sem 5): `Receiver.verify`, `constructEvent`, internal-key middleware. */
  internalTokens?: readonly string[];
  /** Explicit-public markers (Sem 2): `@PermitAll`, `AllowAny`, `skip_before_action`, `withoutMiddleware('auth')`, … */
  publicOverrides?: readonly string[];
  /** The route pattern, for the belt (Sem 10) + prefix (Sem 11) checks. */
  routePattern?: string | null;
  /** True when the ONLY auth evidence is a centralized idiom (belt applies). Route-local evidence sets false. */
  centralizedOnly?: boolean;
  /** True when coverage is conditional / carve-out (Sem 3) → not covering. */
  conditional?: boolean;
  /** True when the caller already determined the auth is optional (arg inspection: credentialsRequired:false, auto_error=False, …). */
  optional?: boolean;
}

/**
 * Auth-name patterns (Sem 8). Matched case-insensitively with word boundaries
 * against a middleware / guard / decorator identifier. Callers should match on
 * the import-RESOLVED symbol where possible (alias resolution), falling back to
 * the literal name.
 */
export const AUTH_NAME_PATTERNS: readonly RegExp[] = [
  /\bauthenticate(d|or)?\b/i,
  /\brequires?auth\b/i,
  /\bensure(auth|logged)\b/i,
  /\bisauthenticated\b/i,
  /\blogin_?required\b/i,
  /\bjwt_?required\b/i,
  /\bverify_?token\b/i,
  /\bcheck_?(auth|jwt)\b/i,
  /\bpassport\.authenticate\b/i,
  /\bexpress_?jwt\b/i,
  /\brequire_?user\b/i,
  /\bauthorize\b/i,
  // Guard-class convention (NestJS `@UseGuards(JwtAuthGuard)`, custom Express
  // classes). Substring, camelCase-tolerant: JwtAuthGuard / LocalAuthGuard.
  // ThrottlerGuard / RolesGuard deliberately do NOT match (rate-limit /
  // authorization-only names are not authentication evidence on their own).
  /auth.?guard/i,
];

/**
 * Machine / internal verifier name patterns (Sem 5). Matched as substrings
 * (not `\b`-bounded) because these appear as camelCase seams in identifiers
 * (`internalKeyGuard`, `verifyQstashSignature`) where `\b` does not fire —
 * and over-matching a machine-endpoint signal is the safe (coverage-loss)
 * direction, never a wrongful user-facing demotion.
 */
export const INTERNAL_NAME_PATTERNS: readonly RegExp[] = [
  /internal/i,
  /signature/i,
  /hmac/i,
  /webhook.?verif/i,
  /qstash/i,
  /svix/i,
];

/**
 * Explicit-public override patterns (Sem 2), matched against a decorator /
 * annotation / call identifier on the route.
 */
export const PUBLIC_OVERRIDE_PATTERNS: readonly RegExp[] = [
  /\bpermit_?all\b/i,
  /\ballow_?anonymous\b/i,
  /\ballow_?any\b/i,
  /\bis_?anonymous\b/i,
  /\bpublic_?access\b/i,
  /\bis_?authenticated_?anonymously\b/i,
  /\blogin_?not_?required\b/i,
  /\bskip_?before_?action\b/i,
  /\bwithout_?middleware\b/i,
  /\bpublic\b/i,
  /\banon(ymous)?\b/i,
  /\bskip.?auth\b/i,
  /\bno.?auth\b/i,
  /\bunprotected\b/i,
  /\ballow.?unauth\b/i,
];

/**
 * Optional / soft-auth veto tokens (Sem 4). An auth-name match that also matches
 * one of these is NOT evidence — the app deliberately lets unauthenticated
 * requests through (passport `'anonymous'`, `*_optional`, soft auth, …).
 */
export const OPTIONAL_VETO_PATTERNS: readonly RegExp[] = [
  // camelCase-tolerant substrings — an auth token that trips these is not
  // evidence, and over-vetoing is coverage loss (safe), never a wrongful demote.
  /optional/i,
  /anonymous/i,
  /guest/i,
  // weaker tokens keep word boundaries to avoid over-matching (soft→software).
  /\bmaybe\b/i,
  /\btry\b/i,
  /\bsoft\b/i,
];

/**
 * Public-route-name belt (Sem 10): route patterns whose path contains one of
 * these segments must never inherit a CENTRALIZED demotion (route-local
 * evidence may still demote them). Segment-boundary matched so `/users/:id/login`
 * matches but `/loginit` does not.
 */
const BELT_SEGMENTS: readonly string[] = [
  'login', 'logout', 'signin', 'signup', 'register', 'password',
  'health', 'status', 'ping', 'webhook', 'callback', 'oauth', 'well-known',
];
const BELT_RE = new RegExp(`(^|[/._-])(${BELT_SEGMENTS.join('|')})([/._-]|$)`, 'i');

export function matchesAuthName(token: string): boolean {
  return AUTH_NAME_PATTERNS.some((re) => re.test(token));
}

export function matchesInternalName(token: string): boolean {
  return INTERNAL_NAME_PATTERNS.some((re) => re.test(token));
}

export function matchesPublicOverride(token: string): boolean {
  return PUBLIC_OVERRIDE_PATTERNS.some((re) => re.test(token));
}

/** An auth-name token that ALSO trips an optional-veto pattern is not evidence (Sem 4). */
export function isOptionalVetoed(token: string): boolean {
  return OPTIONAL_VETO_PATTERNS.some((re) => re.test(token));
}

/** Sem 10 — does this route pattern hit the public-route-name belt? */
export function matchesPublicRouteBelt(routePattern: string | null | undefined): boolean {
  if (!routePattern) return false;
  return BELT_RE.test(routePattern);
}

/**
 * Sem 11 — path-segment-bounded prefix coverage. `/api` covers `/api` and
 * `/api/…` but never `/apiv2`. A pathless (empty) prefix covers everything.
 */
export function prefixCoversRoute(usePrefix: string | null | undefined, routePattern: string | null | undefined): boolean {
  if (usePrefix == null || usePrefix === '' || usePrefix === '/') return true;
  if (!routePattern) return false;
  const p = usePrefix.replace(/\/+$/, '');
  if (routePattern === p) return true;
  return routePattern.startsWith(`${p}/`);
}

/** 1-based inclusive span of any tree-sitter node (Core Semantics 6 line convention). */
export function spanOfNode(node: Node): HandlerSpan {
  return {
    startLine: node.startPosition.row + 1,
    endLine: node.endPosition.row + 1,
  };
}

/** Containment test: `startLine <= line <= endLine` (both 1-based). */
export function spanContains(span: HandlerSpan | null | undefined, line: number): boolean {
  if (!span) return false;
  return span.startLine <= line && line <= span.endLine;
}

/**
 * Classify a single route from its gathered evidence (Sem 1-5, 8, 10).
 *
 * Precedence: explicit-public override → optional-veto → machine/internal
 * verifier → valid auth evidence (subject to conditional + belt) → public.
 */
export function classifyRoute(evidence: RouteAuthEvidence): {
  classification: EntryPointClassification;
  authenticated: boolean;
  authMechanism: string | null;
} {
  const publicResult = { classification: 'PUBLIC_UNAUTH' as const, authenticated: false, authMechanism: null };

  // Sem 2 — explicit-public overrides always win.
  if ((evidence.publicOverrides ?? []).some(matchesPublicOverride)) {
    return publicResult;
  }

  // Sem 5 — verifier / internal-key evidence → background surface. (Machine
  // endpoints take precedence over user auth: a signed webhook is not
  // user-facing attack surface even if it also runs an auth check.)
  const internalHit = (evidence.internalTokens ?? []).find(
    (t) => matchesInternalName(t) || /\.verify\b/i.test(t) || /construct_?event/i.test(t),
  );
  if (internalHit) {
    return { classification: 'OFFLINE_WORKER', authenticated: true, authMechanism: 'signature' };
  }

  // Sem 4 + 8 — a valid auth token is one that matches an auth-name pattern and
  // is NOT optional-vetoed. Vetted tokens (exact annotation semantics) skip the
  // name matching. The caller's `optional` flag (arg inspection) disqualifies
  // both kinds.
  const validAuthTokens = (evidence.authTokens ?? []).filter(
    (t) => matchesAuthName(t) && !isOptionalVetoed(t),
  );
  const hasAuth = (validAuthTokens.length > 0 || (evidence.vettedAuthTokens ?? []).length > 0)
    && !evidence.optional;

  if (!hasAuth) return publicResult;

  // Sem 3 — conditional / carve-out coverage does not cover.
  if (evidence.conditional) return publicResult;

  // Sem 10 — a purely-centralized demotion is blocked on belt routes.
  if (evidence.centralizedOnly && matchesPublicRouteBelt(evidence.routePattern)) {
    return publicResult;
  }

  return { classification: 'AUTH_INTERNAL', authenticated: true, authMechanism: 'route_evidence' };
}
