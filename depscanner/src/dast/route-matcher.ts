// Phase 23b PR 3: framework-aware route normalizer for DAST cross-link.
//
// ZAP findings come back with concrete URLs (e.g. `/users/42/posts`); the
// reachability stack populates `project_entry_points.route_pattern` with
// per-framework patterns (e.g. `/users/:id/posts` for Express, `/users/{id}/posts`
// for FastAPI). The cross-linker matches a concrete URL against a route pattern
// to populate handler_file_path / handler_function_name on the DAST finding,
// which then unlocks the SCA join via project_reachable_flows.
//
// Eight frameworks supported in v1: express, fastify, fastapi, spring, rails,
// gin, sinatra, laravel. Other frameworks logged in cross_link_metadata fall
// through to a permissive literal-segment match (no false positives — only an
// exact-string match wins for unknown frameworks).

export type SupportedFramework =
  | 'express'
  | 'fastify'
  | 'fastapi'
  | 'spring'
  | 'rails'
  | 'gin'
  | 'sinatra'
  | 'laravel';

const SUPPORTED_FRAMEWORKS = new Set<SupportedFramework>([
  'express',
  'fastify',
  'fastapi',
  'spring',
  'rails',
  'gin',
  'sinatra',
  'laravel',
]);

export function isSupportedFramework(framework: string): framework is SupportedFramework {
  return SUPPORTED_FRAMEWORKS.has(framework as SupportedFramework);
}

function escapeLiteral(segment: string): string {
  return segment.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

// Strip a leading scheme+host (`https://staging.example.com/api/users` →
// `/api/users`). For URLs we also drop ?query and #hash; for patterns those
// characters are syntactic (Laravel `{slug?}`) so callers pass `kind='pattern'`.
function pathOnly(input: string, kind: 'url' | 'pattern' = 'url'): string {
  if (!input) return input;
  let cleaned = input;
  if (kind === 'url') {
    const queryIdx = cleaned.indexOf('?');
    if (queryIdx >= 0) cleaned = cleaned.slice(0, queryIdx);
    const hashIdx = cleaned.indexOf('#');
    if (hashIdx >= 0) cleaned = cleaned.slice(0, hashIdx);
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(cleaned)) {
    try {
      const u = new URL(cleaned);
      return u.pathname || '/';
    } catch {
      // fall through to raw cleaned value
    }
  }
  return cleaned.startsWith('/') ? cleaned : `/${cleaned}`;
}

// Normalize trailing slashes — treat `/users/` and `/users` as the same path.
// Empty path ('') and root ('/') both map to '/'.
function trimTrailingSlash(p: string): string {
  if (p.length <= 1) return p;
  return p.endsWith('/') ? p.slice(0, -1) : p;
}

// Per-framework segment compiler. Returns a list of segment regex fragments
// that, joined by '/', form the per-framework body of the matcher.
function compileSegments(framework: SupportedFramework, pattern: string): string[] {
  const path = trimTrailingSlash(pathOnly(pattern, 'pattern'));
  const segments = path.split('/').slice(1);
  return segments.map((seg) => compileSegment(framework, seg));
}

function compileSegment(framework: SupportedFramework, segment: string): string {
  if (segment === '') return '';

  // Express / Fastify: `:name`, `:name?`, `:name(regex)`
  if (framework === 'express' || framework === 'fastify') {
    if (segment === '*') return '.*';
    return compileExpressLikeSegment(segment);
  }

  // Sinatra: `:name`, `*splat`, mixed segments like `:title.:format?`
  if (framework === 'sinatra') {
    if (segment === '*') return '.*';
    return compileSinatraSegment(segment);
  }

  // Rails: `:name`, `*splat`, `:name.:format`
  if (framework === 'rails') {
    if (segment.startsWith('*')) return '.*';
    return compileRailsSegment(segment);
  }

  // Gin: `:name`, `*action` (only valid as last segment, but we handle it greedily)
  if (framework === 'gin') {
    if (segment.startsWith('*')) return '.*';
    if (segment.startsWith(':')) return '[^/]+';
    return escapeLiteral(segment);
  }

  // FastAPI / Spring / Laravel: `{name}`, `{name:type}`, Laravel `{name?}`
  if (framework === 'fastapi' || framework === 'spring' || framework === 'laravel') {
    return compileBraceSegment(segment);
  }

  return escapeLiteral(segment);
}

// Express/Fastify: a segment may contain text + one-or-more `:name(...)?` params.
// `/users/:userId` → `[^/]+`
// `/users-:userId` → `users-[^/]+`
// `/files/:name(\\d+)` → `\\d+` (we keep the user-supplied regex)
// `/users/:userId?` → `[^/]+` (we collapse optional trailing in matcher logic)
function compileExpressLikeSegment(segment: string): string {
  let out = '';
  let i = 0;
  while (i < segment.length) {
    if (segment[i] === ':') {
      let j = i + 1;
      // capture name
      while (j < segment.length && /[A-Za-z0-9_]/.test(segment[j])) j++;
      // capture optional regex group
      let paramRegex: string | null = null;
      if (segment[j] === '(') {
        let depth = 1;
        const start = j + 1;
        let k = start;
        while (k < segment.length && depth > 0) {
          if (segment[k] === '\\' && k + 1 < segment.length) {
            k += 2;
            continue;
          }
          if (segment[k] === '(') depth++;
          else if (segment[k] === ')') depth--;
          if (depth > 0) k++;
        }
        if (depth === 0) {
          paramRegex = segment.slice(start, k);
          j = k + 1;
        }
      }
      // optional `?`
      if (segment[j] === '?') j++;
      out += paramRegex ?? '[^/]+';
      i = j;
    } else {
      // literal char up until next ':'
      const colonAt = segment.indexOf(':', i);
      const literalEnd = colonAt < 0 ? segment.length : colonAt;
      out += escapeLiteral(segment.slice(i, literalEnd));
      i = literalEnd;
    }
  }
  return out;
}

// Sinatra: similar to Express but with `:name` only (no parens-regex), plus
// optional segments like `:format?` mid-string. We treat `?` as making the
// param optional within the segment (matches anywhere from 0+).
function compileSinatraSegment(segment: string): string {
  let out = '';
  let i = 0;
  while (i < segment.length) {
    if (segment[i] === ':') {
      let j = i + 1;
      while (j < segment.length && /[A-Za-z0-9_]/.test(segment[j])) j++;
      const optional = segment[j] === '?';
      if (optional) j++;
      out += optional ? '[^/]*' : '[^/]+';
      i = j;
    } else {
      const colonAt = segment.indexOf(':', i);
      const literalEnd = colonAt < 0 ? segment.length : colonAt;
      out += escapeLiteral(segment.slice(i, literalEnd));
      i = literalEnd;
    }
  }
  return out;
}

// Rails: `:name` only, plus segment-internal mixes like `:resource.:format`.
function compileRailsSegment(segment: string): string {
  let out = '';
  let i = 0;
  while (i < segment.length) {
    if (segment[i] === ':') {
      let j = i + 1;
      while (j < segment.length && /[A-Za-z0-9_]/.test(segment[j])) j++;
      out += '[^/.]+';
      i = j;
    } else {
      const colonAt = segment.indexOf(':', i);
      const literalEnd = colonAt < 0 ? segment.length : colonAt;
      out += escapeLiteral(segment.slice(i, literalEnd));
      i = literalEnd;
    }
  }
  return out;
}

// FastAPI / Spring / Laravel: `{name}`, `{name:type}`, Laravel-only `{name?}`.
// FastAPI type hints (`int`, `str`, `path`, `uuid`, `float`, `bool`) map to
// permissive regexes; Spring users supply raw regexes (e.g. `[0-9]+`); Laravel
// uses `{name?}` for optionality. The type-hint map covers FastAPI defaults.
const FASTAPI_TYPE_HINTS: Record<string, string> = {
  int: '[0-9]+',
  float: '[0-9]+(\\.[0-9]+)?',
  str: '[^/]+',
  bool: '(true|false|0|1)',
  path: '.+',
  uuid: '[0-9a-fA-F-]+',
};

function compileBraceSegment(segment: string): string {
  let out = '';
  let i = 0;
  while (i < segment.length) {
    if (segment[i] === '{') {
      const close = segment.indexOf('}', i);
      if (close < 0) {
        out += escapeLiteral(segment.slice(i));
        break;
      }
      const inside = segment.slice(i + 1, close);
      const colonAt = inside.indexOf(':');
      let paramRegex: string | null = null;
      if (colonAt >= 0) {
        const trailing = inside.slice(colonAt + 1).trim();
        if (trailing && trailing !== '?') {
          // FastAPI-style type-hint name (lowercase identifier) → known regex.
          // Anything else is treated as a Spring-style raw regex.
          if (FASTAPI_TYPE_HINTS[trailing]) {
            paramRegex = FASTAPI_TYPE_HINTS[trailing];
          } else {
            paramRegex = trailing;
          }
        }
      }
      out += paramRegex ?? '[^/]+';
      i = close + 1;
    } else {
      const braceAt = segment.indexOf('{', i);
      const literalEnd = braceAt < 0 ? segment.length : braceAt;
      out += escapeLiteral(segment.slice(i, literalEnd));
      i = literalEnd;
    }
  }
  return out;
}

/**
 * Compile a framework-specific route pattern into a RegExp anchored at start
 * and end. Supports the eight frameworks the v1 cross-linker handles. Returns
 * null when the framework isn't supported (caller falls back to exact match).
 */
export function normalizeRoute(framework: string, pattern: string): RegExp | null {
  if (!isSupportedFramework(framework)) return null;
  const segments = compileSegments(framework, pattern);
  if (segments.length === 0) return new RegExp('^/$');

  // Trailing wildcard segment: make the leading `/` optional so `/foo/*`
  // matches `/foo` (trailing-slash stripped) AND `/foo/anything`.
  const lastIdx = segments.length - 1;
  const lastIsWildcard = segments[lastIdx] === '.*';
  const head = segments.slice(0, lastIdx).join('/');
  if (lastIsWildcard) {
    const headPart = head.length > 0 ? `/${head}` : '';
    return new RegExp(`^${headPart}(?:/.*)?$`);
  }

  const body = segments.join('/');
  return new RegExp(`^/${body}$`);
}

/**
 * Match a concrete URL (or path) emitted by ZAP against a per-framework
 * route pattern. Returns false when framework is unsupported but pattern
 * doesn't exact-match the URL path either.
 */
export function matchRoute(zapUrl: string, pattern: string, framework: string): boolean {
  const url = trimTrailingSlash(pathOnly(zapUrl));

  if (!isSupportedFramework(framework)) {
    // Unsupported framework: only an exact string match is safe (no false positives).
    const cleanedPattern = trimTrailingSlash(pathOnly(pattern));
    return url === cleanedPattern;
  }

  const re = normalizeRoute(framework, pattern);
  if (!re) return false;
  return re.test(url);
}
