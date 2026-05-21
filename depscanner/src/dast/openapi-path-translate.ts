// Phase 35 (v1.1) — per-framework route-pattern → OpenAPI path translator.
//
// 8 frameworks ship in v1.1: express, fastify, flask, fastapi, django,
// spring, gin, rails. The 12 tail frameworks (echo / fiber / chi / koa /
// hono / laravel / symfony / sinatra / aspnet-core / axum / actix / rocket)
// route through the permissive fallback — recognized syntaxes :name / {name}
// / <type:name> still translate; anything truly exotic passes through.
//
// Adding a framework: add a case to translatePathPattern; add a row block
// to depscanner/src/__tests__/dast-openapi-path-translate.test.ts. Test
// shape: `const cases: Array<{ name, framework, in, outPath, outParams }>`
// — table-driven via describe.each. Do NOT use toMatchSnapshot (matches
// the dast-yaml-builder.test.ts convention).

export type V11Framework =
  | 'express' | 'fastify' | 'flask' | 'fastapi'
  | 'django' | 'spring' | 'gin' | 'rails';

export const V11_FRAMEWORKS: ReadonlySet<string> = new Set<V11Framework>([
  'express', 'fastify', 'flask', 'fastapi', 'django', 'spring', 'gin', 'rails',
]);

export type OpenApiParamType = 'string' | 'integer' | 'number';

export interface PathParamMeta {
  name: string;
  in: 'path';
  required: boolean;
  schema: { type: OpenApiParamType };
  /** OpenAPI `pattern` constraint (e.g. Spring `{id:\d+}` → '\d+'). */
  pattern?: string;
  /**
   * Express `:path*` / Gin `*path` / Flask `<path:rest>` style catch-all.
   * OpenAPI doesn't have a native wildcard concept; we emit the param as
   * a normal string + record the wildcard intent via `x-deptex-wildcard`.
   */
  wildcard?: boolean;
}

export interface TranslatedPath {
  /** OpenAPI-shaped path with `{param}` templates. */
  openApiPath: string;
  /** Per-param metadata in path-occurrence order. */
  params: PathParamMeta[];
}

function pathParam(
  name: string,
  opts: {
    type?: OpenApiParamType;
    pattern?: string;
    wildcard?: boolean;
    required?: boolean;
  } = {},
): PathParamMeta {
  return {
    name,
    in: 'path',
    required: opts.required ?? true,
    schema: { type: opts.type ?? 'string' },
    ...(opts.pattern ? { pattern: opts.pattern } : {}),
    ...(opts.wildcard ? { wildcard: true } : {}),
  };
}

// Express / Fastify: `:name` and `:name*` (wildcard).
function expressLike(routePattern: string): TranslatedPath {
  const params: PathParamMeta[] = [];
  const out = routePattern.replace(
    /:([A-Za-z_][A-Za-z0-9_]*)(\*)?/g,
    (_m, name: string, star: string | undefined) => {
      params.push(pathParam(name, { wildcard: Boolean(star) }));
      return `{${name}}`;
    },
  );
  return { openApiPath: out, params };
}

// Gin: `:id` colon params PLUS `*action` catch-all. The catch-all goes
// first so `*` doesn't get consumed by a regex that would also match `:` alone.
function ginTranslate(routePattern: string): TranslatedPath {
  const params: PathParamMeta[] = [];
  let s = routePattern.replace(
    /\*([A-Za-z_][A-Za-z0-9_]*)/g,
    (_m, name: string) => {
      params.push(pathParam(name, { wildcard: true }));
      return `{${name}}`;
    },
  );
  s = s.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, (_m, name: string) => {
    params.push(pathParam(name));
    return `{${name}}`;
  });
  return { openApiPath: s, params };
}

const FLASK_TYPE_MAP: Record<string, OpenApiParamType> = {
  int: 'integer',
  float: 'number',
  path: 'string',
  uuid: 'string',
  string: 'string',
  default: 'string',
};

// Flask: `<type:name>` or `<name>`. Types: int, float, path, uuid, string, default.
function flaskTranslate(routePattern: string): TranslatedPath {
  const params: PathParamMeta[] = [];
  const out = routePattern.replace(
    /<(?:([A-Za-z_]+):)?([A-Za-z_][A-Za-z0-9_]*)>/g,
    (_m, type: string | undefined, name: string) => {
      const t = type ? FLASK_TYPE_MAP[type] ?? 'string' : 'string';
      const wildcard = type === 'path';
      params.push(pathParam(name, { type: t, wildcard }));
      return `{${name}}`;
    },
  );
  return { openApiPath: out, params };
}

// Django path(): same `<type:name>` syntax as Flask. Drop trailing slash for
// OpenAPI consistency (Django apps frequently emit `/users/<id>/`).
function djangoTranslate(routePattern: string): TranslatedPath {
  const t = flaskTranslate(routePattern);
  const trimmed = t.openApiPath.length > 1 ? t.openApiPath.replace(/\/$/, '') : t.openApiPath;
  return { openApiPath: trimmed, params: t.params };
}

// Spring: `{id}` with optional `{id:regex}` constraint. We infer integer
// type for the canonical digit regex \d+.
function springTranslate(routePattern: string): TranslatedPath {
  const params: PathParamMeta[] = [];
  const out = routePattern.replace(
    /\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]+))?\}/g,
    (_m, name: string, pattern: string | undefined) => {
      let type: OpenApiParamType = 'string';
      if (pattern && /^\\d\+?$|^\\d\{\d+(?:,\d*)?\}$/.test(pattern)) {
        type = 'integer';
      }
      params.push(pathParam(name, { type, ...(pattern ? { pattern } : {}) }));
      return `{${name}}`;
    },
  );
  return { openApiPath: out, params };
}

// FastAPI: `{id}` already OpenAPI-shaped. Python type hints in the function
// signature drive parameter types in real FastAPI specs; we don't have access
// to them here, so default to string.
function fastApiTranslate(routePattern: string): TranslatedPath {
  const params: PathParamMeta[] = [];
  const out = routePattern.replace(
    /\{([A-Za-z_][A-Za-z0-9_]*)\}/g,
    (_m, name: string) => {
      params.push(pathParam(name));
      return `{${name}}`;
    },
  );
  return { openApiPath: out, params };
}

// Rails: `:id` like Express. Optional `(.:format)` group is dropped — and
// any other Rails optional `(...)` segments are also dropped (rare; keeps
// the resulting OpenAPI path valid). Constraints like `:id(/show)` are
// uncommon and survive the simple drop.
function railsTranslate(routePattern: string): TranslatedPath {
  let s = routePattern.replace(/\(\.:format\)/g, '');
  s = s.replace(/\(([^)]*)\)/g, '');
  return expressLike(s);
}

// Permissive fallback for tail frameworks. Recognizes :name, {name}, <name>,
// <type:name> — covers most of the 12 deferred frameworks well enough to
// produce a valid OpenAPI path. Type info defaults to string; wildcards
// aren't inferred for tail frameworks (out of v1.1 scope).
function fallbackTranslate(routePattern: string): TranslatedPath {
  const params: PathParamMeta[] = [];
  const out = routePattern.replace(
    /:([A-Za-z_][A-Za-z0-9_]*)\*?|\{([^}/]+)\}|<(?:([A-Za-z_]+):)?([A-Za-z_][A-Za-z0-9_]*)>/g,
    (_m, colonName, braceName, angleType, angleName) => {
      const rawName = colonName ?? braceName ?? angleName;
      const name = String(rawName).replace(/:.*$/, '');
      const type = angleType && FLASK_TYPE_MAP[angleType] ? FLASK_TYPE_MAP[angleType] : 'string';
      params.push(pathParam(name, { type }));
      return `{${name}}`;
    },
  );
  return { openApiPath: out, params };
}

export function translatePathPattern(
  framework: string,
  routePattern: string,
): TranslatedPath {
  if (!routePattern) return { openApiPath: '', params: [] };
  switch (framework) {
    case 'express':
    case 'fastify':
      return expressLike(routePattern);
    case 'gin':
      return ginTranslate(routePattern);
    case 'flask':
      return flaskTranslate(routePattern);
    case 'django':
      return djangoTranslate(routePattern);
    case 'spring':
      return springTranslate(routePattern);
    case 'fastapi':
      return fastApiTranslate(routePattern);
    case 'rails':
      return railsTranslate(routePattern);
    default:
      return fallbackTranslate(routePattern);
  }
}
