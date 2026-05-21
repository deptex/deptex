// Phase 35 (v1.1) — table-driven per-framework path-translator tests.
//
// Test shape (locked — adding a framework appends rows; DO NOT switch to
// toMatchSnapshot per the dast-yaml-builder.test.ts convention):
//   const cases: Array<{ name, framework, in, outPath, outParams? }>
//   describe.each(cases.map((c) => [c.name, c]))('%s', (_, c) => { ... })
//
// Each framework needs ≥5 cases covering: required, optional, wildcard /
// catch-all, regex-constrained, multi-method (handled at synth-level not
// translator-level), operationId collision (handled at synth-level), and
// duplicate-collapse (handled at synth-level).

import {
  translatePathPattern,
  type PathParamMeta,
} from '../dast/openapi-path-translate';

interface Case {
  name: string;
  framework: string;
  in: string;
  outPath: string;
  outParams?: Array<Partial<PathParamMeta> & { name: string }>;
}

const cases: Case[] = [
  // ─── Express ────────────────────────────────────────────────────────────
  { name: 'express: static path', framework: 'express', in: '/health', outPath: '/health', outParams: [] },
  {
    name: 'express: single param',
    framework: 'express',
    in: '/users/:id',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'express: multiple params',
    framework: 'express',
    in: '/users/:userId/posts/:postId',
    outPath: '/users/{userId}/posts/{postId}',
    outParams: [{ name: 'userId' }, { name: 'postId' }],
  },
  {
    name: 'express: wildcard catch-all',
    framework: 'express',
    in: '/files/:path*',
    outPath: '/files/{path}',
    outParams: [{ name: 'path', wildcard: true }],
  },
  {
    name: 'express: param mid-segment',
    framework: 'express',
    in: '/api/v1/users/:id/profile',
    outPath: '/api/v1/users/{id}/profile',
    outParams: [{ name: 'id' }],
  },

  // ─── Fastify (same syntax as Express) ───────────────────────────────────
  {
    name: 'fastify: single param',
    framework: 'fastify',
    in: '/orgs/:org',
    outPath: '/orgs/{org}',
    outParams: [{ name: 'org' }],
  },
  {
    name: 'fastify: nested params',
    framework: 'fastify',
    in: '/teams/:teamId/members/:memberId',
    outPath: '/teams/{teamId}/members/{memberId}',
    outParams: [{ name: 'teamId' }, { name: 'memberId' }],
  },

  // ─── Flask ──────────────────────────────────────────────────────────────
  {
    name: 'flask: typed int param',
    framework: 'flask',
    in: '/users/<int:id>',
    outPath: '/users/{id}',
    outParams: [{ name: 'id', schema: { type: 'integer' } }],
  },
  {
    name: 'flask: typed float param',
    framework: 'flask',
    in: '/temp/<float:value>',
    outPath: '/temp/{value}',
    outParams: [{ name: 'value', schema: { type: 'number' } }],
  },
  {
    name: 'flask: path wildcard',
    framework: 'flask',
    in: '/files/<path:rest>',
    outPath: '/files/{rest}',
    outParams: [{ name: 'rest', schema: { type: 'string' }, wildcard: true }],
  },
  {
    name: 'flask: untyped param',
    framework: 'flask',
    in: '/posts/<slug>',
    outPath: '/posts/{slug}',
    outParams: [{ name: 'slug', schema: { type: 'string' } }],
  },
  {
    name: 'flask: uuid param',
    framework: 'flask',
    in: '/objects/<uuid:oid>',
    outPath: '/objects/{oid}',
    outParams: [{ name: 'oid', schema: { type: 'string' } }],
  },

  // ─── FastAPI ────────────────────────────────────────────────────────────
  {
    name: 'fastapi: brace param',
    framework: 'fastapi',
    in: '/users/{id}',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'fastapi: multiple braces',
    framework: 'fastapi',
    in: '/users/{user_id}/files/{file_id}',
    outPath: '/users/{user_id}/files/{file_id}',
    outParams: [{ name: 'user_id' }, { name: 'file_id' }],
  },
  {
    name: 'fastapi: trailing slash preserved',
    framework: 'fastapi',
    in: '/users/{id}/',
    outPath: '/users/{id}/',
    outParams: [{ name: 'id' }],
  },

  // ─── Django ─────────────────────────────────────────────────────────────
  {
    name: 'django: typed int + trailing slash trimmed',
    framework: 'django',
    in: '/users/<int:id>/',
    outPath: '/users/{id}',
    outParams: [{ name: 'id', schema: { type: 'integer' } }],
  },
  {
    name: 'django: slug typed param',
    framework: 'django',
    in: '/posts/<slug:slug>/',
    outPath: '/posts/{slug}',
    outParams: [{ name: 'slug', schema: { type: 'string' } }],
  },
  {
    name: 'django: path wildcard + trailing slash',
    framework: 'django',
    in: '/files/<path:rest>/',
    outPath: '/files/{rest}',
    outParams: [{ name: 'rest', schema: { type: 'string' }, wildcard: true }],
  },
  {
    name: 'django: static no trailing slash',
    framework: 'django',
    in: '/admin',
    outPath: '/admin',
    outParams: [],
  },

  // ─── Spring ─────────────────────────────────────────────────────────────
  {
    name: 'spring: brace param',
    framework: 'spring',
    in: '/users/{id}',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'spring: regex int constraint',
    framework: 'spring',
    in: '/users/{id:\\d+}',
    outPath: '/users/{id}',
    outParams: [{ name: 'id', schema: { type: 'integer' }, pattern: '\\d+' }],
  },
  {
    name: 'spring: regex string constraint',
    framework: 'spring',
    in: '/items/{slug:[a-z0-9-]+}',
    outPath: '/items/{slug}',
    outParams: [{ name: 'slug', schema: { type: 'string' }, pattern: '[a-z0-9-]+' }],
  },
  {
    name: 'spring: multiple params, mixed types',
    framework: 'spring',
    in: '/orgs/{orgId:\\d+}/teams/{slug}',
    outPath: '/orgs/{orgId}/teams/{slug}',
    outParams: [
      { name: 'orgId', schema: { type: 'integer' }, pattern: '\\d+' },
      { name: 'slug' },
    ],
  },

  // ─── Gin ────────────────────────────────────────────────────────────────
  {
    name: 'gin: colon param',
    framework: 'gin',
    in: '/users/:id',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'gin: catch-all wildcard',
    framework: 'gin',
    in: '/files/*action',
    outPath: '/files/{action}',
    outParams: [{ name: 'action', wildcard: true }],
  },
  {
    name: 'gin: mixed colon + catch-all',
    framework: 'gin',
    in: '/orgs/:org/files/*name',
    outPath: '/orgs/{org}/files/{name}',
    // Note: catch-all is consumed first (handled before colons), so its
    // metadata appears earlier in the params array than its path position.
    // Synth-level emission re-uses these metadata entries by name, not
    // index, so order doesn't matter for OpenAPI correctness.
    outParams: [{ name: 'name', wildcard: true }, { name: 'org' }],
  },
  {
    name: 'gin: nested colon params',
    framework: 'gin',
    in: '/users/:userId/posts/:postId',
    outPath: '/users/{userId}/posts/{postId}',
    outParams: [{ name: 'userId' }, { name: 'postId' }],
  },

  // ─── Rails ──────────────────────────────────────────────────────────────
  {
    name: 'rails: simple colon param',
    framework: 'rails',
    in: '/users/:id',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'rails: drops (.:format)',
    framework: 'rails',
    in: '/users/:id(.:format)',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'rails: drops other optional segments',
    framework: 'rails',
    in: '/users/:id(/edit)',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'rails: nested resource',
    framework: 'rails',
    in: '/posts/:post_id/comments/:id(.:format)',
    outPath: '/posts/{post_id}/comments/{id}',
    outParams: [{ name: 'post_id' }, { name: 'id' }],
  },

  // ─── Fallback (tail framework — koa) ────────────────────────────────────
  {
    name: 'fallback: koa colon param translated permissively',
    framework: 'koa',
    in: '/users/:id',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'fallback: hono brace param translated permissively',
    framework: 'hono',
    in: '/users/{id}',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'fallback: laravel optional param translated permissively',
    framework: 'laravel',
    in: '/users/{id}',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
  {
    name: 'fallback: aspnet-core typed param maps name only',
    framework: 'aspnet-core',
    in: '/users/{id:int}',
    outPath: '/users/{id}',
    outParams: [{ name: 'id' }],
  },
];

describe('translatePathPattern (8 v1.1 frameworks + permissive fallback)', () => {
  test.each(cases.map((c) => [c.name, c]))('%s', (_name, c) => {
    const out = translatePathPattern(c.framework, c.in);
    expect(out.openApiPath).toBe(c.outPath);

    if (c.outParams) {
      expect(out.params).toHaveLength(c.outParams.length);
      for (let i = 0; i < c.outParams.length; i++) {
        const expected = c.outParams[i];
        const actual = out.params[i];
        expect(actual.name).toBe(expected.name);
        if (expected.schema?.type) expect(actual.schema.type).toBe(expected.schema.type);
        else expect(actual.schema.type).toBe('string');
        if (expected.pattern) expect(actual.pattern).toBe(expected.pattern);
        if (expected.wildcard) expect(actual.wildcard).toBe(true);
      }
    }
  });

  it('returns empty translation for an empty route pattern', () => {
    const out = translatePathPattern('express', '');
    expect(out.openApiPath).toBe('');
    expect(out.params).toEqual([]);
  });
});
