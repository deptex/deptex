// Phase 35 (v1.1) — synthesizer behavioral tests.
//
// Structural assertions (NOT snapshots) per the
// dast-yaml-builder.test.ts:4 convention.

import * as yaml from 'js-yaml';
import { synthesizeOpenApi } from '../dast/openapi-synth';
import type { EntryPointRow } from '../dast/cross-link';

function ep(overrides: Partial<EntryPointRow>): EntryPointRow {
  return {
    framework: 'express',
    http_method: 'GET',
    route_pattern: '/users/:id',
    handler_name: 'getUser',
    file_path: 'src/users.ts',
    line_number: 42,
    entry_point_type: 'http_route',
    classification: 'PUBLIC_UNAUTH',
    ...overrides,
  };
}

describe('synthesizeOpenApi', () => {
  describe('filters', () => {
    it('returns empty result when entry_points is empty', () => {
      const out = synthesizeOpenApi([], { targetUrl: 'https://api.example.com' });
      expect(out.yaml).toBeNull();
      expect(out.sidecar).toBeNull();
      expect(out.endpoint_count).toBe(0);
    });

    it('drops entry_point_type !== http_route', () => {
      const out = synthesizeOpenApi(
        [
          ep({ entry_point_type: 'graphql_resolver' }),
          ep({ entry_point_type: 'websocket' }),
          ep({ entry_point_type: 'message_handler' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      expect(out.endpoint_count).toBe(0);
    });

    it('scans an http_route OFFLINE_WORKER (webhook) but drops a non-http OFFLINE_WORKER', () => {
      const out = synthesizeOpenApi(
        [
          // signature-verified webhook — real external HTTP surface → scanned
          ep({ classification: 'OFFLINE_WORKER', route_pattern: '/webhooks/stripe', http_method: 'POST', handler_name: 'stripeWebhook' }),
          // genuine background handler (non-http_route) → dropped
          ep({ classification: 'OFFLINE_WORKER', entry_point_type: 'message_handler', route_pattern: '/queue/process' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      expect(out.endpoint_count).toBe(1);
    });

    it('drops health-probe paths (case-insensitive)', () => {
      const out = synthesizeOpenApi(
        [
          ep({ route_pattern: '/health' }),
          ep({ route_pattern: '/Healthz' }),
          ep({ route_pattern: '/livez' }),
          ep({ route_pattern: '/_status' }),
          ep({ route_pattern: '/readyz' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      expect(out.endpoint_count).toBe(0);
    });

    it('drops entries with no route_pattern or invalid http_method', () => {
      const out = synthesizeOpenApi(
        [
          ep({ route_pattern: null }),
          ep({ http_method: null }),
          ep({ http_method: 'BREW' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      expect(out.endpoint_count).toBe(0);
    });
  });

  describe('emission', () => {
    it('emits OpenAPI 3.1.0 doc with servers.url', () => {
      const out = synthesizeOpenApi([ep({})], { targetUrl: 'https://api.example.com' });
      expect(out.yaml).not.toBeNull();
      const parsed = yaml.load(out.yaml!) as Record<string, unknown>;
      expect(parsed.openapi).toBe('3.1.0');
      expect((parsed.servers as Array<{ url: string }>)[0].url).toBe('https://api.example.com');
    });

    it('emits one operation per http_route entry point', () => {
      const out = synthesizeOpenApi(
        [
          ep({ route_pattern: '/users', http_method: 'GET' }),
          ep({ route_pattern: '/users', http_method: 'POST', handler_name: 'createUser' }),
          ep({ route_pattern: '/users/:id', http_method: 'PATCH', handler_name: 'updateUser' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      expect(out.endpoint_count).toBe(3);
      const parsed = yaml.load(out.yaml!) as { paths: Record<string, Record<string, unknown>> };
      expect(parsed.paths['/users'].get).toBeDefined();
      expect(parsed.paths['/users'].post).toBeDefined();
      expect(parsed.paths['/users/{id}'].patch).toBeDefined();
    });

    it('writes sidecar keyed by `${METHOD} ${openApiPath}` with handler attribution', () => {
      const out = synthesizeOpenApi(
        [ep({ route_pattern: '/users/:id', file_path: 'src/handlers/users.ts', line_number: 99, handler_name: 'getUser' })],
        { targetUrl: 'https://api.example.com' },
      );
      expect(out.sidecar).not.toBeNull();
      expect(out.sidecar!['GET /users/{id}']).toEqual({
        file_path: 'src/handlers/users.ts',
        function_name: 'getUser',
        line_number: 99,
      });
    });

    it('emits x-deptex-handler extension on every operation', () => {
      const out = synthesizeOpenApi(
        [ep({ file_path: 'src/u.ts', handler_name: 'h', line_number: 7 })],
        { targetUrl: 'https://api.example.com' },
      );
      const parsed = yaml.load(out.yaml!) as { paths: Record<string, Record<string, Record<string, unknown>>> };
      const op = parsed.paths['/users/{id}'].get;
      expect(op['x-deptex-handler']).toEqual({
        file_path: 'src/u.ts',
        function_name: 'h',
        line_number: 7,
      });
    });

    it('emits requestBody for POST/PUT/PATCH but not for GET/DELETE/HEAD/OPTIONS', () => {
      const out = synthesizeOpenApi(
        [
          ep({ http_method: 'POST', route_pattern: '/a' }),
          ep({ http_method: 'PUT', route_pattern: '/b' }),
          ep({ http_method: 'PATCH', route_pattern: '/c' }),
          ep({ http_method: 'GET', route_pattern: '/d' }),
          ep({ http_method: 'DELETE', route_pattern: '/e' }),
          ep({ http_method: 'HEAD', route_pattern: '/f' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      const parsed = yaml.load(out.yaml!) as { paths: Record<string, Record<string, Record<string, unknown>>> };
      expect(parsed.paths['/a'].post.requestBody).toBeDefined();
      expect(parsed.paths['/b'].put.requestBody).toBeDefined();
      expect(parsed.paths['/c'].patch.requestBody).toBeDefined();
      expect(parsed.paths['/d'].get.requestBody).toBeUndefined();
      expect(parsed.paths['/e'].delete.requestBody).toBeUndefined();
      expect(parsed.paths['/f'].head.requestBody).toBeUndefined();
    });

    it('emits parameters for path params with type info', () => {
      const out = synthesizeOpenApi(
        [
          ep({ framework: 'flask', route_pattern: '/users/<int:id>', http_method: 'GET' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      const parsed = yaml.load(out.yaml!) as { paths: Record<string, Record<string, Record<string, unknown>>> };
      const op = parsed.paths['/users/{id}'].get as Record<string, unknown>;
      expect(op.parameters).toEqual([
        { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
      ]);
    });

    it('emits x-deptex-middleware extension when middleware_chain present', () => {
      const out = synthesizeOpenApi(
        [ep({ middleware_chain: ['authMiddleware', 'rateLimit'] })],
        { targetUrl: 'https://api.example.com' },
      );
      const parsed = yaml.load(out.yaml!) as { paths: Record<string, Record<string, Record<string, unknown>>> };
      const op = parsed.paths['/users/{id}'].get;
      expect(op['x-deptex-middleware']).toEqual(['authMiddleware', 'rateLimit']);
    });

    it('emits components.securitySchemes when auth_mechanism is set', () => {
      const out = synthesizeOpenApi(
        [ep({ auth_mechanism: 'bearer_jwt' })],
        { targetUrl: 'https://api.example.com' },
      );
      const parsed = yaml.load(out.yaml!) as {
        components: { securitySchemes: Record<string, Record<string, unknown>> };
        paths: Record<string, Record<string, Record<string, unknown>>>;
      };
      expect(parsed.components.securitySchemes.deptexAuth).toEqual({
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      });
      expect(parsed.paths['/users/{id}'].get.security).toEqual([{ deptexAuth: [] }]);
    });

    it('maps cookie auth mechanism to apiKey-in-cookie scheme', () => {
      const out = synthesizeOpenApi(
        [ep({ auth_mechanism: 'session_cookie' })],
        { targetUrl: 'https://api.example.com' },
      );
      const parsed = yaml.load(out.yaml!) as { components: { securitySchemes: { deptexAuth: Record<string, unknown> } } };
      expect(parsed.components.securitySchemes.deptexAuth).toEqual({
        type: 'apiKey',
        in: 'cookie',
        name: 'session',
      });
    });
  });

  describe('de-duplication and operationId', () => {
    it('de-dupes (method, path) collisions; first wins', () => {
      const out = synthesizeOpenApi(
        [
          ep({ route_pattern: '/users/:id', file_path: 'src/a.ts', line_number: 10, handler_name: 'first' }),
          ep({ route_pattern: '/users/:id', file_path: 'src/b.ts', line_number: 20, handler_name: 'second' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      expect(out.endpoint_count).toBe(1);
      expect(out.sidecar!['GET /users/{id}'].file_path).toBe('src/a.ts');
    });

    it('suffixes operationId with file basename on collision', () => {
      const out = synthesizeOpenApi(
        [
          ep({ route_pattern: '/users/:id', file_path: 'src/users.ts', handler_name: 'getUser' }),
          ep({ route_pattern: '/admin/users/:id', file_path: 'src/admin.ts', handler_name: 'getUser' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      const parsed = yaml.load(out.yaml!) as { paths: Record<string, Record<string, Record<string, unknown>>> };
      const op1 = parsed.paths['/users/{id}'].get;
      const op2 = parsed.paths['/admin/users/{id}'].get;
      expect(op1.operationId).toBe('getUser');
      expect(op2.operationId).toBe('getUser_admin');
    });

    it('numeric suffix when even basename-suffixed operationId collides', () => {
      const out = synthesizeOpenApi(
        [
          ep({ route_pattern: '/a/:id', file_path: 'src/handler.ts', handler_name: 'h' }),
          ep({ route_pattern: '/b/:id', file_path: 'src/handler.ts', handler_name: 'h' }),
          ep({ route_pattern: '/c/:id', file_path: 'src/handler.ts', handler_name: 'h' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      const parsed = yaml.load(out.yaml!) as { paths: Record<string, Record<string, Record<string, unknown>>> };
      const ids = new Set([
        parsed.paths['/a/{id}'].get.operationId,
        parsed.paths['/b/{id}'].get.operationId,
        parsed.paths['/c/{id}'].get.operationId,
      ]);
      expect(ids.size).toBe(3);
    });
  });

  describe('tail-framework fallback', () => {
    it('still emits a valid OpenAPI path for a koa/hono/laravel route', () => {
      const out = synthesizeOpenApi(
        [
          ep({ framework: 'koa', route_pattern: '/users/:id' }),
          ep({ framework: 'hono', route_pattern: '/things/{id}' }),
          ep({ framework: 'laravel', route_pattern: '/posts/{slug}' }),
        ],
        { targetUrl: 'https://api.example.com' },
      );
      expect(out.endpoint_count).toBe(3);
      const parsed = yaml.load(out.yaml!) as { paths: Record<string, Record<string, unknown>> };
      expect(parsed.paths['/users/{id}']).toBeDefined();
      expect(parsed.paths['/things/{id}']).toBeDefined();
      expect(parsed.paths['/posts/{slug}']).toBeDefined();
    });
  });
});
