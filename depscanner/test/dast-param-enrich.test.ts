/**
 * M3 + CI-seam test for DAST spec param enrichment.
 *
 *  - unit: synthesizeOpenApi emits the harvested query params as OpenAPI
 *    `query` parameters (deduped against path params).
 *  - validity: the emitted doc is structurally valid OpenAPI 3.1 (every
 *    parameter has name/in/schema; `in` is a legal location) — ZAP silently
 *    drops malformed parameter blocks, so this guards a false pass.
 *  - CI seam (replaces the manual live-ZAP gate for merge): the express
 *    dogfood entry points → a synthesized spec that targets `/api/users` +
 *    `/api/render` with the `id` / `tpl` query params ZAP needs to fire the
 *    SQLi + RCE. No live target / no ZAP spawn.
 *
 * Run: npm run test:dast-param-enrich
 */

import assert from 'node:assert';
import * as yaml from 'js-yaml';
import { synthesizeOpenApi } from '../src/dast/openapi-synth';
import type { EntryPointRow } from '../src/dast/cross-link';
import type { RequestParam } from '../src/param-harvest/types';

let passed = 0;
function ok(cond: boolean, msg: string): void {
  assert.ok(cond, msg);
  passed++;
}

function qp(name: string): RequestParam {
  return { name, in: 'query', required: false, schema: { type: 'string' }, provenance: 'ast' };
}
function row(partial: Partial<EntryPointRow>): EntryPointRow {
  return {
    framework: 'express',
    http_method: 'GET',
    route_pattern: null,
    handler_name: null,
    file_path: 'routes/api.js',
    line_number: 1,
    ...partial,
  };
}

interface OpenApiDoc {
  openapi: string;
  paths: Record<string, Record<string, { parameters?: Array<{ name: string; in: string; schema?: unknown; required?: boolean }> }>>;
}

function synth(rows: EntryPointRow[]): OpenApiDoc {
  const result = synthesizeOpenApi(rows, { targetUrl: 'http://localhost:4001' });
  assert.ok(result.yaml, 'synth produced a spec');
  return yaml.load(result.yaml!) as OpenApiDoc;
}

const LEGAL_IN = new Set(['query', 'path', 'header', 'cookie']);
/** Structural OpenAPI 3.1 validity check on the synthesized doc. */
function assertValid31(doc: OpenApiDoc): void {
  ok(doc.openapi === '3.1.0', 'openapi version is 3.1.0');
  ok(doc.paths && typeof doc.paths === 'object', 'paths is an object');
  for (const [p, methods] of Object.entries(doc.paths)) {
    ok(p.startsWith('/'), `path ${p} starts with /`);
    for (const op of Object.values(methods)) {
      for (const param of op.parameters ?? []) {
        ok(typeof param.name === 'string' && param.name.length > 0, `param has a name on ${p}`);
        ok(LEGAL_IN.has(param.in), `param.in '${param.in}' is legal on ${p}`);
        ok(param.schema !== undefined, `param ${param.name} has a schema on ${p}`);
      }
    }
  }
}

function queryParams(doc: OpenApiDoc, path: string, method: string): string[] {
  const op = doc.paths[path]?.[method];
  return (op?.parameters ?? []).filter((p) => p.in === 'query').map((p) => p.name).sort();
}

function main(): void {
  // ---- unit: query param emitted ----------------------------------------
  {
    const doc = synth([row({ route_pattern: '/api/users', request_params: [qp('id')] })]);
    assertValid31(doc);
    ok(!!doc.paths['/api/users']?.get, 'GET /api/users present');
    assert.deepStrictEqual(queryParams(doc, '/api/users', 'get'), ['id'], 'id query param emitted');
    passed++;
  }

  // ---- path + query coexist, deduped -------------------------------------
  {
    // express `:id` path param + a harvested `id` query param would collide on
    // name but differ on `in` — both must survive (different locations).
    const doc = synth([row({ route_pattern: '/users/:id', request_params: [qp('q'), qp('id')] })]);
    assertValid31(doc);
    const op = doc.paths['/users/{id}']?.get;
    ok(!!op, 'GET /users/{id} present (path translated)');
    const byIn = (loc: string) => (op!.parameters ?? []).filter((p) => p.in === loc).map((p) => p.name).sort();
    assert.deepStrictEqual(byIn('path'), ['id'], 'path param id from route string');
    assert.deepStrictEqual(byIn('query'), ['id', 'q'], 'query params id+q (id distinct from path id)');
    passed++;
  }

  // ---- no params → today's behavior (no parameters block) ----------------
  {
    const doc = synth([row({ route_pattern: '/ping' })]);
    ok((doc.paths['/ping']?.get?.parameters ?? []).length === 0, 'paramless route emits no params');
  }

  // ---- CI SEAM: the express dogfood spec is attack-ready ------------------
  // Mirrors what the enriched extraction produces for depscanner/test-repos/express
  // after mount-prefix resolution (/api prefix) + query-param harvest.
  {
    const dogfood: EntryPointRow[] = [
      row({ route_pattern: '/api/users', http_method: 'GET', handler_name: 'getUsers', request_params: [qp('id')] }),
      row({ route_pattern: '/api/render', http_method: 'GET', handler_name: 'render', request_params: [qp('tpl')], file_path: 'routes/api.js' }),
      // health route — must stay filtered out (no attack surface bloat)
      row({ route_pattern: '/api/health', http_method: 'GET', handler_name: 'health' }),
    ];
    const doc = synth(dogfood);
    assertValid31(doc);
    assert.deepStrictEqual(queryParams(doc, '/api/users', 'get'), ['id'], 'SQLi target: /api/users?id= is attackable');
    assert.deepStrictEqual(queryParams(doc, '/api/render', 'get'), ['tpl'], 'RCE target: /api/render?tpl= is attackable');
    ok(!doc.paths['/api/health'] && !doc.paths['/health'], 'health route filtered out (no bloat)');
    passed++;
  }

  console.log(`\ndast-param-enrich: ${passed} assertions passed`);
}

try {
  main();
  process.exit(0);
} catch (err) {
  console.error('dast-param-enrich FAILED:', err);
  process.exit(1);
}
