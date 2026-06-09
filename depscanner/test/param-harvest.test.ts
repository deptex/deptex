/**
 * Unit tests for the deterministic request-param harvest (express + flask) and
 * the express mount-prefix resolver. Parses real tree-sitter grammars via
 * parseSource (same path the extractor uses) and asserts the harvested
 * RequestParam[] + the composed route patterns.
 *
 * Run: npm run test:param-harvest
 */

import assert from 'node:assert';
import type { Node } from 'web-tree-sitter';
import { parseSource } from '../src/tree-sitter-extractor/parser';
import { harvestExpressParams } from '../src/param-harvest/express-harvest';
import { harvestFlaskParams } from '../src/param-harvest/flask-harvest';
import { resolveMountPrefixes } from '../src/param-harvest/mount-prefix';
import { canonicalizeParams, isPlausibleParamName } from '../src/param-harvest/types';
import type { RequestParam } from '../src/param-harvest/types';
import type { EntryPoint } from '../src/framework-rules/types';
import type { ExtractedFile, ImportBinding } from '../src/tree-sitter-extractor/languages/types';

let passed = 0;
function ok(cond: boolean, msg: string): void {
  assert.ok(cond, msg);
  passed++;
}
function eq(actual: unknown, expected: unknown, msg: string): void {
  assert.deepStrictEqual(actual, expected, msg);
  passed++;
}

function findFirst(node: Node, type: string): Node | null {
  if (node.type === type) return node;
  for (let i = 0; i < node.namedChildCount; i++) {
    const hit = findFirst(node.namedChild(i)!, type);
    if (hit) return hit;
  }
  return null;
}

/** Compact a RequestParam[] to `name:in` strings for readable assertions. */
function compact(params: RequestParam[] | null): string[] {
  return (params ?? []).map((p) => `${p.name}:${p.in}`);
}

async function parseJs(src: string): Promise<Node> {
  const tree = await parseSource('tree-sitter-javascript.wasm', src);
  assert.ok(tree, 'JS parse produced a tree');
  return tree!.rootNode;
}
async function parsePy(src: string): Promise<Node> {
  const tree = await parseSource('tree-sitter-python.wasm', src);
  assert.ok(tree, 'Python parse produced a tree');
  return tree!.rootNode;
}

async function harvestJsHandler(src: string): Promise<RequestParam[] | null> {
  const root = await parseJs(src);
  const handler = findFirst(root, 'arrow_function') ?? findFirst(root, 'function_expression');
  assert.ok(handler, 'found a handler node');
  return harvestExpressParams(handler, src);
}

function epRow(partial: Partial<EntryPoint>): EntryPoint {
  return {
    filePath: '',
    lineNumber: 1,
    framework: 'express',
    handlerName: null,
    httpMethod: null,
    routePattern: null,
    entryPointType: 'http_route',
    classification: 'PUBLIC_UNAUTH',
    authenticated: false,
    authMechanism: null,
    middlewareChain: null,
    metadata: null,
    ...partial,
  };
}
function imp(localName: string, source: string): ImportBinding {
  return { localName, importedName: null, source, line: 0, kind: 'cjs-require' };
}
function extracted(filePath: string, entryPoints: EntryPoint[], imports: ImportBinding[] = []): ExtractedFile {
  return { filePath, language: 'javascript', imports, usages: [], entryPoints };
}

async function main(): Promise<void> {
  // ---- canonicalizeParams (pure) -----------------------------------------
  eq(canonicalizeParams([]), null, 'empty → null');
  eq(canonicalizeParams(null), null, 'null → null');
  {
    const a: RequestParam = { name: 'z', in: 'query', required: false, schema: { type: 'string' }, provenance: 'ast' };
    const b: RequestParam = { name: 'a', in: 'query', required: false, schema: { type: 'string' }, provenance: 'ast' };
    const h: RequestParam = { name: 'x', in: 'header', required: false, schema: { type: 'string' }, provenance: 'ast' };
    // sort by (in, name): query a, query z, header x → query before header
    eq(compact(canonicalizeParams([a, b, h, a])), ['a:query', 'z:query', 'x:header'], 'canonical sort + dedup');
  }
  ok(isPlausibleParamName('userId') && !isPlausibleParamName('$(curl evil)'), 'identifier guard');

  // ---- express harvest ----------------------------------------------------
  // dogfood shape: direct member access in a const.
  eq(
    compact(await harvestJsHandler(`const h = (req, res) => { const id = req.query.id; res.send(id); };`)),
    ['id:query'],
    'express member req.query.id',
  );
  eq(
    compact(await harvestJsHandler(`app.get('/r', (req, res) => { const t = req.query.tpl; render(t); });`)),
    ['tpl:query'],
    'express member req.query.tpl (dogfood RCE param)',
  );
  // subscript + destructure + header getter + cookie
  eq(
    compact(await harvestJsHandler(`const h = (req, res) => { const a = req.query['a']; const { b, c } = req.query; const t = req.get('X-Token'); const s = req.cookies.sid; };`)),
    ['a:query', 'b:query', 'c:query', 'X-Token:header', 'sid:cookie'],
    'express subscript + destructure + header(name) + cookie(name)',
  );
  // NEGATIVE: paramless handler → null
  eq(await harvestJsHandler(`const h = (req, res) => { res.send('ok'); };`), null, 'paramless handler → null');
  // NEGATIVE: path + body params are NOT harvested here (owned by route string / fast-follow)
  eq(
    compact(await harvestJsHandler(`const h = (req, res) => { const id = req.params.id; const x = req.body.x; const q = req.query.q; };`)),
    ['q:query'],
    'req.params + req.body excluded; only query',
  );
  // SCOPING: two sibling handlers harvest independently
  {
    const src = `const a = (req, res) => { const x = req.query.aa; }; const b = (req, res) => { const y = req.query.bb; };`;
    const root = await parseJs(src);
    const arrows: Node[] = [];
    const collect = (n: Node): void => { if (n.type === 'arrow_function') arrows.push(n); for (let i = 0; i < n.namedChildCount; i++) collect(n.namedChild(i)!); };
    collect(root);
    ok(arrows.length === 2, 'two handlers parsed');
    eq(compact(harvestExpressParams(arrows[0], src)), ['aa:query'], 'handler A only sees its own param');
    eq(compact(harvestExpressParams(arrows[1], src)), ['bb:query'], 'handler B only sees its own param');
  }
  // DETERMINISM: same input twice → byte-identical
  {
    const src = `const h = (req, res) => { const z = req.query.zeta; const a = req.query.alpha; const t = req.get('H'); };`;
    const r1 = JSON.stringify(await harvestJsHandler(src));
    const r2 = JSON.stringify(await harvestJsHandler(src));
    eq(r1, r2, 'harvest is deterministic across runs');
  }
  // alt receiver name (request) still works
  eq(
    compact(await harvestJsHandler(`const h = (request, res) => { const id = request.query.id; };`)),
    ['id:query'],
    'receiver named `request`',
  );

  // ---- flask harvest ------------------------------------------------------
  {
    const root = await parsePy(`def view():\n    q = request.args.get('q')\n    p = request.args['p']\n    tok = request.headers.get('X-Tok')\n    f = request.form.get('body_field')\n    return q\n`);
    const fn = findFirst(root, 'function_definition');
    ok(!!fn, 'flask view function parsed');
    eq(
      compact(harvestFlaskParams(fn!, `def view():\n    q = request.args.get('q')\n    p = request.args['p']\n    tok = request.headers.get('X-Tok')\n    f = request.form.get('body_field')\n    return q\n`)),
      ['p:query', 'q:query', 'X-Tok:header'],
      'flask args(.get/[]) → query, headers → header, form(body) excluded',
    );
  }

  // ---- mount-prefix resolution -------------------------------------------
  // Cross-file (the express dogfood shape): server.js mounts require('./routes/api') at /api.
  {
    const server = extracted(
      'server.js',
      [epRow({ filePath: 'server.js', routePattern: '/api', handlerName: 'apiRouter', httpMethod: null, metadata: { instance: 'app', call: 'app.use' } })],
      [imp('apiRouter', './routes/api')],
    );
    const api = extracted('routes/api.js', [
      epRow({ filePath: 'routes/api.js', routePattern: '/users', handlerName: '(anonymous)', httpMethod: 'GET', metadata: { instance: 'router', call: 'router.get' } }),
      epRow({ filePath: 'routes/api.js', routePattern: '/health', handlerName: '(anonymous)', httpMethod: 'GET', metadata: { instance: 'router', call: 'router.get' } }),
    ]);
    resolveMountPrefixes([server, api]);
    eq(
      (api.entryPoints ?? []).map((e) => e.routePattern),
      ['/api/users', '/api/health'],
      'cross-file mount: routes/api.js routes get /api prefix',
    );
  }
  // Same-file router instance.
  {
    const f = extracted('app.js', [
      epRow({ filePath: 'app.js', routePattern: '/v1', handlerName: 'r', httpMethod: null, metadata: { instance: 'app', call: 'app.use' } }),
      epRow({ filePath: 'app.js', routePattern: '/things', handlerName: '(anonymous)', httpMethod: 'GET', metadata: { instance: 'r', call: 'r.get' } }),
    ]);
    resolveMountPrefixes([f]);
    eq((f.entryPoints ?? [])[1].routePattern, '/v1/things', 'same-file router mount prefix');
  }
  // No-op: mount at '/' leaves routes untouched.
  {
    const server = extracted('s.js', [epRow({ filePath: 's.js', routePattern: '/', handlerName: 'r', httpMethod: null, metadata: { instance: 'app', call: 'app.use' } })], [imp('r', './r')]);
    const r = extracted('r.js', [epRow({ filePath: 'r.js', routePattern: '/x', handlerName: '(anonymous)', httpMethod: 'GET', metadata: { instance: 'router', call: 'router.get' } })]);
    resolveMountPrefixes([server, r]);
    eq((r.entryPoints ?? [])[0].routePattern, '/x', "mount at '/' is a no-op");
  }

  console.log(`\nparam-harvest: ${passed} assertions passed`);
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error('param-harvest FAILED:', err);
    process.exit(1);
  },
);
