/**
 * Unit tests for the entry-point auth-classification core (plan T1):
 *   - the pure evidence/classify/belt/prefix logic (auth-evidence.ts)
 *   - the flow→route span join + tag vocabulary (match-flow-to-routes.ts)
 *   - the JS AST span-resolution + demotion-eligibility helpers, against REAL
 *     tree-sitter trees (javascript.ts).
 *
 * Run: npx tsx test/entry-point-auth.test.ts
 */
import * as path from 'path';
import type { Node } from 'web-tree-sitter';
import { parseSource } from '../src/tree-sitter-extractor/parser';
import {
  classifyRoute,
  matchesPublicRouteBelt,
  prefixCoversRoute,
  spanContains,
  isOptionalVetoed,
  type RouteAuthRecord,
} from '../src/framework-rules/util/auth-evidence';
import {
  matchFlowToRoutes,
  parseEntryPointTag,
  tagForClass,
  TAG_UNMATCHED,
  TAG_LEGACY_PUBLIC,
  type EntryPointAuthMap,
} from '../src/taint-engine/match-flow-to-routes';
import {
  resolveSameFileHandlerSpan,
  handlerSpanForArg,
  isNamedHandlerDemotionEligible,
} from '../src/framework-rules/util/javascript';
import {
  buildEntryPointAuthMap,
  runPostProcess,
  summarizeAttackSurface,
} from '../src/framework-rules/build-auth-map';
import { computeEntryPointTag } from '../src/taint-engine/storage';
import { resetDetectorErrors, getDetectorErrorSummary } from '../src/tree-sitter-extractor/detector-errors';
import type { EntryPoint, CtxOnlyRouteRecord, FrameworkDetector } from '../src/framework-rules/types';
import type { ExtractedFile } from '../src/tree-sitter-extractor/languages/types';
import type { Flow, FlowNode } from '../src/taint-engine/flow';

let failures = 0;
let passes = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`  FAIL: ${msg}`); failures++; }
  else { console.log(`  ok: ${msg}`); passes++; }
}
function eq(a: unknown, b: unknown, msg: string): void {
  assert(JSON.stringify(a) === JSON.stringify(b), `${msg} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
}

// ---- helpers to build route records ---------------------------------------
function route(p: Partial<RouteAuthRecord>): RouteAuthRecord {
  return {
    classification: 'PUBLIC_UNAUTH',
    handlerSpan: null,
    demotionEligible: true,
    routePattern: null,
    middlewareChain: null,
    authMechanism: null,
    ...p,
  };
}

async function run(): Promise<void> {
  // ========================================================================
  console.log('\nclassifyRoute — Semantics 1-5, 8');
  // ========================================================================
  eq(classifyRoute({ authTokens: ['requireAuth'] }).classification, 'AUTH_INTERNAL', 'route-local auth token → AUTH_INTERNAL');
  eq(classifyRoute({}).classification, 'PUBLIC_UNAUTH', 'no evidence → PUBLIC (evidence-public)');
  eq(classifyRoute({ authTokens: ['loadUser'] }).classification, 'PUBLIC_UNAUTH', 'non-auth middleware → PUBLIC');
  // Sem 2 override wins
  eq(classifyRoute({ authTokens: ['requireAuth'], publicOverrides: ['AllowAnonymous'] }).classification, 'PUBLIC_UNAUTH', 'explicit-public override beats auth');
  eq(classifyRoute({ authTokens: ['authenticate'], publicOverrides: ['permitAll'] }).classification, 'PUBLIC_UNAUTH', 'SpEL permitAll override');
  // Sem 4 optional veto
  eq(classifyRoute({ authTokens: ["passport.authenticate('anonymous')"] }).classification, 'PUBLIC_UNAUTH', 'passport anonymous → not evidence');
  eq(classifyRoute({ authTokens: ['getCurrentUserOptional'] }).classification, 'PUBLIC_UNAUTH', 'optional-named auth → not evidence');
  eq(classifyRoute({ authTokens: ['requireAuth'], optional: true }).classification, 'PUBLIC_UNAUTH', 'caller optional flag vetoes');
  assert(isOptionalVetoed('jwtOptional'), 'isOptionalVetoed catches *Optional');
  // Sem 5 machine evidence
  eq(classifyRoute({ internalTokens: ['Receiver.verify'] }).classification, 'OFFLINE_WORKER', 'verifier → OFFLINE_WORKER');
  eq(classifyRoute({ internalTokens: ['stripe.webhooks.constructEvent'] }).classification, 'OFFLINE_WORKER', 'constructEvent → OFFLINE_WORKER');
  eq(classifyRoute({ internalTokens: ['internalKeyGuard'] }).classification, 'OFFLINE_WORKER', 'internal-name middleware → OFFLINE_WORKER');
  // Sem 3 conditional
  eq(classifyRoute({ authTokens: ['authenticate'], conditional: true }).classification, 'PUBLIC_UNAUTH', 'conditional coverage does not cover');

  // ========================================================================
  console.log('\nbelt (Sem 10) + prefix (Sem 11)');
  // ========================================================================
  assert(matchesPublicRouteBelt('/login'), 'belt: /login');
  assert(matchesPublicRouteBelt('/users/:id/login'), 'belt: nested login segment');
  assert(matchesPublicRouteBelt('/.well-known/jwks.json'), 'belt: well-known');
  assert(!matchesPublicRouteBelt('/loginit'), 'belt: /loginit NOT matched (segment boundary)');
  assert(!matchesPublicRouteBelt('/dashboard'), 'belt: /dashboard not matched');
  // belt only blocks CENTRALIZED demotions
  eq(classifyRoute({ authTokens: ['authenticate'], centralizedOnly: true, routePattern: '/login' }).classification, 'PUBLIC_UNAUTH', 'centralized demotion blocked on belt route');
  eq(classifyRoute({ authTokens: ['authenticate'], centralizedOnly: false, routePattern: '/login' }).classification, 'AUTH_INTERNAL', 'route-local auth STILL demotes a belt route');
  assert(prefixCoversRoute('/api', '/api/users'), 'prefix: /api covers /api/users');
  assert(prefixCoversRoute('/api', '/api'), 'prefix: /api covers itself');
  assert(!prefixCoversRoute('/api', '/apiv2/users'), 'prefix: /api does NOT cover /apiv2 (segment boundary)');
  assert(prefixCoversRoute('', '/anything'), 'prefix: pathless covers everything');
  assert(prefixCoversRoute('/', '/anything'), 'prefix: / covers everything');

  // ========================================================================
  console.log('\nspanContains + matchFlowToRoutes (Sem 6)');
  // ========================================================================
  assert(spanContains({ startLine: 5, endLine: 9 }, 5), 'span inclusive lower');
  assert(spanContains({ startLine: 5, endLine: 9 }, 9), 'span inclusive upper');
  assert(spanContains({ startLine: 7, endLine: 7 }, 7), 'one-line span (start==end)');
  assert(!spanContains({ startLine: 5, endLine: 9 }, 4), 'below span excluded');
  assert(!spanContains(null, 5), 'null span never contains');

  const map: EntryPointAuthMap = new Map();
  map.set('routes/api.ts', [
    route({ classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 10, endLine: 20 }, routePattern: '/admin' }),
    route({ classification: 'PUBLIC_UNAUTH', handlerSpan: { startLine: 30, endLine: 40 }, routePattern: '/health' }),
  ]);
  eq(matchFlowToRoutes(map, 'routes/api.ts', 15).stampTag, tagForClass('AUTH_INTERNAL'), 'flow inside authed span → framework-route:auth_internal');
  eq(matchFlowToRoutes(map, 'routes/api.ts', 35).stampTag, tagForClass('PUBLIC_UNAUTH'), 'flow inside public span → framework-route:public_unauth');
  eq(matchFlowToRoutes(map, 'routes/api.ts', 25).stampTag, TAG_UNMATCHED, 'flow between spans → unmatched');
  eq(matchFlowToRoutes(map, 'services/helper.ts', 5).stampTag, TAG_UNMATCHED, 'flow in file with no routes → unmatched');
  // mixed candidates: an authed + a public span overlapping → public wins (fail-safe)
  const overlap: EntryPointAuthMap = new Map([['f.ts', [
    route({ classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 1, endLine: 50 } }),
    route({ classification: 'PUBLIC_UNAUTH', handlerSpan: { startLine: 10, endLine: 20 } }),
  ]]]);
  eq(matchFlowToRoutes(overlap, 'f.ts', 15).stampTag, tagForClass('PUBLIC_UNAUTH'), 'overlapping authed+public → public wins');
  // ineligible candidate → unmatched even though authed
  const ineligible: EntryPointAuthMap = new Map([['f.ts', [
    route({ classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 1, endLine: 10 }, demotionEligible: false }),
  ]]]);
  eq(matchFlowToRoutes(ineligible, 'f.ts', 5).stampTag, TAG_UNMATCHED, 'authed-but-ineligible span → unmatched (exported/referenced handler)');
  // UNKNOWN candidate → unmatched
  const unknown: EntryPointAuthMap = new Map([['f.ts', [
    route({ classification: 'UNKNOWN', handlerSpan: { startLine: 1, endLine: 10 } }),
  ]]]);
  eq(matchFlowToRoutes(unknown, 'f.ts', 5).stampTag, TAG_UNMATCHED, 'UNKNOWN candidate → unmatched (not evidence-public)');
  // OFFLINE_WORKER only
  const worker: EntryPointAuthMap = new Map([['f.ts', [
    route({ classification: 'OFFLINE_WORKER', handlerSpan: { startLine: 1, endLine: 10 } }),
  ]]]);
  eq(matchFlowToRoutes(worker, 'f.ts', 5).stampTag, tagForClass('OFFLINE_WORKER'), 'worker span → framework-route:offline_worker');

  // ========================================================================
  console.log('\nparseEntryPointTag (Sem 7 vote membership)');
  // ========================================================================
  eq(parseEntryPointTag('framework-route:auth_internal'), { cls: 'AUTH_INTERNAL', votes: true }, 'auth_internal votes');
  eq(parseEntryPointTag('framework-route:public_unauth'), { cls: 'PUBLIC_UNAUTH', votes: true }, 'evidence-public votes');
  eq(parseEntryPointTag('framework-route:offline_worker'), { cls: 'OFFLINE_WORKER', votes: true }, 'offline_worker votes');
  eq(parseEntryPointTag(TAG_UNMATCHED), { cls: 'PUBLIC_UNAUTH', votes: false }, 'unmatched: PUBLIC weight, NO vote');
  eq(parseEntryPointTag(TAG_LEGACY_PUBLIC), { cls: 'PUBLIC_UNAUTH', votes: false }, 'legacy constant: NO vote (kills detector-flow pinning)');
  eq(parseEntryPointTag(null), { cls: 'PUBLIC_UNAUTH', votes: false }, 'null tag: no vote');

  // ========================================================================
  console.log('\nJS AST helpers — real tree-sitter trees (Sem 6 span/eligibility)');
  // ========================================================================
  const parse = async (src: string): Promise<Node> => {
    const t = await parseSource('tree-sitter-javascript.wasm', src);
    if (!t) throw new Error('parse failed');
    return t.rootNode;
  };

  const namedFn = await parse(
    `function resetPassword(req, res) {\n  const t = req.body.token;\n  doReset(t);\n}\nrouter.post('/reset', requireAuth, resetPassword);\n`,
  );
  const span = resolveSameFileHandlerSpan(namedFn, `function resetPassword(req, res) {\n  const t = req.body.token;\n  doReset(t);\n}\nrouter.post('/reset', requireAuth, resetPassword);\n`, 'resetPassword');
  eq(span, { startLine: 1, endLine: 4 }, 'resolveSameFileHandlerSpan: function decl span (1-based inclusive)');

  const arrowSrc = `const h = (req, res) => { res.send(req.query.x); };\napp.get('/x', h);\n`;
  const arrowRoot = await parse(arrowSrc);
  eq(resolveSameFileHandlerSpan(arrowRoot, arrowSrc, 'h'), { startLine: 1, endLine: 1 }, 'resolveSameFileHandlerSpan: one-line arrow (start==end)');

  const dupSrc = `function h(){}\nfunction h(){}\napp.get('/x', h);\n`;
  const dupRoot = await parse(dupSrc);
  eq(resolveSameFileHandlerSpan(dupRoot, dupSrc, 'h'), null, 'resolveSameFileHandlerSpan: two decls → null (ambiguous)');

  // eligibility: unexported, single-registration named handler → eligible
  const eligSrc = `function admin(req,res){ res.send(req.body.x); }\nrouter.get('/admin', auth, admin);\n`;
  const eligRoot = await parse(eligSrc);
  assert(isNamedHandlerDemotionEligible(eligRoot, eligSrc, 'admin'), 'eligible: unexported single-registration handler');

  // ineligible via export list after declaration (the R1/R2 P0 resurrection shape)
  const expSrc = `function resetPassword(req,res){ res.send(req.body.token); }\nrouter.post('/reset', auth, resetPassword);\nexport { resetPassword };\n`;
  const expRoot = await parse(expSrc);
  assert(!isNamedHandlerDemotionEligible(expRoot, expSrc, 'resetPassword'), 'INELIGIBLE: export { h } after declaration');

  // ineligible via export function form
  const expFnSrc = `export function reset(req,res){ res.send(req.body.token); }\nrouter.post('/reset', auth, reset);\n`;
  const expFnRoot = await parse(expFnSrc);
  assert(!isNamedHandlerDemotionEligible(expFnRoot, expFnSrc, 'reset'), 'INELIGIBLE: export function h');

  // ineligible via CJS module.exports
  const cjsSrc = `function reset(req,res){ res.send(req.body.token); }\nrouter.post('/reset', auth, reset);\nmodule.exports = { reset };\n`;
  const cjsRoot = await parse(cjsSrc);
  assert(!isNamedHandlerDemotionEligible(cjsRoot, cjsSrc, 'reset'), 'INELIGIBLE: module.exports = { h }');

  // ineligible via same-file double-registration / wrapped re-mount (skeptic3-f3)
  const dblSrc = `function admin(req,res){ res.send(req.body.x); }\nrouter.get('/admin', auth, admin);\nrouter.get('/public', admin);\n`;
  const dblRoot = await parse(dblSrc);
  assert(!isNamedHandlerDemotionEligible(dblRoot, dblSrc, 'admin'), 'INELIGIBLE: handler referenced on a second route (occurrence > 2)');

  // handlerSpanForArg: member expression → null (r3-ec-4)
  const memberSrc = `router.get('/x', auth, ctrl.renderSearch);\n`;
  const memberRoot = await parse(memberSrc);
  // find the member_expression node
  let memberNode: Node | null = null;
  const findMember = (n: Node): void => {
    if (n.type === 'member_expression' && n.text === 'ctrl.renderSearch') memberNode = n;
    for (let i = 0; i < n.namedChildCount; i++) findMember(n.namedChild(i)!);
  };
  findMember(memberRoot);
  eq(handlerSpanForArg(memberNode, memberRoot, memberSrc), null, 'handlerSpanForArg: member_expression handler → null span');

  // ========================================================================
  console.log('\nbuildEntryPointAuthMap + attack surface (T2)');
  // ========================================================================
  const mkEP = (p: Partial<EntryPoint>): EntryPoint => ({
    filePath: 'routes/api.ts',
    lineNumber: 10,
    framework: 'express',
    handlerName: null,
    httpMethod: 'GET',
    routePattern: '/x',
    entryPointType: 'http_route',
    classification: 'PUBLIC_UNAUTH',
    authenticated: null,
    authMechanism: null,
    middlewareChain: null,
    metadata: null,
    ...p,
  });
  const mkFile = (p: Partial<ExtractedFile>): ExtractedFile => ({
    filePath: 'routes/api.ts',
    language: 'javascript',
    imports: [],
    usages: [],
    ...p,
  });

  {
    const files = [mkFile({
      entryPoints: [
        mkEP({ classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 10, endLine: 20 }, demotionEligible: true, routePattern: '/admin' }),
        mkEP({ classification: 'PUBLIC_UNAUTH', lineNumber: 30, handlerSpan: { startLine: 30, endLine: 40 } }),
        mkEP({ classification: 'AUTH_INTERNAL', lineNumber: 50, handlerSpan: null }), // no span → default-ineligible
      ],
    })];
    const m = buildEntryPointAuthMap(files, [], undefined);
    const recs = m.get('routes/api.ts') ?? [];
    eq(recs.length, 3, 'map keeps every route (pre-dedupe)');
    eq(recs[0].classification, 'AUTH_INTERNAL', 'record carries classification');
    eq(recs[0].demotionEligible, true, 'explicit demotionEligible preserved');
    eq(recs[2].demotionEligible, false, 'no span + no flag → demotionEligible defaults false (fail-safe)');
    // span-present + absent flag → eligible-by-default
    const m2 = buildEntryPointAuthMap([mkFile({ entryPoints: [mkEP({ classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 1, endLine: 2 } })] })], [], undefined);
    eq((m2.get('routes/api.ts') ?? [])[0].demotionEligible, true, 'span present + absent flag → eligible by default');
  }

  {
    // Absolute ep path under workspaceRoot → project-relative POSIX key (matches flows).
    const ws = path.resolve('deptex-extract-xyz');
    const abs = path.join(ws, 'routes', 'admin.ts');
    const files = [mkFile({ filePath: abs, entryPoints: [mkEP({ filePath: abs, classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 1, endLine: 5 } })] })];
    const m = buildEntryPointAuthMap(files, [], ws);
    assert(m.has('routes/admin.ts'), 'absolute ep path normalized to project-relative POSIX key');
    assert(!m.has(abs), 'absolute path is NOT a key');
  }

  {
    // postProcess ctx-only records merge under their filePath.
    const extra: CtxOnlyRouteRecord[] = [{
      filePath: 'app/controllers/admin_controller.rb',
      classification: 'AUTH_INTERNAL',
      handlerSpan: { startLine: 3, endLine: 8 },
      demotionEligible: true,
      routePattern: '/admin/dashboard',
      middlewareChain: ['authenticate_user!'],
      authMechanism: 'before_action',
    }];
    const m = buildEntryPointAuthMap([mkFile({ entryPoints: [] })], extra, undefined);
    eq((m.get('app/controllers/admin_controller.rb') ?? []).length, 1, 'postProcess record homed onto controller file');
  }

  {
    const surface = summarizeAttackSurface([mkFile({
      entryPoints: [
        mkEP({ classification: 'PUBLIC_UNAUTH' }),
        mkEP({ classification: 'UNKNOWN' }),
        mkEP({ classification: 'AUTH_INTERNAL' }),
        mkEP({ classification: 'OFFLINE_WORKER' }),
      ],
    })]);
    eq(surface, { public: 2, authenticated: 1, background: 1 }, 'attack surface buckets (UNKNOWN counts as public)');
  }

  // ========================================================================
  console.log('\nrunPostProcess — per-detector containment (T2)');
  // ========================================================================
  {
    resetDetectorErrors();
    const okDetector = {
      name: 'ok-fw',
      displayName: 'OK',
      language: 'javascript',
      triggerImports: [],
      detect: () => [],
      postProcess: () => [{
        filePath: 'a.rb', classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 1, endLine: 2 },
        demotionEligible: true, routePattern: '/a', middlewareChain: null, authMechanism: null,
      } as CtxOnlyRouteRecord],
    } as unknown as FrameworkDetector;
    const throwDetector = {
      name: 'boom-fw',
      displayName: 'Boom',
      language: 'javascript',
      triggerImports: [],
      detect: () => [],
      postProcess: () => { throw new Error('postProcess boom'); },
    } as unknown as FrameworkDetector;
    const recs = await runPostProcess([mkFile({ entryPoints: [] })], '/ws', [throwDetector, okDetector]);
    eq(recs.length, 1, 'throwing postProcess is contained; the other detector still contributes');
    eq(recs[0].filePath, 'a.rb', 'surviving detector record returned');
    assert(getDetectorErrorSummary().total >= 1, 'the throw was recorded as a detector error (not swallowed silently)');
    resetDetectorErrors();
  }

  // ========================================================================
  console.log('\ncomputeEntryPointTag — stamping decision (T3)');
  // ========================================================================
  const node = (kind: FlowNode['kind'], line: number): FlowNode => ({ filePath: 'routes/api.ts', line, column: 0, label: 'x', kind });
  const mkTaintFlow = (p: Partial<Flow>): Flow => ({
    id: 'f', vuln_class: 'xss', taint_kind: 'http_input',
    entry_point_file: 'routes/api.ts', entry_point_line: 15, entry_point_method: 'handler', entry_point_pattern: 'req.body',
    sink_file: 'routes/api.ts', sink_line: 18, sink_method: 'res.send', sink_pattern: 'res.send(*)', sink_is_external: false,
    flow_nodes: [node('source', 15), node('sink', 18)], flow_length: 2,
    source_description: 'src', sink_description: 'snk', engine_confidence: 0.5, ...p,
  });
  const stampMap: EntryPointAuthMap = new Map([['routes/api.ts', [
    route({ classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 10, endLine: 20 } }),
    route({ classification: 'PUBLIC_UNAUTH', handlerSpan: { startLine: 30, endLine: 40 } }),
  ]]]);

  // no map → legacy constant, never joinable
  eq(computeEntryPointTag(mkTaintFlow({}), undefined), { tag: TAG_LEGACY_PUBLIC, joinable: false, matched: false }, 'no auth map → legacy constant, not joinable');
  // detector-coerced flow (single sink node) → legacy constant even WITH a map
  const coerced = mkTaintFlow({ flow_nodes: [node('sink', 15)], flow_length: 1 });
  eq(computeEntryPointTag(coerced, stampMap), { tag: TAG_LEGACY_PUBLIC, joinable: false, matched: false }, 'detector-coerced flow keeps legacy constant (not joinable)');
  // real flow inside authed span → framework-route:auth_internal, joined + matched
  eq(computeEntryPointTag(mkTaintFlow({ entry_point_line: 15 }), stampMap), { tag: tagForClass('AUTH_INTERNAL'), joinable: true, matched: true }, 'flow in authed span → framework-route:auth_internal (matched)');
  // real flow inside public span → evidence public, matched (counts toward coverage)
  eq(computeEntryPointTag(mkTaintFlow({ entry_point_line: 35 }), stampMap), { tag: tagForClass('PUBLIC_UNAUTH'), joinable: true, matched: true }, 'flow in public span → framework-route:public_unauth (matched)');
  // real flow with no span match → unmatched, joinable but not matched
  eq(computeEntryPointTag(mkTaintFlow({ entry_point_line: 25 }), stampMap), { tag: TAG_UNMATCHED, joinable: true, matched: false }, 'flow with no span match → unmatched (joinable, not matched)');
  // path normalization: map built from absolute ep path, flow uses relative path → still joins
  {
    const ws = path.resolve('deptex-extract-join');
    const abs = path.join(ws, 'routes', 'api.ts');
    const m = buildEntryPointAuthMap(
      [mkFile({ filePath: abs, entryPoints: [mkEP({ filePath: abs, classification: 'AUTH_INTERNAL', handlerSpan: { startLine: 10, endLine: 20 } })] })],
      [], ws,
    );
    eq(computeEntryPointTag(mkTaintFlow({ entry_point_file: 'routes/api.ts', entry_point_line: 15 }), m).tag, tagForClass('AUTH_INTERNAL'), 'path normalization: absolute-keyed map joins a relative-path flow');
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
