/**
 * Unit tests for the entry-point auth-classification core (plan T1):
 *   - the pure evidence/classify/belt/prefix logic (auth-evidence.ts)
 *   - the flow→route span join + tag vocabulary (match-flow-to-routes.ts)
 *   - the JS AST span-resolution + demotion-eligibility helpers, against REAL
 *     tree-sitter trees (javascript.ts).
 *
 * Run: npx tsx test/entry-point-auth.test.ts
 */
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

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
