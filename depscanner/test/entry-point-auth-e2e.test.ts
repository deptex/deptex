/**
 * END-TO-END proof for the entry-point auth arc (no Docker / no Supabase).
 *
 * Runs the REAL pipeline components over the committed express dogfood fixture on
 * disk, exactly as the worker chains them:
 *   1. extractUsage — the real framework detectors classify every route + capture
 *      handler spans, and cross-file postProcess runs.
 *   2. buildEntryPointAuthMap — the real ctx.entryPointAuth map.
 *   3. runEngineCore — the REAL cross-file taint engine emits real Flow objects
 *      for the lodash CVE-2021-23337 sinks (`_.template(req.query.tpl)`).
 *   4. computeEntryPointTag — the real span-join stamp each flow would get in
 *      writeFlows.
 *   5. aggregateEpdFromFlows — the real EPD merge, showing the authed dep demote.
 *
 * Asserts the demotion the whole arc exists to produce: the flow whose source
 * fires inside the requireAuth-guarded /api/admin/render handler stamps
 * framework-route:auth_internal (weight 0.5), while the public /api/render flow
 * stamps framework-route:public_unauth (weight 1.0).
 *
 * Run: npx tsx test/entry-point-auth-e2e.test.ts
 */
import * as path from 'path';
import { extractUsage } from '../src/tree-sitter-extractor';
import { buildEntryPointAuthMap, runPostProcess } from '../src/framework-rules/build-auth-map';
import { runEngineCore } from '../src/taint-engine/runner';
import { computeEntryPointTag } from '../src/taint-engine/storage';
import { aggregateEpdFromFlows, type PerFlowVerdict } from '../src/epd';
import type { Flow } from '../src/taint-engine/flow';

let failures = 0;
let passes = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`  FAIL: ${msg}`); failures++; }
  else { console.log(`  ok: ${msg}`); passes++; }
}

async function run(): Promise<void> {
  const workspaceRoot = path.resolve(__dirname, '..', 'test-repos', 'express');
  console.log(`workspace: ${workspaceRoot}\n`);

  // 1. Real detectors + spans.
  const extraction = await extractUsage({
    workspaceRoot,
    ecosystem: 'npm',
    deps: [{ name: 'express', namespace: null }, { name: 'lodash', namespace: null }],
  });
  const routeEps = extraction.files.flatMap((f) => (f.entryPoints ?? []).filter((e) => e.framework === 'express'));
  console.log(`detected ${routeEps.length} express routes:`);
  for (const ep of routeEps) {
    console.log(`  ${ep.routePattern}  ${ep.classification}  span=${ep.handlerSpan ? `${ep.handlerSpan.startLine}-${ep.handlerSpan.endLine}` : 'null'}`);
  }
  const admin = routeEps.find((e) => (e.routePattern ?? '').includes('/admin/render'));
  const publicRender = routeEps.find((e) => (e.routePattern ?? '').endsWith('/render') && !(e.routePattern ?? '').includes('admin'));
  assert(admin?.classification === 'AUTH_INTERNAL', `/admin/render classified AUTH_INTERNAL`);
  assert(admin?.handlerSpan != null, `/admin/render captured a handler span`);
  assert(publicRender?.classification === 'PUBLIC_UNAUTH', `/api/render classified PUBLIC_UNAUTH`);

  // 2. Real map.
  const postRecords = await runPostProcess(extraction.files, workspaceRoot);
  const authMap = buildEntryPointAuthMap(extraction.files, postRecords, workspaceRoot);
  console.log(`\nauth map covers ${authMap.size} file(s)`);

  // 3. Real taint engine over the fixture.
  const engine = await runEngineCore({ workspaceRoot, ecosystem: 'npm', onWarn: (m) => console.log(`  [engine] ${m}`) });
  const flows: Flow[] = engine.propagation?.flows ?? [];
  console.log(`\ntaint engine emitted ${flows.length} flow(s):`);
  for (const f of flows) {
    console.log(`  ${f.vuln_class}  src=${f.entry_point_file}:${f.entry_point_line}  sink=${f.sink_method}`);
  }
  assert(flows.length > 0, 'taint engine emitted at least one flow over the fixture');

  // 4. Real stamp per flow.
  const adminFlow = flows.find((f) => f.entry_point_file.includes('admin.js'));
  const publicFlow = flows.find((f) => f.entry_point_file.includes('api.js'));
  assert(adminFlow != null, 'a flow sourced in routes/admin.js (behind requireAuth) exists');
  assert(publicFlow != null, 'a flow sourced in routes/api.js (public) exists');

  if (adminFlow) {
    const stamp = computeEntryPointTag(adminFlow, authMap);
    console.log(`\nadmin.js flow stamp: ${stamp.tag} (joinable=${stamp.joinable}, matched=${stamp.matched})`);
    assert(stamp.tag === 'framework-route:auth_internal', 'admin.js flow → framework-route:auth_internal (THE DEMOTION)');
    assert(stamp.matched, 'admin.js flow counted as a span match');
  }
  if (publicFlow) {
    const stamp = computeEntryPointTag(publicFlow, authMap);
    console.log(`api.js flow stamp:   ${stamp.tag}`);
    assert(stamp.tag === 'framework-route:public_unauth', 'api.js flow → framework-route:public_unauth (stays public)');
  }

  // 5. Real EPD merge — the authed flow demotes the endpoint weight.
  if (adminFlow) {
    const stamp = computeEntryPointTag(adminFlow, authMap);
    const verdict: PerFlowVerdict = {
      isSuppressed: false, filterVerdict: null, sanitization: null, endpoint: null,
      flowLength: adminFlow.flow_length, reachabilitySource: 'taint_engine', entryPointTag: stamp.tag,
    };
    const epd = aggregateEpdFromFlows([verdict], 10.0, 'confirmed', true);
    console.log(`\nEPD for the authed lodash flow (no AI verdict, evidence only): class=${epd.entry_point_classification} weight=${epd.entry_point_weight}`);
    assert(epd.entry_point_classification === 'AUTH_INTERNAL', 'EPD merge: verdict-less authed-evidence flow → AUTH_INTERNAL');
    assert(epd.entry_point_weight === 0.5, 'EPD entry weight demoted 1.0 → 0.5');
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
