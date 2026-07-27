/**
 * PGLite integration test for the phase66 silence-event log (workstream M / M1).
 *
 * Proves that `updateReachabilityLevels` writes ONE `silence_events` row per PDV
 * per run, mapping every column to the in-scope classifier input, alongside the
 * existing project_dependency_findings verdict write — without changing
 * that verdict. It boots the real backend/database/schema.sql (so the phase66
 * table + its unique constraint actually exist), seeds four PDVs that exercise
 * the four distinct silence verdicts, runs the classifier, and asserts the
 * emitted rows.
 *
 * It also re-runs the classifier to prove the (extraction_run_id, pdv_id) upsert
 * is idempotent within a run (EPD rescore / retries must NOT duplicate-count).
 *
 * Run: npx tsx test/silence-events-pglite.test.ts
 */

import { createPGLiteStorage } from '../src/storage';

type PgStorage = Awaited<ReturnType<typeof createPGLiteStorage>>;

let failures = 0;
let passed = 0;
function eq(actual: unknown, expected: unknown, msg: string): void {
  // Loose equality so PGLite's boolean/integer marshalling (true/'t', 0/'0')
  // doesn't trip the test; the SQL types are pinned by schema.sql.
  // eslint-disable-next-line eqeqeq
  if (actual == expected) { console.log(`  ok: ${msg} = ${JSON.stringify(actual)}`); passed++; }
  else { console.error(`  FAIL: ${msg} (expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)})`); failures++; }
}
function assert(cond: unknown, msg: string): void {
  if (cond) { console.log(`  ok: ${msg}`); passed++; }
  else { console.error(`  FAIL: ${msg}`); failures++; }
}

const log = {
  info: async () => {},
  warn: async () => {},
};

const ORG = '11111111-1111-1111-1111-111111111111';
const PROJECT = '22222222-2222-2222-2222-222222222222';
const RUN = 'run_silence_events_m1';

// Four PDVs, one per distinct silence verdict the classifier emits.
interface Fixture {
  pdvId: string;
  pdId: string;
  depId: string;
  name: string;
  isDirect: boolean;
  filesImporting: number;
  environment: string | null;
}

const ORPHAN: Fixture = { pdvId: 'f1000000-0000-0000-0000-000000000001', pdId: 'd0000000-0000-0000-0000-000000000001', depId: 'e0000000-0000-0000-0000-000000000001', name: 'orphan-pkg', isDirect: false, filesImporting: 0, environment: null };
const DEV: Fixture = { pdvId: 'f1000000-0000-0000-0000-000000000002', pdId: 'd0000000-0000-0000-0000-000000000002', depId: 'e0000000-0000-0000-0000-000000000002', name: 'dev-pkg', isDirect: true, filesImporting: 0, environment: 'dev' };
const DIRECT: Fixture = { pdvId: 'f1000000-0000-0000-0000-000000000003', pdId: 'd0000000-0000-0000-0000-000000000003', depId: 'e0000000-0000-0000-0000-000000000003', name: 'direct-pkg', isDirect: true, filesImporting: 2, environment: null };
const CGREACHED: Fixture = { pdvId: 'f1000000-0000-0000-0000-000000000004', pdId: 'd0000000-0000-0000-0000-000000000004', depId: 'e0000000-0000-0000-0000-000000000004', name: 'cgreached-pkg', isDirect: false, filesImporting: 0, environment: null };

const ALL = [ORPHAN, DEV, DIRECT, CGREACHED];

async function seed(storage: PgStorage): Promise<void> {
  {
    const { error } = await storage.from('organizations').insert({ id: ORG, name: 'silence-org', created_at: new Date().toISOString() });
    assert(error === null, `seed org (error=${error?.message ?? 'null'})`);
  }
  {
    const { error } = await storage.from('projects').insert({ id: PROJECT, organization_id: ORG, name: 'silence-proj', created_at: new Date().toISOString() });
    assert(error === null, `seed project (error=${error?.message ?? 'null'})`);
  }
  // project_dependencies — dependency_version_id left NULL (no dependency_versions
  // seeded; the FK is ON DELETE SET NULL and transitive-of-reachable needs no edges here).
  for (const f of ALL) {
    const { error } = await storage.from('project_dependencies').insert({
      id: f.pdId,
      project_id: PROJECT,
      name: f.name,
      version: '1.0.0',
      is_direct: f.isDirect,
      source: 'dependencies',
      dependency_id: f.depId,
      dependency_version_id: null,
      files_importing_count: f.filesImporting,
      environment: f.environment,
      namespace: null,
      last_seen_extraction_run_id: RUN,
      created_at: new Date().toISOString(),
    });
    assert(error === null, `seed PD ${f.name} (error=${error?.message ?? 'null'})`);
  }
  // PDVs — these are what updateReachabilityLevels classifies.
  for (const f of ALL) {
    const { error } = await storage.from('project_dependency_findings').insert({
      id: f.pdvId,
      project_id: PROJECT,
      project_dependency_id: f.pdId,
      osv_id: `CVE-2024-${f.name}`,
      extraction_run_id: RUN,
    });
    assert(error === null, `seed PDV ${f.name} (error=${error?.message ?? 'null'})`);
  }
  // One usage slice so usageAnalysisProducedOutput=true (it matches none of the
  // four deps, so isDepUsed stays false for each).
  {
    const { error } = await storage.from('project_usage_slices').insert({
      project_id: PROJECT,
      extraction_run_id: RUN,
      file_path: 'src/app.js',
      line_number: 1,
      target_name: 'app.handle',
      target_type: 'app.handle',
      resolved_method: 'app.handle',
    });
    assert(error === null, `seed usage slice (error=${error?.message ?? 'null'})`);
  }
}

async function readSilenceRows(storage: PgStorage): Promise<any[]> {
  const { data, error } = await storage
    .from('silence_events')
    .select('pdv_id, project_dependency_id, dependency_id, osv_id, reachability_level, is_reachable, verdict, graph_trusted, ast_parsed, ecosystem, files_importing_count, is_direct, dev_scoped, callgraph_reached')
    .eq('extraction_run_id', RUN);
  assert(error === null, `read silence_events (error=${error?.message ?? 'null'})`);
  return (data ?? []) as any[];
}

async function main(): Promise<void> {
  const { updateReachabilityLevels } = await import('../src/reachability');
  const storage = await createPGLiteStorage();
  await seed(storage);

  // npm + a callgraph that reached only cgreached-pkg.
  await updateReachabilityLevels(
    PROJECT,
    RUN,
    storage as any,
    log as any,
    undefined,
    { ecosystem: 'npm', usedTransitives: new Set(['cgreached-pkg']) },
  );

  const rows = await readSilenceRows(storage);
  eq(rows.length, ALL.length, 'one silence_events row per PDV');

  const byPdv = new Map<string, any>(rows.map((r) => [r.pdv_id, r]));

  // --- orphan transitive → unreachable / orphan_transitive_unreachable ---
  {
    const r = byPdv.get(ORPHAN.pdvId);
    assert(!!r, 'orphan row present');
    eq(r?.reachability_level, 'unreachable', 'orphan level');
    eq(r?.is_reachable, false, 'orphan is_reachable');
    eq(r?.verdict, 'orphan_transitive_unreachable', 'orphan verdict');
    eq(r?.callgraph_reached, false, 'orphan callgraph_reached=false');
    eq(r?.files_importing_count, 0, 'orphan files_importing_count');
    eq(r?.is_direct, false, 'orphan is_direct');
    eq(r?.dev_scoped, false, 'orphan dev_scoped');
    eq(r?.ecosystem, 'npm', 'orphan ecosystem');
    eq(r?.graph_trusted, true, 'orphan graph_trusted');
    eq(r?.ast_parsed, true, 'orphan ast_parsed');
    eq(r?.dependency_id, ORPHAN.depId, 'orphan dependency_id mapped');
  }

  // --- dev-scoped → unreachable / dev_scope_unreachable ---
  {
    const r = byPdv.get(DEV.pdvId);
    eq(r?.reachability_level, 'unreachable', 'dev level');
    eq(r?.is_reachable, false, 'dev is_reachable');
    eq(r?.verdict, 'dev_scope_unreachable', 'dev verdict');
    eq(r?.dev_scoped, true, 'dev dev_scoped=true');
    eq(r?.is_direct, true, 'dev is_direct');
  }

  // --- direct imported → module / no verdict, reachable ---
  {
    const r = byPdv.get(DIRECT.pdvId);
    eq(r?.reachability_level, 'module', 'direct level');
    eq(r?.is_reachable, true, 'direct is_reachable');
    eq(r?.verdict, null, 'direct verdict null (plain module)');
    eq(r?.files_importing_count, 2, 'direct files_importing_count');
    eq(r?.is_direct, true, 'direct is_direct');
    eq(r?.callgraph_reached, false, 'direct callgraph_reached=false');
  }

  // --- callgraph-reached transitive → module / callgraph_reached_transitive ---
  {
    const r = byPdv.get(CGREACHED.pdvId);
    eq(r?.reachability_level, 'module', 'cgreached level');
    eq(r?.is_reachable, true, 'cgreached is_reachable');
    eq(r?.verdict, 'callgraph_reached_transitive', 'cgreached verdict');
    eq(r?.callgraph_reached, true, 'cgreached callgraph_reached=true');
    eq(r?.is_direct, false, 'cgreached is_direct');
  }

  // --- the silence write must NOT change the PDV verdict it mirrors ---
  {
    const { data: pdvRows } = await storage
      .from('project_dependency_findings')
      .select('id, reachability_level, is_reachable')
      .eq('extraction_run_id', RUN);
    const pdvByPdv = new Map<string, any>((pdvRows ?? []).map((r: any) => [r.id, r]));
    eq(pdvByPdv.get(ORPHAN.pdvId)?.reachability_level, 'unreachable', 'PDV verdict matches silence row (orphan)');
    eq(pdvByPdv.get(CGREACHED.pdvId)?.reachability_level, 'module', 'PDV verdict matches silence row (cgreached)');
  }

  // --- idempotency: re-run must NOT duplicate (extraction_run_id, pdv_id) ---
  await updateReachabilityLevels(
    PROJECT,
    RUN,
    storage as any,
    log as any,
    undefined,
    { ecosystem: 'npm', usedTransitives: new Set(['cgreached-pkg']) },
  );
  const rows2 = await readSilenceRows(storage);
  eq(rows2.length, ALL.length, 'idempotent re-run still has exactly one row per PDV');

  console.log(`\n${passed} passed, ${failures} failed`);
  await (storage as any).close?.();
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
