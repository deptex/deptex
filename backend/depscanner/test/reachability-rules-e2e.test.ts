/**
 * End-to-end test for the Phase 23 reachability engine.
 *
 * Boots PGLite, loads schema.sql (including the phase23 columns on
 * project_reachable_flows), seeds a realistic (org, project, dep, PDV)
 * triple, writes one atom-derived flow and one semgrep-taint flow, then
 * runs the *real* updateReachabilityLevels against PGLiteStorage and
 * asserts the taint flow promotes its specific PDV to `confirmed` while
 * an unrelated PDV on the same dep falls through to `data_flow`.
 *
 * This deliberately does NOT invoke the semgrep subprocess — that path
 * is covered by the live-semgrep Jest test that runs in Docker/CI. The
 * integration value here is proving the level classifier interprets the
 * polymorphic-source schema correctly against an actual Postgres-shaped
 * store (PGLite), not a hand-rolled Storage mock.
 *
 * Run: npx tsx test/reachability-rules-e2e.test.ts
 */

import { createPGLiteStorage } from '../src/storage';
import { updateReachabilityLevels } from '../src/reachability';

let failures = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

const silentLogger = {
  info: async () => {},
  warn: async () => {},
};

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage...');
  const storage = await createPGLiteStorage();
  console.log(`  booted in ${Date.now() - t0}ms\n`);

  const ORG_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const PROJECT_ID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
  const RUN_ID = 'run_reach_rules_e2e_001';
  const TAINT_CVE = 'CVE-2021-23337';
  const OTHER_CVE = 'CVE-2020-28500'; // real lodash ReDoS; no rule authored for it

  // --- Seed: org + project ---
  await storage.from('organizations').insert({
    id: ORG_ID,
    name: 'reach-rules-test-org',
    created_at: new Date().toISOString(),
  });
  await storage.from('projects').insert({
    id: PROJECT_ID,
    organization_id: ORG_ID,
    name: 'reach-rules-test-project',
    active_extraction_run_id: RUN_ID,
    created_at: new Date().toISOString(),
  });

  // --- Seed: dependency + project_dependency ---
  const { data: depIns } = await storage
    .from('dependencies')
    .insert({ name: 'lodash', ecosystem: 'npm', license: 'MIT' })
    .select('id');
  const DEP_ID = (depIns as any)?.[0]?.id as string;
  assert(typeof DEP_ID === 'string' && DEP_ID.length > 0, 'seeded dependencies.lodash has id');

  const { data: pdIns } = await storage
    .from('project_dependencies')
    .insert({
      project_id: PROJECT_ID,
      name: 'lodash',
      version: '4.17.20',
      is_direct: true,
      source: 'package.json',
      dependency_id: DEP_ID,
      environment: 'prod',
      last_seen_extraction_run_id: RUN_ID,
      files_importing_count: 2,
    })
    .select('id');
  const PD_ID = (pdIns as any)?.[0]?.id as string;
  assert(typeof PD_ID === 'string' && PD_ID.length > 0, 'seeded project_dependencies.lodash has id');

  // --- Seed: two PDVs on the same dep — one we have a rule for, one we don't ---
  const { data: taintPdvIns } = await storage
    .from('project_dependency_vulnerabilities')
    .insert({
      project_id: PROJECT_ID,
      project_dependency_id: PD_ID,
      osv_id: TAINT_CVE,
      severity: 'HIGH',
      extraction_run_id: RUN_ID,
    })
    .select('id');
  const TAINT_PDV_ID = (taintPdvIns as any)?.[0]?.id as string;
  assert(typeof TAINT_PDV_ID === 'string', 'PDV for taint CVE inserted');

  const { data: otherPdvIns } = await storage
    .from('project_dependency_vulnerabilities')
    .insert({
      project_id: PROJECT_ID,
      project_dependency_id: PD_ID,
      osv_id: OTHER_CVE,
      severity: 'MEDIUM',
      extraction_run_id: RUN_ID,
    })
    .select('id');
  const OTHER_PDV_ID = (otherPdvIns as any)?.[0]?.id as string;
  assert(typeof OTHER_PDV_ID === 'string', 'PDV for unrelated CVE inserted');

  // --- Seed: flows ---
  // Atom-derived flow — no osv_id / rule_id, proves reachable for the dep
  // generally but doesn't encode CVE specificity.
  await storage.from('project_reachable_flows').insert({
    project_id: PROJECT_ID,
    extraction_run_id: RUN_ID,
    purl: 'pkg:npm/lodash@4.17.20',
    dependency_id: DEP_ID,
    reachability_source: 'atom',
    flow_nodes: [
      { file: 'src/index.js', line: 5, content: '_.template(...)' },
    ],
    entry_point_file: 'src/index.js',
    entry_point_method: 'handleRequest',
    entry_point_line: 3,
    sink_file: 'src/index.js',
    sink_method: '_.template',
    sink_line: 5,
    sink_is_external: true,
    flow_length: 2,
  });

  // Semgrep taint flow — targets the specific CVE.
  await storage.from('project_reachable_flows').insert({
    project_id: PROJECT_ID,
    extraction_run_id: RUN_ID,
    purl: 'pkg:npm/lodash@4.17.20',
    dependency_id: DEP_ID,
    reachability_source: 'semgrep_taint',
    osv_id: TAINT_CVE,
    rule_id: 'deptex.lodash.template-injection',
    flow_nodes: [
      { file: 'src/index.js', line: 4, content: 'req.body.template' },
      { file: 'src/index.js', line: 5, content: '_.template(userTemplate)' },
    ],
    entry_point_file: 'src/index.js',
    entry_point_method: null,
    entry_point_line: 4,
    sink_file: 'src/index.js',
    sink_method: '_.template',
    sink_line: 5,
    sink_is_external: true,
    flow_length: 2,
  });

  // --- Act: run the real level classifier ---
  console.log('\nCalling updateReachabilityLevels...');
  await updateReachabilityLevels(PROJECT_ID, RUN_ID, storage, silentLogger);

  // --- Assert: taint PDV promoted to confirmed ---
  {
    const { data, error } = await storage
      .from('project_dependency_vulnerabilities')
      .select('reachability_level, reachability_details, is_reachable')
      .eq('id', TAINT_PDV_ID)
      .single();
    assert(error === null, `read taint PDV (error=${error?.message ?? 'null'})`);
    const row = data as any;
    assert(row?.reachability_level === 'confirmed', `taint PDV level === 'confirmed' (got: ${row?.reachability_level})`);
    assert(row?.is_reachable === true, 'taint PDV is_reachable === true');
    const details = row?.reachability_details ?? {};
    const ruleIds = Array.isArray(details.rule_ids) ? details.rule_ids : [];
    assert(
      ruleIds.includes('deptex.lodash.template-injection'),
      `reachability_details.rule_ids includes the lodash rule id (got: ${JSON.stringify(ruleIds)})`,
    );
    assert(
      typeof details.flow_count === 'number' && details.flow_count >= 1,
      `reachability_details.flow_count >= 1 (got: ${details.flow_count})`,
    );
  }

  // --- Assert: unrelated PDV on same dep falls through to data_flow ---
  {
    const { data } = await storage
      .from('project_dependency_vulnerabilities')
      .select('reachability_level, is_reachable')
      .eq('id', OTHER_PDV_ID)
      .single();
    const row = data as any;
    // Atom flow exists for this dep, so the unrelated CVE should land on
    // data_flow — NOT confirmed (no matching rule), NOT function/module
    // (we have a real flow).
    assert(
      row?.reachability_level === 'data_flow',
      `unrelated CVE level === 'data_flow' (got: ${row?.reachability_level})`,
    );
    assert(row?.is_reachable === true, 'unrelated CVE is_reachable === true');
  }

  console.log(`\nDone in ${Date.now() - t0}ms. ${failures === 0 ? 'ALL GREEN' : `${failures} FAILURES`}.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('test crashed:', e);
  process.exit(1);
});
