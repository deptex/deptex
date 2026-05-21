/**
 * PGLite integration test for dual-scope PDV attachment.
 *
 * When one package is declared as a direct devDependency *and* also pulled in
 * as a production transitive, dep-scan sees two `project_dependencies` rows for
 * the same `name@version`. The vulnerability must attach to the production
 * row — otherwise a genuine runtime vuln lands on the dev row and dev-scope
 * classification flips it to `unreachable`, a Gate-3 false negative.
 *
 * The unit test in src/__tests__/dev-scope.test.ts pins the dev-scope
 * classifier with a hand-rolled storage mock. This test instead boots PGLite
 * (loading the real backend/database/schema.sql), seeds the two rows, runs the
 * exact `.select('id, name, version, environment')` dep-scan.ts performs, and
 * feeds the result through `resolveDualScopePdMap` — the helper dep-scan uses
 * to pick the attachment target.
 *
 * Postgres does not guarantee row order without ORDER BY, so the resolver must
 * pick the production row regardless of which `project_dependencies` row was
 * inserted first. The test seeds the dev row first in one case and the prod
 * row first in the other (each in its own project — the dual rows would
 * otherwise collide on the (project_id, name, version, is_direct, source)
 * unique key), and asserts the resolved id — and the PDV that lands on it —
 * is the production row both times.
 *
 * Run: npx tsx test/dual-scope-attachment-pglite.test.ts
 */

import { createPGLiteStorage } from '../src/storage';
import { resolveDualScopePdMap } from '../src/pipeline-steps/dep-scan';

type PgStorage = Awaited<ReturnType<typeof createPGLiteStorage>>;

let failures = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

const ORG_ID = '11111111-1111-1111-1111-111111111111';
const RUN_ID = 'run_dual_scope_test';

// One vulnerable package present twice: a direct devDependency and a
// production transitive at the same version.
const PKG_NAME = 'lodash';
const PKG_VERSION = '4.17.20';

async function seedProject(storage: PgStorage, projectId: string): Promise<void> {
  const { error } = await storage.from('projects').insert({
    id: projectId,
    organization_id: ORG_ID,
    name: `dual-scope-${projectId.slice(-4)}`,
    created_at: new Date().toISOString(),
  });
  assert(error === null, `seed project ${projectId.slice(0, 8)} (error=${error?.message ?? 'null'})`);
}

async function seedDualScope(
  storage: PgStorage,
  projectId: string,
  order: 'dev-first' | 'prod-first',
  devPdId: string,
  prodPdId: string,
): Promise<void> {
  const devRow = {
    id: devPdId,
    project_id: projectId,
    name: PKG_NAME,
    version: PKG_VERSION,
    is_direct: true,
    source: 'devDependencies',
    environment: 'dev',
    last_seen_extraction_run_id: RUN_ID,
  };
  const prodRow = {
    id: prodPdId,
    project_id: projectId,
    name: PKG_NAME,
    version: PKG_VERSION,
    is_direct: false,
    source: 'transitive',
    environment: 'prod',
    last_seen_extraction_run_id: RUN_ID,
  };

  const rows = order === 'dev-first' ? [devRow, prodRow] : [prodRow, devRow];
  for (const row of rows) {
    const { error } = await storage.from('project_dependencies').insert(row);
    assert(error === null, `[${order}] insert ${row.environment} row (error=${error?.message ?? 'null'})`);
  }
}

/**
 * Resolve the attachment target exactly as dep-scan.ts does: the same SELECT,
 * then `resolveDualScopePdMap`.
 */
async function resolveAttachment(storage: PgStorage, projectId: string): Promise<string | undefined> {
  const { data: pdRows, error } = await storage
    .from('project_dependencies')
    .select('id, name, version, environment')
    .eq('project_id', projectId)
    .eq('last_seen_extraction_run_id', RUN_ID);
  assert(error === null, `select project_dependencies (error=${error?.message ?? 'null'})`);
  const map = resolveDualScopePdMap((pdRows ?? []) as any);
  return map.get(`${PKG_NAME}@${PKG_VERSION}`);
}

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage...');
  const storage = await createPGLiteStorage();
  console.log(`  booted in ${Date.now() - t0}ms\n`);

  const PROJECT_A = '22222222-2222-2222-2222-22222222000a';
  const PROJECT_B = '22222222-2222-2222-2222-22222222000b';
  const PROJECT_C = '22222222-2222-2222-2222-22222222000c';

  // --- Bootstrap org + the three projects so the project_dependencies FK resolves ---
  {
    const { error: orgErr } = await storage
      .from('organizations')
      .insert({ id: ORG_ID, name: 'dual-scope-test-org', created_at: new Date().toISOString() });
    assert(orgErr === null, `seed organization (error=${orgErr?.message ?? 'null'})`);
    for (const p of [PROJECT_A, PROJECT_B, PROJECT_C]) await seedProject(storage, p);
  }

  // In every case the dev id sorts *below* the prod id, so the lowest-id
  // tiebreak alone would pick the dev row — proving the resolver wins on
  // scope, not on id ordering.

  // --- Case A: dev row inserted first ---
  console.log('\n[case A] dev devDependency row inserted before the prod transitive');
  {
    const devPdId = 'd1111111-0000-0000-0000-000000000001';
    const prodPdId = 'f1111111-0000-0000-0000-000000000002';
    await seedDualScope(storage, PROJECT_A, 'dev-first', devPdId, prodPdId);
    const resolved = await resolveAttachment(storage, PROJECT_A);
    assert(resolved === prodPdId, `PDV attaches to the prod row (expected ${prodPdId}, got ${resolved})`);

    // Land an actual reachable PDV on the resolved id and read it back —
    // proves the FK accepts it and the vuln sits on the production row.
    const { error: vulnErr } = await storage.from('project_dependency_vulnerabilities').insert({
      project_id: PROJECT_A,
      project_dependency_id: resolved,
      osv_id: 'CVE-2021-23337',
      extraction_run_id: RUN_ID,
      is_reachable: true,
    });
    assert(vulnErr === null, `insert PDV onto resolved row (error=${vulnErr?.message ?? 'null'})`);
    const { data: pdvRows } = await storage
      .from('project_dependency_vulnerabilities')
      .select('project_dependency_id')
      .eq('project_id', PROJECT_A);
    assert(
      Array.isArray(pdvRows) && pdvRows.length === 1 && (pdvRows[0] as any).project_dependency_id === prodPdId,
      `the PDV row points at the prod project_dependency (rows=${JSON.stringify(pdvRows)})`,
    );
  }

  // --- Case B: prod row inserted first (order independence) ---
  console.log('\n[case B] prod transitive row inserted before the dev devDependency');
  {
    const devPdId = 'd2222222-0000-0000-0000-000000000001';
    const prodPdId = 'f2222222-0000-0000-0000-000000000002';
    await seedDualScope(storage, PROJECT_B, 'prod-first', devPdId, prodPdId);
    const resolved = await resolveAttachment(storage, PROJECT_B);
    assert(
      resolved === prodPdId,
      `PDV still attaches to the prod row regardless of insert order (expected ${prodPdId}, got ${resolved})`,
    );
  }

  // --- Case C: only a dev row exists — the package still resolves ---
  console.log('\n[case C] a dev-only package resolves to its single row');
  {
    const devPdId = 'cccccccc-0000-0000-0000-000000000001';
    const { error } = await storage.from('project_dependencies').insert({
      id: devPdId,
      project_id: PROJECT_C,
      name: PKG_NAME,
      version: PKG_VERSION,
      is_direct: true,
      source: 'devDependencies',
      environment: 'dev',
      last_seen_extraction_run_id: RUN_ID,
    });
    assert(error === null, `insert dev-only row (error=${error?.message ?? 'null'})`);
    const resolved = await resolveAttachment(storage, PROJECT_C);
    assert(resolved === devPdId, `dev-only package maps to its row (expected ${devPdId}, got ${resolved})`);
  }

  await storage.close?.();
  console.log(`\nDone in ${Date.now() - t0}ms. ${failures === 0 ? 'ALL GREEN' : `${failures} FAILURES`}.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('test crashed:', e);
  process.exit(1);
});
