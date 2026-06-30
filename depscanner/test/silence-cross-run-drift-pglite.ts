/**
 * Hand-oracle test for the phase66b M2 differ: silence_cross_run_drift().
 *
 * The function, for every project with a non-null previous_extraction_run_id,
 * diffs the prior run's SILENCED findings (reachability_level in unreachable|
 * module) against the current run via the STABLE cross-run key
 * (project_id, project_dependency_id, osv_id) — pdv_id is deliberately NOT used
 * (it forks every run). It returns one row per (project, prior_verdict) bucket
 * of PROMOTED findings (current rank > prior rank), with:
 *   - upgraded_count   : any upward tier move from the silenced set (informational;
 *                        unreachable→module counts here — shows R1 working)
 *   - silence_fn_count : the SILENCE FALSE-NEGATIVE bucket — prior tier SILENCED
 *                        (unreachable|module, rnk<=1) AND current tier VISIBLE
 *                        (function|data_flow|confirmed, rnk>=2). The worst failure:
 *                        an auto-ignored vuln is now reachable. (Silenced/visible
 *                        split per phase48 auto-ignore + the unreachable-audit doc.)
 *   - to_levels        : the distinct current levels they landed on
 *
 * Seed (one project, prev run = R0, cur run = R1) — locks all three FN cases:
 *   F1: orphan_transitive_unreachable (unreachable) → module      (healthy R1 floor; still SILENCED → fn=0)
 *   F2: unreachable (no verdict)       → data_flow                (silenced→VISIBLE: dangerous FN → fn=1)
 *   F3: module                         → function                 (silenced→VISIBLE: module-prior FN → fn=1)
 *   F4: unreachable                    → unreachable (no change)   (must NOT appear — not promoted)
 *   F5: a finding whose PD version changed (new project_dependency_id) → excluded by the
 *       stable key (proves "vuln gone because upgraded" is not counted as a promotion)
 *
 * Also asserts a second project with no prior run is ignored, and that pdv_id
 * churn across runs does not affect the join (the key is project_dependency_id).
 *
 * Run: npx tsx test/silence-cross-run-drift-pglite.ts
 */

import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite/vector';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import * as fs from 'fs';
import * as path from 'path';

const SCHEMA_FILE = path.resolve(__dirname, '../../backend/database/schema.sql');

let failures = 0;
let passed = 0;
function eq(actual: unknown, expected: unknown, msg: string): void {
  const a = Number(actual);
  const e = Number(expected);
  if (a !== e) { console.error(`  FAIL: ${msg} (expected ${e}, got ${actual})`); failures++; }
  else { console.log(`  ok: ${msg} = ${e}`); passed++; }
}
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`  FAIL: ${msg}`); failures++; } else { console.log(`  ok: ${msg}`); passed++; }
}

const ORG = '11111111-1111-1111-1111-111111111111';
const P1 = '22222222-2222-2222-2222-222222222221';
const P2 = '22222222-2222-2222-2222-222222222222'; // no prior run → ignored
const R0 = 'run_prev';
const R1 = 'run_cur';

// Stable project_dependency_ids (survive across runs).
const PD1 = '33333333-3333-3333-3333-333333333331';
const PD2 = '33333333-3333-3333-3333-333333333332';
const PD3 = '33333333-3333-3333-3333-333333333333';
const PD4 = '33333333-3333-3333-3333-333333333334';
const PD5A = '33333333-3333-3333-3333-33333333335a'; // prior PD for the upgraded finding
const PD5B = '33333333-3333-3333-3333-33333333335b'; // cur PD (version changed → new id)

async function bootDb(): Promise<PGlite> {
  const db = new PGlite({ extensions: { vector, uuid_ossp } });
  await db.waitReady;
  await db.exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);
  await db.exec(`CREATE EXTENSION IF NOT EXISTS vector;`);
  await db.exec(`
    CREATE SCHEMA IF NOT EXISTS auth;
    CREATE TABLE IF NOT EXISTS auth.users (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text, created_at timestamptz DEFAULT now());
    CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;
    CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$ SELECT 'service_role'::text $$;
    CREATE OR REPLACE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE AS $$ SELECT NULL::text $$;
    CREATE TABLE IF NOT EXISTS public.aegis_memory (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid, category text, key text, content text, embedding vector(1536), expires_at timestamptz);
  `);
  await db.exec(`SET check_function_bodies = off;`);
  await db.exec(fs.readFileSync(SCHEMA_FILE, 'utf8'));
  return db;
}

// helper: insert one silence_events row (only the columns the differ reads).
function se(run: string, pdvId: string, pdId: string, osv: string, level: string, isReachable: boolean, verdict: string | null): string {
  const v = verdict === null ? 'NULL' : `'${verdict}'`;
  return `INSERT INTO public.silence_events
    (project_id, extraction_run_id, pdv_id, project_dependency_id, dependency_id, osv_id, reachability_level, is_reachable, verdict, graph_trusted, ast_parsed)
    VALUES ('${P1}', '${run}', '${pdvId}', '${pdId}', uuid_generate_v4(), '${osv}', '${level}', ${isReachable}, ${v}, true, true);`;
}

async function seed(db: PGlite): Promise<void> {
  await db.exec(`
    INSERT INTO organizations (id, name, created_at) VALUES ('${ORG}', 'org', NOW()) ON CONFLICT (id) DO NOTHING;
    INSERT INTO projects (id, organization_id, name, active_extraction_run_id, previous_extraction_run_id, created_at) VALUES
      ('${P1}', '${ORG}', 'p1', '${R1}', '${R0}', NOW()),
      ('${P2}', '${ORG}', 'p2', '${R1}', NULL,   NOW()) ON CONFLICT (id) DO NOTHING;
  `);

  // pdv_id intentionally DIFFERS between runs (run-specific). The differ must
  // join on project_dependency_id+osv_id, not pdv_id.
  // --- PREV run (R0): the silenced set ---
  await db.exec(se(R0, 'aa000000-0000-0000-0000-0000000000f1', PD1, 'CVE-1', 'unreachable', false, 'orphan_transitive_unreachable'));
  await db.exec(se(R0, 'aa000000-0000-0000-0000-0000000000f2', PD2, 'CVE-2', 'unreachable', false, null));
  await db.exec(se(R0, 'aa000000-0000-0000-0000-0000000000f3', PD3, 'CVE-3', 'module',      true,  null));
  await db.exec(se(R0, 'aa000000-0000-0000-0000-0000000000f4', PD4, 'CVE-4', 'unreachable', false, null));
  await db.exec(se(R0, 'aa000000-0000-0000-0000-0000000000f5', PD5A, 'CVE-5', 'unreachable', false, null));

  // --- CUR run (R1): the new verdicts ---
  await db.exec(se(R1, 'bb000000-0000-0000-0000-0000000000f1', PD1, 'CVE-1', 'module',     true,  'transitive_of_reachable'));       // unreachable→module: still silenced → fn=0
  await db.exec(se(R1, 'bb000000-0000-0000-0000-0000000000f2', PD2, 'CVE-2', 'data_flow',  true,  null));                            // unreachable→data_flow: VISIBLE → SILENCE FN
  await db.exec(se(R1, 'bb000000-0000-0000-0000-0000000000f3', PD3, 'CVE-3', 'function',   true,  null));                            // module→function: VISIBLE → SILENCE FN (module-prior)
  await db.exec(se(R1, 'bb000000-0000-0000-0000-0000000000f4', PD4, 'CVE-4', 'unreachable', false, null));                          // unchanged → excluded
  // F5: version bumped → new project_dependency_id PD5B (and the old finding is
  // gone). Joins on the stable key fail → excluded (correctly: it was upgraded).
  await db.exec(se(R1, 'bb000000-0000-0000-0000-0000000000f5', PD5B, 'CVE-5', 'confirmed', true,  null));
}

async function run<T = any>(db: PGlite, sql: string): Promise<T[]> {
  const res = await db.query<T>(sql);
  return res.rows;
}

async function main(): Promise<void> {
  const db = await bootDb();
  await seed(db);

  const rows = await run<any>(db, `SELECT * FROM silence_cross_run_drift() ORDER BY prior_verdict`);

  // Expected buckets (prior_verdict): only PROMOTED findings from P1.
  //   F1: prior_verdict 'orphan_transitive_unreachable' → module    (upgraded 1, fn 0 — still silenced)
  //   F2: prior_verdict 'unreachable' (COALESCE of null) → data_flow (upgraded 1, fn 1 — now visible)
  //   F3: prior_verdict 'module'                          → function  (upgraded 1, fn 1 — now visible)
  //   F4: not promoted → absent.  F5: stable-key miss → absent.  P2: no prior run → absent.
  assert(rows.length === 3, `three prior_verdict buckets (got ${rows.length})`);

  const byVerdict = new Map<string, any>(rows.map((r) => [r.prior_verdict, r]));

  // --- CASE 1: unreachable→module floor correction (still SILENCED → NOT a FN) ---
  // silence_fn_count counts prior-silenced findings that became VISIBLE (rnk>=2).
  // `module` (rnk 1) is still silenced/auto-ignored, so this healthy R1 correction
  // must NOT register as a silence false-negative.
  {
    const r = byVerdict.get('orphan_transitive_unreachable');
    assert(!!r, 'orphan_transitive_unreachable bucket present');
    eq(r?.upgraded_count, 1, 'orphan upgraded_count (informational: unreachable→module counts)');
    eq(r?.silence_fn_count, 0, 'orphan silence_fn_count = 0 (cur module is STILL silenced, rnk<2 → healthy R1 correction)');
    assert(Array.isArray(r?.to_levels) && r.to_levels.includes('module'), 'orphan to_levels includes module');
  }

  // --- CASE 2: unreachable→data_flow (silenced→VISIBLE: the DANGEROUS FN) ---
  {
    const r = byVerdict.get('unreachable');
    assert(!!r, 'unreachable bucket present');
    eq(r?.upgraded_count, 1, 'unreachable upgraded_count (F2)');
    eq(r?.silence_fn_count, 1, 'unreachable silence_fn_count = 1 (F2: prior unreachable, now data_flow = VISIBLE) — the dangerous transition');
    assert(Array.isArray(r?.to_levels) && r.to_levels.includes('data_flow'), 'unreachable to_levels includes data_flow');
  }

  // --- CASE 3: module→function (silenced→VISIBLE: locks the module-prior FN) ---
  // Prior tier `module` is SILENCED (rnk 1); current tier `function` is VISIBLE
  // (rnk 2). This MUST register as a silence FN — the old prior_level='unreachable'
  // filter wrongly dropped it.
  {
    const r = byVerdict.get('module');
    assert(!!r, 'module bucket present');
    eq(r?.upgraded_count, 1, 'module upgraded_count (F3)');
    eq(r?.silence_fn_count, 1, 'module silence_fn_count = 1 (F3: prior module silenced, now function = VISIBLE)');
    assert(Array.isArray(r?.to_levels) && r.to_levels.includes('function'), 'module to_levels includes function');
  }

  // --- aggregate sanity: total silence FN across the project = 2 (F2 + F3) ---
  // (the two silenced findings that crossed into the VISIBLE tier; F1 stayed
  // silenced at module, so it is NOT counted.)
  const totalFn = rows.reduce((s, r) => s + Number(r.silence_fn_count), 0);
  eq(totalFn, 2, 'total silence_fn across project = 2 (F2 unreachable→data_flow + F3 module→function)');

  // --- a project with no prior run produces no rows (P2 excluded entirely) ---
  const p2rows = rows.filter((r) => r.project_id === P2);
  eq(p2rows.length, 0, 'project with no previous_extraction_run_id is ignored');

  // --- empty DB sanity: dropping prior run from P1 makes it vanish ---
  await db.exec(`UPDATE projects SET previous_extraction_run_id = NULL WHERE id = '${P1}';`);
  const none = await run<any>(db, `SELECT * FROM silence_cross_run_drift()`);
  eq(none.length, 0, 'no projects with a prior run → empty result');

  console.log(`\n${passed} passed, ${failures} failed`);
  await db.close();
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
