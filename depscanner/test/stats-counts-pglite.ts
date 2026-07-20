/**
 * Hand-oracle test for the phase64b stats-counts RPCs:
 *   project_stats_counts(p_project_id, p_active_run_id)
 *   team_stats_counts(p_project_ids[], p_active_run_ids[])
 *   team_top_vulns(p_project_ids[], p_active_run_ids[])
 *
 * These replace the JS row-counting in project /stats and team /stats, which
 * silently truncated at PostgREST's 1000-row client cap. PGLite can't reproduce
 * that client cap, so this test instead proves the SQL math is correct against a
 * FIXED, hand-computed seed — and seeds a >1000-dep block to prove the SQL has no
 * such ceiling. It also boots the real schema.sql, so it doubles as a parse check
 * that the three functions were inserted into schema.sql correctly.
 *
 * Covered: DISTINCT vulnerable-dep counting, suppressed exclusion, the project-vs-team
 * SLA asymmetry (project SLA excludes suppressed; team SLA includes ALL rows), active-run
 * filtering, non-band ('moderate') severity, osv dedup + affected-project counts + worst
 * project in the top-5, and >1000 deps.
 *
 * Run: npx tsx test/stats-counts-pglite.ts
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
  if (a !== e) { console.error(`    FAIL: ${msg} (expected ${e}, got ${actual})`); failures++; }
  else { console.log(`    ok: ${msg} = ${e}`); passed++; }
}
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`    FAIL: ${msg}`); failures++; } else { console.log(`    ok: ${msg}`); passed++; }
}

const ORG = '11111111-1111-1111-1111-111111111111';
const P1 = '22222222-2222-2222-2222-222222222222';
const P2 = '22222222-2222-2222-2222-222222222223';
const D1 = '33333333-3333-3333-3333-333333333331';
const D2 = '33333333-3333-3333-3333-333333333332';
const D3 = '33333333-3333-3333-3333-333333333333';
const D5 = '33333333-3333-3333-3333-333333333335';
const D6 = '33333333-3333-3333-3333-333333333336';
const RUN1 = 'run_p1_active';
const RUN2 = 'run_p2_active';
const RUN_OLD = 'run_p1_stale';

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

async function seed(db: PGlite): Promise<void> {
  await db.exec(`
    INSERT INTO organizations (id, name, created_at) VALUES ('${ORG}', 'org', NOW()) ON CONFLICT (id) DO NOTHING;
    INSERT INTO projects (id, organization_id, name, active_extraction_run_id, created_at) VALUES
      ('${P1}', '${ORG}', 'p1', '${RUN1}', NOW()),
      ('${P2}', '${ORG}', 'p2', '${RUN2}', NOW()) ON CONFLICT (id) DO NOTHING;
  `);

  // --- P1 dependencies: D1 direct/compliant, D2 transitive/failing/outdated, D3 direct/not-evaluated ---
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, policy_result, is_outdated, created_at) VALUES
      ('${D1}','${P1}','d1','1.0.0', true,  'dependencies', '{"allowed": true}'::jsonb,  false, NOW()),
      ('${D2}','${P1}','d2','1.0.0', false, 'dependencies', '{"allowed": false}'::jsonb, true,  NOW()),
      ('${D3}','${P1}','d3','1.0.0', true,  'dependencies', NULL,                         false, NOW());
  `);
  // 1100 extra transitive deps (no policy) → proves deps_total counts past the 1000 client cap.
  await db.exec(`
    INSERT INTO project_dependencies (project_id, name, version, is_direct, source, created_at)
    SELECT '${P1}', 'pkg' || g, '1.0.0', false, 'dependencies', NOW() FROM generate_series(1, 1100) g;
  `);
  // A removed dep that must NOT count (removed_at set).
  await db.exec(`
    INSERT INTO project_dependencies (project_id, name, version, is_direct, source, removed_at, created_at)
    VALUES ('${P1}','removed','1.0.0', true, 'dependencies', NOW(), NOW());
  `);

  // --- P1 PDV (active run RUN1) ---
  // severity 'moderate' is a non-band value: counts in vuln_total only. CVE-D is suppressed.
  await db.exec(`
    INSERT INTO project_dependency_findings
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, is_reachable, suppressed, sla_status, depscore) VALUES
      ('${P1}','${D1}','CVE-A','critical','${RUN1}','open', true,  false, 'met',      95),
      ('${P1}','${D1}','CVE-B','high',    '${RUN1}','open', false, false, 'on_track', 90),
      ('${P1}','${D2}','CVE-C','medium',  '${RUN1}','open', false, false, 'breached', 70),
      ('${P1}','${D3}','CVE-MOD','moderate','${RUN1}','open', false, false, 'warning', 40),
      ('${P1}','${D2}','CVE-D','critical','${RUN1}','open', false, true,  'exempt',   88),
      ('${P1}','${D1}','CVE-OLD','critical','${RUN_OLD}','open', true, false, 'met',   99);
  `);

  // --- P2 PDV (active run RUN2) ---
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, created_at) VALUES
      ('${D5}','${P2}','d5','1.0.0', true, 'dependencies', NOW()),
      ('${D6}','${P2}','d6','1.0.0', true, 'dependencies', NOW());
    INSERT INTO project_dependency_findings
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, is_reachable, suppressed, sla_status, depscore) VALUES
      ('${P2}','${D5}','CVE-A','critical','${RUN2}','open', true,  false, NULL, 80),
      ('${P2}','${D6}','CVE-X','critical','${RUN2}','open', false, false, NULL, 99);
  `);
}

async function run<T = any>(db: PGlite, sql: string): Promise<T[]> {
  const res = await db.query<T>(sql);
  return res.rows;
}

async function main(): Promise<void> {
  const db = await bootDb();
  await seed(db);

  console.log('project_stats_counts(P1, RUN1):');
  const [ps] = await run<any>(db, `SELECT * FROM project_stats_counts('${P1}', '${RUN1}')`);
  eq(ps.vuln_total, 4, 'vuln_total (A,B,C,MOD; D suppressed + OLD stale-run excluded)');
  eq(ps.vuln_critical, 1, 'vuln_critical (A)');
  eq(ps.vuln_high, 1, 'vuln_high (B)');
  eq(ps.vuln_medium, 1, 'vuln_medium (C)');
  eq(ps.vuln_low, 0, 'vuln_low');
  eq(ps.reachable_count, 1, 'reachable_count (A)');
  eq(ps.deps_vulnerable, 3, 'deps_vulnerable DISTINCT (D1,D2,D3)');
  eq(ps.sla_met, 1, 'sla_met (A)');
  eq(ps.sla_on_track, 1, 'sla_on_track (B)');
  eq(ps.sla_breached, 1, 'sla_breached (C)');
  eq(ps.sla_warning, 1, 'sla_warning (MOD)');
  eq(ps.sla_exempt, 0, 'sla_exempt = 0 (CVE-D exempt but suppressed → project SLA excludes it)');
  eq(ps.deps_total, 1103, 'deps_total counts past the 1000-row cap (3 + 1100; removed excluded)');
  eq(ps.deps_direct, 2, 'deps_direct (D1, D3)');
  eq(ps.deps_transitive, 1101, 'deps_transitive (D2 + 1100)');
  eq(ps.deps_outdated, 1, 'deps_outdated (D2)');
  eq(ps.deps_compliant, 1, 'deps_compliant (D1 allowed=true)');
  eq(ps.deps_failing, 1, 'deps_failing (D2 allowed=false)');

  console.log('team_stats_counts([P1,P2], [RUN1,RUN2]):');
  const [ts] = await run<any>(db,
    `SELECT * FROM team_stats_counts(ARRAY['${P1}','${P2}']::uuid[], ARRAY['${RUN1}','${RUN2}']::text[])`);
  eq(ts.vuln_total, 6, 'team vuln_total (P1 A,B,C,MOD + P2 A,X; D suppressed excluded)');
  eq(ts.vuln_critical, 3, 'team vuln_critical (P1 A + P2 A,X)');
  eq(ts.vuln_high, 1, 'team vuln_high (P1 B)');
  eq(ts.vuln_medium, 1, 'team vuln_medium (P1 C)');
  eq(ts.sla_met, 1, 'team sla_met');
  eq(ts.sla_on_track, 1, 'team sla_on_track');
  eq(ts.sla_breached, 1, 'team sla_breached');
  eq(ts.sla_warning, 1, 'team sla_warning');
  eq(ts.sla_exempt, 1, 'team sla_exempt = 1 (CVE-D suppressed but team SLA counts ALL rows)');

  console.log('team_top_vulns([P1,P2], [RUN1,RUN2]):');
  const top = await run<any>(db,
    `SELECT * FROM team_top_vulns(ARRAY['${P1}','${P2}']::uuid[], ARRAY['${RUN1}','${RUN2}']::text[])`);
  eq(top.length, 3, 'top vulns count (CVE-X, CVE-A, CVE-B; medium/moderate/suppressed excluded)');
  assert(top[0]?.osv_id === 'CVE-X' && Number(top[0]?.depscore) === 99 && top[0]?.worst_project_id === P2 && Number(top[0]?.affected_project_count) === 1,
    'row0 = CVE-X depscore99 worst=P2 affected=1');
  assert(top[1]?.osv_id === 'CVE-A' && Number(top[1]?.depscore) === 95 && top[1]?.worst_project_id === P1 && Number(top[1]?.affected_project_count) === 2,
    'row1 = CVE-A depscore95 (dedup keeps the higher P1 row) worst=P1 affected=2 (P1+P2)');
  assert(top[2]?.osv_id === 'CVE-B' && Number(top[2]?.depscore) === 90 && top[2]?.worst_project_id === P1 && Number(top[2]?.affected_project_count) === 1,
    'row2 = CVE-B depscore90 worst=P1 affected=1');

  console.log('empty cases:');
  const [pe] = await run<any>(db, `SELECT * FROM project_stats_counts('${P1}', '__no_active_run__')`);
  eq(pe.vuln_total, 0, 'no-active-run sentinel → zero vulns');
  eq(pe.deps_total, 1103, 'no-active-run still returns the real dep total (deps are run-agnostic)');
  const [te] = await run<any>(db, `SELECT * FROM team_stats_counts(ARRAY[]::uuid[], ARRAY[]::text[])`);
  eq(te.vuln_total, 0, 'empty team → zero vulns');
  const teTop = await run<any>(db, `SELECT * FROM team_top_vulns(ARRAY[]::uuid[], ARRAY[]::text[])`);
  eq(teTop.length, 0, 'empty team → no top vulns');

  console.log(`\n${passed} passed, ${failures} failed`);
  await db.close();
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
