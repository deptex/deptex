/**
 * SC2 + N2 PGLite gate — boots a fresh PGLite from backend/database/schema.sql
 * and asserts the DAST scoring fixes land in the live schema:
 *
 *   N2 — project_dast_findings.depscore column exists.
 *   SC2 — confirm_pdvs_from_dast_run, when it promotes a cross-linked PDV to
 *         reachability_level='confirmed', RECOMPUTES contextual_depscore to the
 *         confirmed tier (weight 1.0) instead of keeping the pre-DAST value:
 *           - NULL contextual (EPD never ran) is filled with
 *             base_depscore_no_reachability × COALESCE(epd_factor, 1.0).
 *           - an existing (EPD/composition-derived) contextual is left untouched.
 *
 * Run: `cd depscanner && npx tsx test/dast-confirm-contextual-depscore-pglite.ts`
 */

import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite/vector';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import * as fs from 'fs';
import * as path from 'path';

const SCHEMA_FILE = path.resolve(__dirname, '../../backend/database/schema.sql');

let failures = 0;
let passed = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`    FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`    ok: ${msg}`);
    passed++;
  }
}

async function bootDb(): Promise<PGlite> {
  const db = new PGlite({ extensions: { vector, uuid_ossp } });
  await db.waitReady;
  await db.exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);
  await db.exec(`CREATE EXTENSION IF NOT EXISTS vector;`);
  await db.exec(`
    CREATE SCHEMA IF NOT EXISTS auth;
    CREATE TABLE IF NOT EXISTS auth.users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email text,
      created_at timestamptz DEFAULT now()
    );
    CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;
    CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$ SELECT 'service_role'::text $$;
    CREATE OR REPLACE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE AS $$ SELECT NULL::text $$;
    CREATE TABLE IF NOT EXISTS public.aegis_memory (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      organization_id uuid,
      category text,
      key text,
      content text,
      embedding vector(1536),
      expires_at timestamptz
    );
  `);
  await db.exec(`SET check_function_bodies = off;`);
  const schemaSql = fs.readFileSync(SCHEMA_FILE, 'utf8');
  await db.exec(schemaSql);
  return db;
}

const ORG = '11111111-1111-1111-1111-111111111111';

async function seedProject(db: PGlite, projectId: string, importance: number): Promise<void> {
  await db.exec(`
    INSERT INTO organizations (id, name, created_at)
    VALUES ('${ORG}', 'org', NOW())
    ON CONFLICT (id) DO NOTHING;
  `);
  await db.exec(`
    INSERT INTO projects (id, organization_id, name, importance, created_at)
    VALUES ('${projectId}', '${ORG}', 'proj-${projectId}', ${importance}, NOW())
    ON CONFLICT (id) DO NOTHING;
  `);
}

async function seedDep(db: PGlite, id: string, projectId: string, runId: string): Promise<string> {
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES ('${id}', '${projectId}', 'dep-${id.slice(0, 8)}', '1.0.0', true, 'dependencies', '${runId}', NOW());
  `);
  return id;
}

async function seedPdv(
  db: PGlite,
  opts: {
    projectId: string;
    depId: string;
    osvId: string;
    runId: string;
    reachability: string;
    baseNoReach: number | null;
    depscore: number | null;
    epdFactor: number | null;
    contextual: number | null;
  },
): Promise<void> {
  const lit = (v: number | null) => (v == null ? 'NULL' : String(v));
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id,
       status, reachability_level, base_depscore_no_reachability, depscore,
       epd_factor, contextual_depscore, detected_at, created_at)
    VALUES
      ('${opts.projectId}', '${opts.depId}', '${opts.osvId}', 'high', '${opts.runId}',
       'open', '${opts.reachability}', ${lit(opts.baseNoReach)}, ${lit(opts.depscore)},
       ${lit(opts.epdFactor)}, ${lit(opts.contextual)}, NOW(), NOW());
  `);
}

async function seedTarget(db: PGlite, projectId: string): Promise<string> {
  const r = await db.query<{ id: string }>(`
    INSERT INTO project_dast_targets (project_id, organization_id, target_url, label)
    VALUES ('${projectId}', '${ORG}', 'https://app.example.com/', 'T')
    RETURNING id;
  `);
  return r.rows[0].id;
}

async function seedNucleiFinding(
  db: PGlite,
  opts: { projectId: string; targetId: string; dastRunId: string; linkedDepId: string; cveIds: string[] },
): Promise<string> {
  const meta = JSON.stringify({ nuclei: { cve_ids: opts.cveIds } });
  const r = await db.query<{ id: string }>(`
    INSERT INTO project_dast_findings
      (project_id, organization_id, target_id, dast_run_id, engine,
       endpoint_url, http_method, vulnerability_type, severity, confidence,
       linked_sca_project_dependency_id, cross_link_metadata, created_at)
    VALUES
      ('${opts.projectId}', '${ORG}', '${opts.targetId}', '${opts.dastRunId}', 'nuclei',
       'https://app/x', 'GET', 'CVE', 'high', 'high',
       '${opts.linkedDepId}', '${meta}'::jsonb, NOW())
    RETURNING id;
  `);
  return r.rows[0].id;
}

interface PdvScore {
  reachability_level: string;
  contextual_depscore: string | null;
  depscore: number | null;
}

async function readPdv(db: PGlite, projectId: string): Promise<PdvScore> {
  const r = await db.query<PdvScore>(
    `SELECT reachability_level, contextual_depscore, depscore
       FROM project_dependency_vulnerabilities WHERE project_id = '${projectId}'`,
  );
  return r.rows[0];
}

async function main(): Promise<void> {
  const t0 = Date.now();
  console.log('SC2/N2 DAST scoring PGLite gate\n');

  // -- N2: depscore column exists on project_dast_findings.
  console.log('[N2] project_dast_findings.depscore column');
  {
    const db = await bootDb();
    const col = await db.query<{ data_type: string }>(`
      SELECT data_type FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'project_dast_findings'
         AND column_name = 'depscore';
    `);
    assert(col.rows.length === 1, `[N2] depscore column exists`);
    assert(col.rows[0]?.data_type === 'integer', `[N2] depscore is integer (got ${col.rows[0]?.data_type})`);
    await db.close();
  }

  // -- SC2 case 1: NULL contextual (EPD never ran), epd_factor NULL.
  //    Promotion fills contextual = base_no_reach × 1.0.
  console.log('\n[SC2] NULL contextual is filled at the confirmed tier');
  {
    const db = await bootDb();
    const PROJ = 'a0000000-0000-0000-0000-000000000001';
    await seedProject(db, PROJ, 1.0);
    const dep = await seedDep(db, 'a1000000-0000-0000-0000-000000000001', PROJ, 'run1');
    // module-tier: depscore = base(80) × 0.5 = 40, contextual NULL, no EPD.
    await seedPdv(db, {
      projectId: PROJ, depId: dep, osvId: 'CVE-2021-44228', runId: 'run1',
      reachability: 'module', baseNoReach: 80, depscore: 40, epdFactor: null, contextual: null,
    });
    const before = await readPdv(db, PROJ);
    assert(before.contextual_depscore === null, `[SC2] pre: contextual is NULL`);

    const target = await seedTarget(db, PROJ);
    await seedNucleiFinding(db, { projectId: PROJ, targetId: target, dastRunId: 'dast_a', linkedDepId: dep, cveIds: ['CVE-2021-44228'] });
    const rows = await db.query(`SELECT * FROM confirm_pdvs_from_dast_run('${PROJ}'::uuid, 'dast_a'::text)`);
    assert(rows.rows.length === 1, `[SC2] RPC flips 1 PDV`);

    const after = await readPdv(db, PROJ);
    assert(after.reachability_level === 'confirmed', `[SC2] reachability now confirmed`);
    assert(after.contextual_depscore !== null, `[SC2] contextual is no longer NULL`);
    // base_no_reach (80) × COALESCE(epd_factor, 1.0) = 80.0000
    assert(Number(after.contextual_depscore) === 80, `[SC2] contextual = base_no_reach × 1.0 = 80 (got ${after.contextual_depscore})`);
    // The fix lifts it above the stale module-tier depscore (40).
    assert(Number(after.contextual_depscore) > Number(before.depscore), `[SC2] confirmed contextual (${after.contextual_depscore}) > stale module depscore (${before.depscore})`);
    await db.close();
  }

  // -- SC2 case 2: NULL contextual but an epd_factor present (e.g. carried
  //    diagnostic). Promotion fills contextual = base_no_reach × epd_factor.
  console.log('\n[SC2] NULL contextual with epd_factor folds the factor in');
  {
    const db = await bootDb();
    const PROJ = 'a0000000-0000-0000-0000-000000000002';
    await seedProject(db, PROJ, 1.0);
    const dep = await seedDep(db, 'a1000000-0000-0000-0000-000000000002', PROJ, 'run1');
    await seedPdv(db, {
      projectId: PROJ, depId: dep, osvId: 'CVE-2019-10744', runId: 'run1',
      reachability: 'function', baseNoReach: 70, depscore: 49, epdFactor: 0.5, contextual: null,
    });
    const target = await seedTarget(db, PROJ);
    await seedNucleiFinding(db, { projectId: PROJ, targetId: target, dastRunId: 'dast_b', linkedDepId: dep, cveIds: ['CVE-2019-10744'] });
    await db.query(`SELECT * FROM confirm_pdvs_from_dast_run('${PROJ}'::uuid, 'dast_b'::text)`);
    const after = await readPdv(db, PROJ);
    assert(after.reachability_level === 'confirmed', `[SC2] reachability now confirmed`);
    // 70 × 0.5 = 35.0000
    assert(Number(after.contextual_depscore) === 35, `[SC2] contextual = base_no_reach × epd_factor = 35 (got ${after.contextual_depscore})`);
    await db.close();
  }

  // -- SC2 case 3: existing (EPD-derived) contextual is NOT clobbered.
  console.log('\n[SC2] existing contextual is preserved (no clobber)');
  {
    const db = await bootDb();
    const PROJ = 'a0000000-0000-0000-0000-000000000003';
    await seedProject(db, PROJ, 1.0);
    const dep = await seedDep(db, 'a1000000-0000-0000-0000-000000000003', PROJ, 'run1');
    // data_flow PDV that EPD already scored — contextual already set + a
    // composition-style factor baked in (62.5 ≠ base × epd_factor).
    await seedPdv(db, {
      projectId: PROJ, depId: dep, osvId: 'CVE-2020-8163', runId: 'run1',
      reachability: 'data_flow', baseNoReach: 90, depscore: 81, epdFactor: 0.8, contextual: 62.5,
    });
    const target = await seedTarget(db, PROJ);
    await seedNucleiFinding(db, { projectId: PROJ, targetId: target, dastRunId: 'dast_c', linkedDepId: dep, cveIds: ['CVE-2020-8163'] });
    await db.query(`SELECT * FROM confirm_pdvs_from_dast_run('${PROJ}'::uuid, 'dast_c'::text)`);
    const after = await readPdv(db, PROJ);
    assert(after.reachability_level === 'confirmed', `[SC2] reachability now confirmed`);
    assert(Number(after.contextual_depscore) === 62.5, `[SC2] existing contextual preserved (got ${after.contextual_depscore})`);
    await db.close();
  }

  console.log(
    `\nSC2/N2 DAST scoring gate ${failures === 0 ? 'PASSED' : 'FAILED'} in ${Date.now() - t0}ms ` +
      `(${passed} passed, ${failures} failure${failures === 1 ? '' : 's'})`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
