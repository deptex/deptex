/**
 * phase25a (DAST v2.1c) migration verification — boots a fresh PGLite, loads
 * the post-phase25a backend/database/schema.sql, and exercises the
 * confirm_pdvs_from_dast_run RPC + carry-forward survival.
 *
 * What this proves:
 *   1. Additive schema: project_dast_findings.kev, the three
 *      project_dependency_findings.runtime_confirmed_* columns, the
 *      FK + covering index all exist.
 *   2. scan_jobs_dast_columns_match_type accepts type='dast_nuclei' carrying
 *      target_url (the widened CHECK).
 *   3. _pdv_reachability_rank('confirmed') = 4.
 *   4. confirm_pdvs_from_dast_run is callable and its tenancy guard raises
 *      P0001 on a (project_id, dast_run_id) pair with no Nuclei findings.
 *   5. Positive flip — CVE-primary (pdv.osv_id matches a Nuclei cve_id).
 *   6. Positive flip — GHSA-aliased (pdv.osv_id is a GHSA id, CVE in aliases[]).
 *   7. Positive flip — case-insensitive (lowercase osv_id + lowercase cve_ids).
 *   8. Negative — URL miss (finding links a different project_dependency).
 *   9. Negative — CVE miss (cve_ids do not intersect osv_id/aliases).
 *  10. Negative — cross-project (pdv in another project is untouched).
 *  11. Idempotency — a second RPC call flips nothing (rank guard).
 *  12. Multi-row — highest-severity Nuclei finding wins the confirmation.
 *  13. One call writes BOTH reachability_level='confirmed' AND
 *      re_review_triggered_at on the same row.
 *  14. Re-review skipped when the asset tier sets enabled=false.
 *  15. Re-review skipped when the asset tier sets reachability_upgrade=false.
 *  16. asset_tier_id NULL is safe (re-review fires by default).
 *  17. Carry-forward — after a flip, finalize_extraction's carry_forward keeps
 *      runtime_confirmed_* and forces reachability_level='confirmed' on the
 *      next extraction generation.
 *  18. REVOKE/GRANT — confirm_pdvs_from_dast_run is EXECUTE-able by service_role
 *      and not by PUBLIC (pg_proc.proacl).
 *
 * Run: `cd depscanner && npx tsx test/dast-v2-1c-migration-pglite.ts`
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
  // Disable parse-time body validation: the schema dump emits functions in
  // name order, so a few forward-reference each other (e.g.
  // pg_catalog_dump_v1_all calls pg_catalog_dump_v1, defined later).
  await db.exec(`SET check_function_bodies = off;`);
  const schemaSql = fs.readFileSync(SCHEMA_FILE, 'utf8');
  await db.exec(schemaSql);
  return db;
}

const ORG = '11111111-1111-1111-1111-111111111111';
const ORG_OTHER = '22222222-2222-2222-2222-222222222222';

/** Insert an org + project (+ optional asset tier). */
async function seedProject(
  db: PGlite,
  opts: { projectId: string; orgId: string; activeRun?: string | null; assetTierId?: string | null },
): Promise<void> {
  await db.exec(`
    INSERT INTO organizations (id, name, created_at)
    VALUES ('${opts.orgId}', 'org-${opts.orgId.slice(0, 8)}', NOW())
    ON CONFLICT (id) DO NOTHING;
  `);
  const activeLit = opts.activeRun == null ? 'NULL' : `'${opts.activeRun}'`;
  const tierLit = opts.assetTierId == null ? 'NULL' : `'${opts.assetTierId}'`;
  await db.exec(`
    INSERT INTO projects (id, organization_id, name, active_extraction_run_id, asset_tier_id, created_at)
    VALUES ('${opts.projectId}', '${opts.orgId}', 'proj-${opts.projectId}', ${activeLit}, ${tierLit}, NOW())
    ON CONFLICT (id) DO NOTHING;
  `);
}

async function seedAssetTier(db: PGlite, id: string, orgId: string, rereview: object): Promise<void> {
  await db.exec(`
    INSERT INTO organization_asset_tiers (id, organization_id, name, rereview_settings)
    VALUES ('${id}', '${orgId}', 'tier-${id}', '${JSON.stringify(rereview)}'::jsonb);
  `);
}

/** Insert a project_dependency, return its id. */
async function seedDep(
  db: PGlite,
  opts: { id: string; projectId: string; name: string; version: string; runId: string },
): Promise<string> {
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES ('${opts.id}', '${opts.projectId}', '${opts.name}', '${opts.version}', true, 'dependencies', '${opts.runId}', NOW());
  `);
  return opts.id;
}

/** Insert a PDV row. */
async function seedPdv(
  db: PGlite,
  opts: {
    projectId: string;
    depId: string;
    osvId: string;
    runId: string;
    reachability: string;
    severity?: string;
    aliases?: string[];
  },
): Promise<void> {
  const aliasesLit =
    opts.aliases && opts.aliases.length
      ? `ARRAY[${opts.aliases.map((a) => `'${a}'`).join(',')}]::text[]`
      : `ARRAY[]::text[]`;
  await db.exec(`
    INSERT INTO project_dependency_findings
      (project_id, project_dependency_id, osv_id, severity, aliases, extraction_run_id,
       status, reachability_level, detected_at, created_at)
    VALUES
      ('${opts.projectId}', '${opts.depId}', '${opts.osvId}', '${opts.severity ?? 'high'}',
       ${aliasesLit}, '${opts.runId}', 'open', '${opts.reachability}', NOW(), NOW());
  `);
}

/** Insert a project_dast_target, return its id. */
async function seedTarget(db: PGlite, projectId: string, orgId: string): Promise<string> {
  const r = await db.query<{ id: string }>(`
    INSERT INTO project_dast_targets (project_id, organization_id, target_url, label)
    VALUES ('${projectId}', '${orgId}', 'https://app-${projectId.slice(0, 8)}.example.com/', 'T')
    RETURNING id;
  `);
  return r.rows[0].id;
}

/** Insert a Nuclei project_dast_finding, return its id. */
async function seedNucleiFinding(
  db: PGlite,
  opts: {
    projectId: string;
    orgId: string;
    targetId: string;
    dastRunId: string;
    linkedDepId: string | null;
    cveIds: string[];
    severity?: string;
  },
): Promise<string> {
  const linkedLit = opts.linkedDepId == null ? 'NULL' : `'${opts.linkedDepId}'`;
  const meta = JSON.stringify({ nuclei: { cve_ids: opts.cveIds } });
  const r = await db.query<{ id: string }>(`
    INSERT INTO project_dast_findings
      (project_id, organization_id, target_id, dast_run_id, engine,
       endpoint_url, http_method, vulnerability_type, severity, confidence,
       linked_sca_project_dependency_id, cross_link_metadata, created_at)
    VALUES
      ('${opts.projectId}', '${opts.orgId}', '${opts.targetId}', '${opts.dastRunId}', 'nuclei',
       'https://app/x', 'GET', 'CVE', '${opts.severity ?? 'high'}', 'high',
       ${linkedLit}, '${meta}'::jsonb, NOW())
    RETURNING id;
  `);
  return r.rows[0].id;
}

interface RpcRow {
  pdv_id: string;
  osv_id: string;
  prior_reachability_level: string;
  new_reachability_level: string;
}

async function callRpc(db: PGlite, projectId: string, dastRunId: string): Promise<RpcRow[]> {
  const r = await db.query<RpcRow>(
    `SELECT * FROM confirm_pdvs_from_dast_run($1::uuid, $2::text)`,
    [projectId, dastRunId],
  );
  return r.rows;
}

// -----------------------------------------------------------------------------
// Scenario A — schema assertions
// -----------------------------------------------------------------------------
async function testSchema(): Promise<void> {
  console.log('\n[A] phase25a schema additions');
  const db = await bootDb();

  const cols = await db.query<{ table_name: string; column_name: string }>(`
    SELECT table_name, column_name FROM information_schema.columns
    WHERE table_schema = 'public'
      AND ((table_name = 'project_dast_findings' AND column_name = 'kev')
        OR (table_name = 'project_dependency_findings'
            AND column_name IN ('runtime_confirmed_at', 'runtime_confirmed_dast_finding_id', 'runtime_confirmed_prior_level')));
  `);
  assert(cols.rows.length === 4, `[A] kev + 3 runtime_confirmed_* columns exist (got ${cols.rows.length})`);

  const fk = await db.query<{ count: string }>(`
    SELECT COUNT(*)::text AS count FROM pg_constraint
    WHERE conname = 'project_dependency_findings_runtime_confirmed_dast_fkey';
  `);
  assert(fk.rows[0].count === '1', `[A] runtime_confirmed FK exists (got ${fk.rows[0].count})`);

  const idx = await db.query<{ count: string }>(`
    SELECT COUNT(*)::text AS count FROM pg_indexes
    WHERE indexname = 'project_dependency_findings_runtime_confirmed_fk';
  `);
  assert(idx.rows[0].count === '1', `[A] runtime_confirmed covering index exists (got ${idx.rows[0].count})`);

  const rank = await db.query<{ rank: number }>(`SELECT _pdv_reachability_rank('confirmed') AS rank;`);
  assert(Number(rank.rows[0].rank) === 4, `[A] _pdv_reachability_rank('confirmed') = 4 (got ${rank.rows[0].rank})`);

  // Widened CHECK: a dast_nuclei scan_jobs row carrying target_url must insert.
  await seedProject(db, { projectId: 'a0000000-0000-0000-0000-0000000000a1', orgId: ORG });
  let checkErr = '';
  try {
    await db.exec(`
      INSERT INTO scan_jobs (project_id, organization_id, type, status, target_url)
      VALUES ('a0000000-0000-0000-0000-0000000000a1', '${ORG}', 'dast_nuclei', 'queued', 'https://app.example.com/');
    `);
  } catch (e: any) {
    checkErr = String(e?.message ?? '');
  }
  assert(checkErr === '', `[A] scan_jobs CHECK accepts type='dast_nuclei' + target_url (got: ${checkErr.slice(0, 120)})`);

  // REVOKE/GRANT — apply phase25a's ACL statements against a freshly-created
  // service_role (schema.sql does not dump ACLs), then check proacl.
  await db.exec(`DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
      CREATE ROLE service_role;
    END IF;
  END $$;`);
  await db.exec(`REVOKE EXECUTE ON FUNCTION public.confirm_pdvs_from_dast_run(uuid, text) FROM PUBLIC;`);
  await db.exec(`GRANT EXECUTE ON FUNCTION public.confirm_pdvs_from_dast_run(uuid, text) TO service_role;`);
  const acl = await db.query<{ proacl: string | null }>(`
    SELECT proacl::text AS proacl FROM pg_proc WHERE proname = 'confirm_pdvs_from_dast_run';
  `);
  const aclStr = acl.rows[0]?.proacl ?? '';
  assert(/service_role=X/.test(aclStr), `[A] service_role has EXECUTE on the RPC (proacl: ${aclStr})`);
  // A PUBLIC grant appears as an entry with an empty grantee ("=X/owner").
  assert(!/(?:^\{|,)=/.test(aclStr), `[A] PUBLIC EXECUTE revoked from the RPC (proacl: ${aclStr})`);

  await db.close();
}

// -----------------------------------------------------------------------------
// Scenario B — RPC flip behavior
// -----------------------------------------------------------------------------
async function testRpcFlips(): Promise<void> {
  console.log('\n[B] confirm_pdvs_from_dast_run flip behavior');
  const db = await bootDb();

  // -- Tenancy guard: a run with no Nuclei findings raises P0001.
  const PROJ_GUARD = 'b0000000-0000-0000-0000-000000000001';
  await seedProject(db, { projectId: PROJ_GUARD, orgId: ORG });
  let guardErr: any;
  try {
    await callRpc(db, PROJ_GUARD, 'dast_nonexistent_run');
  } catch (e: any) {
    guardErr = e;
  }
  assert(
    /has no Nuclei findings/.test(String(guardErr?.message ?? '')),
    `[B] tenancy guard raises on Nuclei-less run (got: ${String(guardErr?.message ?? '').slice(0, 120)})`,
  );
  assert(String(guardErr?.code ?? '') === 'P0001', `[B] tenancy guard ERRCODE = P0001 (got: ${guardErr?.code})`);

  // -- Positive flip: CVE-primary.
  const PROJ_CVE = 'b0000000-0000-0000-0000-000000000002';
  await seedProject(db, { projectId: PROJ_CVE, orgId: ORG });
  const depCve = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000002', projectId: PROJ_CVE, name: 'tomcat', version: '9.0.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_CVE, depId: depCve, osvId: 'CVE-2017-12615', runId: 'run1', reachability: 'module' });
  const tCve = await seedTarget(db, PROJ_CVE, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_CVE, orgId: ORG, targetId: tCve, dastRunId: 'dast_cve', linkedDepId: depCve, cveIds: ['CVE-2017-12615'] });
  const cveRows = await callRpc(db, PROJ_CVE, 'dast_cve');
  assert(cveRows.length === 1, `[B] CVE-primary flip returns 1 row (got ${cveRows.length})`);
  assert(cveRows[0]?.new_reachability_level === 'confirmed', `[B] CVE-primary new level = confirmed`);
  assert(cveRows[0]?.prior_reachability_level === 'module', `[B] CVE-primary prior level = module`);

  // -- Positive flip: GHSA-aliased.
  const PROJ_GHSA = 'b0000000-0000-0000-0000-000000000003';
  await seedProject(db, { projectId: PROJ_GHSA, orgId: ORG });
  const depGhsa = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000003', projectId: PROJ_GHSA, name: 'lodash', version: '4.17.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_GHSA, depId: depGhsa, osvId: 'GHSA-jf85-cpcp-j695', runId: 'run1', reachability: 'function', aliases: ['CVE-2019-10744'] });
  const tGhsa = await seedTarget(db, PROJ_GHSA, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_GHSA, orgId: ORG, targetId: tGhsa, dastRunId: 'dast_ghsa', linkedDepId: depGhsa, cveIds: ['CVE-2019-10744'] });
  const ghsaRows = await callRpc(db, PROJ_GHSA, 'dast_ghsa');
  assert(ghsaRows.length === 1 && ghsaRows[0].new_reachability_level === 'confirmed', `[B] GHSA-aliased flip confirmed`);

  // -- Positive flip: case-insensitive (lowercase osv_id + lowercase cve_ids).
  const PROJ_CASE = 'b0000000-0000-0000-0000-000000000004';
  await seedProject(db, { projectId: PROJ_CASE, orgId: ORG });
  const depCase = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000004', projectId: PROJ_CASE, name: 'struts', version: '2.0.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_CASE, depId: depCase, osvId: 'cve-2018-11776', runId: 'run1', reachability: 'module' });
  const tCase = await seedTarget(db, PROJ_CASE, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_CASE, orgId: ORG, targetId: tCase, dastRunId: 'dast_case', linkedDepId: depCase, cveIds: ['cve-2018-11776'] });
  const caseRows = await callRpc(db, PROJ_CASE, 'dast_case');
  assert(caseRows.length === 1 && caseRows[0].new_reachability_level === 'confirmed', `[B] case-insensitive flip confirmed`);

  // -- Negative: URL miss — finding links a different project_dependency.
  const PROJ_URL = 'b0000000-0000-0000-0000-000000000005';
  await seedProject(db, { projectId: PROJ_URL, orgId: ORG });
  const depUrlA = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000005', projectId: PROJ_URL, name: 'jackson', version: '2.9.0', runId: 'run1' });
  const depUrlB = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000015', projectId: PROJ_URL, name: 'guava', version: '30.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_URL, depId: depUrlA, osvId: 'CVE-2019-12384', runId: 'run1', reachability: 'module' });
  const tUrl = await seedTarget(db, PROJ_URL, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_URL, orgId: ORG, targetId: tUrl, dastRunId: 'dast_url', linkedDepId: depUrlB, cveIds: ['CVE-2019-12384'] });
  const urlRows = await callRpc(db, PROJ_URL, 'dast_url');
  assert(urlRows.length === 0, `[B] URL miss flips nothing (got ${urlRows.length})`);

  // -- Negative: CVE miss — cve_ids do not intersect osv_id/aliases.
  const PROJ_CVEMISS = 'b0000000-0000-0000-0000-000000000006';
  await seedProject(db, { projectId: PROJ_CVEMISS, orgId: ORG });
  const depCveMiss = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000006', projectId: PROJ_CVEMISS, name: 'spring', version: '5.0.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_CVEMISS, depId: depCveMiss, osvId: 'CVE-2022-22965', runId: 'run1', reachability: 'module' });
  const tCveMiss = await seedTarget(db, PROJ_CVEMISS, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_CVEMISS, orgId: ORG, targetId: tCveMiss, dastRunId: 'dast_cvemiss', linkedDepId: depCveMiss, cveIds: ['CVE-1999-0001'] });
  const cveMissRows = await callRpc(db, PROJ_CVEMISS, 'dast_cvemiss');
  assert(cveMissRows.length === 0, `[B] CVE miss flips nothing (got ${cveMissRows.length})`);

  // -- Negative: cross-project — a PDV in another project is untouched.
  const PROJ_X = 'b0000000-0000-0000-0000-000000000007';
  const PROJ_Y = 'b0000000-0000-0000-0000-000000000008';
  await seedProject(db, { projectId: PROJ_X, orgId: ORG });
  await seedProject(db, { projectId: PROJ_Y, orgId: ORG });
  const depX = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000007', projectId: PROJ_X, name: 'log4j', version: '2.14.0', runId: 'run1' });
  const depY = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000008', projectId: PROJ_Y, name: 'log4j', version: '2.14.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_X, depId: depX, osvId: 'CVE-2021-44228', runId: 'run1', reachability: 'module' });
  await seedPdv(db, { projectId: PROJ_Y, depId: depY, osvId: 'CVE-2021-44228', runId: 'run1', reachability: 'module' });
  const tX = await seedTarget(db, PROJ_X, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_X, orgId: ORG, targetId: tX, dastRunId: 'dast_x', linkedDepId: depX, cveIds: ['CVE-2021-44228'] });
  const xRows = await callRpc(db, PROJ_X, 'dast_x');
  assert(xRows.length === 1, `[B] cross-project: project X flips its own PDV`);
  const yLevel = await db.query<{ reachability_level: string }>(
    `SELECT reachability_level FROM project_dependency_findings WHERE project_id = '${PROJ_Y}'`,
  );
  assert(yLevel.rows[0].reachability_level === 'module', `[B] cross-project: project Y PDV untouched (still module)`);

  // -- Idempotency: re-run flips nothing (rank guard, already confirmed).
  const xAgain = await callRpc(db, PROJ_X, 'dast_x');
  assert(xAgain.length === 0, `[B] idempotency: second RPC call flips nothing (got ${xAgain.length})`);

  // -- Multi-row: highest-severity Nuclei finding wins the confirmation.
  const PROJ_MULTI = 'b0000000-0000-0000-0000-000000000009';
  await seedProject(db, { projectId: PROJ_MULTI, orgId: ORG });
  const depMulti = await seedDep(db, { id: 'b1000000-0000-0000-0000-000000000009', projectId: PROJ_MULTI, name: 'rails', version: '6.0.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_MULTI, depId: depMulti, osvId: 'CVE-2020-8163', runId: 'run1', reachability: 'module' });
  const tMulti = await seedTarget(db, PROJ_MULTI, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_MULTI, orgId: ORG, targetId: tMulti, dastRunId: 'dast_multi', linkedDepId: depMulti, cveIds: ['CVE-2020-8163'], severity: 'low' });
  const critFindingId = await seedNucleiFinding(db, { projectId: PROJ_MULTI, orgId: ORG, targetId: tMulti, dastRunId: 'dast_multi', linkedDepId: depMulti, cveIds: ['CVE-2020-8163'], severity: 'critical' });
  const multiRows = await callRpc(db, PROJ_MULTI, 'dast_multi');
  assert(multiRows.length === 1, `[B] multi-row flip returns exactly 1 PDV row (got ${multiRows.length})`);
  const winner = await db.query<{ runtime_confirmed_dast_finding_id: string }>(
    `SELECT runtime_confirmed_dast_finding_id FROM project_dependency_findings WHERE project_id = '${PROJ_MULTI}'`,
  );
  assert(
    winner.rows[0].runtime_confirmed_dast_finding_id === critFindingId,
    `[B] multi-row: highest-severity (critical) finding wins the confirmation`,
  );

  await db.close();
}

// -----------------------------------------------------------------------------
// Scenario C — re-review gating
// -----------------------------------------------------------------------------
async function testReReviewGating(): Promise<void> {
  console.log('\n[C] re-review column writes (single UPDATE)');
  const db = await bootDb();

  // -- Default (no asset tier): one call writes BOTH confirmed + re_review.
  const PROJ_DEF = 'c0000000-0000-0000-0000-000000000001';
  await seedProject(db, { projectId: PROJ_DEF, orgId: ORG, assetTierId: null });
  const depDef = await seedDep(db, { id: 'c1000000-0000-0000-0000-000000000001', projectId: PROJ_DEF, name: 'flask', version: '1.0.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_DEF, depId: depDef, osvId: 'CVE-2018-1000656', runId: 'run1', reachability: 'module' });
  const tDef = await seedTarget(db, PROJ_DEF, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_DEF, orgId: ORG, targetId: tDef, dastRunId: 'dast_def', linkedDepId: depDef, cveIds: ['CVE-2018-1000656'] });
  await callRpc(db, PROJ_DEF, 'dast_def');
  const defRow = await db.query<{ reachability_level: string; re_review_triggered_at: string | null; re_review_reasons: any }>(
    `SELECT reachability_level, re_review_triggered_at, re_review_reasons FROM project_dependency_findings WHERE project_id = '${PROJ_DEF}'`,
  );
  assert(defRow.rows[0].reachability_level === 'confirmed', `[C] asset_tier NULL: reachability_level = confirmed`);
  assert(defRow.rows[0].re_review_triggered_at !== null, `[C] asset_tier NULL: re_review_triggered_at written in same call`);
  const defReasons = Array.isArray(defRow.rows[0].re_review_reasons) ? defRow.rows[0].re_review_reasons : [];
  assert(
    defReasons.some((r: any) => r?.trigger === 'reachability_upgrade'),
    `[C] asset_tier NULL: re_review_reasons carries reachability_upgrade`,
  );

  // -- enabled=false: reachability flips, re-review skipped.
  const PROJ_OFF = 'c0000000-0000-0000-0000-000000000002';
  const TIER_OFF = 'c2000000-0000-0000-0000-000000000002';
  await seedAssetTier(db, TIER_OFF, ORG, { enabled: false, triggers: { reachability_upgrade: true } });
  await seedProject(db, { projectId: PROJ_OFF, orgId: ORG, assetTierId: TIER_OFF });
  const depOff = await seedDep(db, { id: 'c1000000-0000-0000-0000-000000000002', projectId: PROJ_OFF, name: 'django', version: '2.0.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_OFF, depId: depOff, osvId: 'CVE-2019-19844', runId: 'run1', reachability: 'module' });
  const tOff = await seedTarget(db, PROJ_OFF, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_OFF, orgId: ORG, targetId: tOff, dastRunId: 'dast_off', linkedDepId: depOff, cveIds: ['CVE-2019-19844'] });
  await callRpc(db, PROJ_OFF, 'dast_off');
  const offRow = await db.query<{ reachability_level: string; re_review_triggered_at: string | null }>(
    `SELECT reachability_level, re_review_triggered_at FROM project_dependency_findings WHERE project_id = '${PROJ_OFF}'`,
  );
  assert(offRow.rows[0].reachability_level === 'confirmed', `[C] enabled=false: reachability still flips to confirmed`);
  assert(offRow.rows[0].re_review_triggered_at === null, `[C] enabled=false: re_review_triggered_at NOT written`);

  // -- reachability_upgrade=false: reachability flips, re-review skipped.
  const PROJ_NRU = 'c0000000-0000-0000-0000-000000000003';
  const TIER_NRU = 'c2000000-0000-0000-0000-000000000003';
  await seedAssetTier(db, TIER_NRU, ORG, { enabled: true, triggers: { reachability_upgrade: false } });
  await seedProject(db, { projectId: PROJ_NRU, orgId: ORG, assetTierId: TIER_NRU });
  const depNru = await seedDep(db, { id: 'c1000000-0000-0000-0000-000000000003', projectId: PROJ_NRU, name: 'nextjs', version: '12.0.0', runId: 'run1' });
  await seedPdv(db, { projectId: PROJ_NRU, depId: depNru, osvId: 'CVE-2022-23646', runId: 'run1', reachability: 'module' });
  const tNru = await seedTarget(db, PROJ_NRU, ORG);
  await seedNucleiFinding(db, { projectId: PROJ_NRU, orgId: ORG, targetId: tNru, dastRunId: 'dast_nru', linkedDepId: depNru, cveIds: ['CVE-2022-23646'] });
  await callRpc(db, PROJ_NRU, 'dast_nru');
  const nruRow = await db.query<{ reachability_level: string; re_review_triggered_at: string | null }>(
    `SELECT reachability_level, re_review_triggered_at FROM project_dependency_findings WHERE project_id = '${PROJ_NRU}'`,
  );
  assert(nruRow.rows[0].reachability_level === 'confirmed', `[C] reachability_upgrade=false: reachability still flips`);
  assert(nruRow.rows[0].re_review_triggered_at === null, `[C] reachability_upgrade=false: re_review_triggered_at NOT written`);

  await db.close();
}

// -----------------------------------------------------------------------------
// Scenario D — carry-forward survival across extraction runs
// -----------------------------------------------------------------------------
async function testCarryForwardSurvival(): Promise<void> {
  console.log('\n[D] runtime confirmation survives the next extraction run');
  const db = await bootDb();

  const PROJ = 'd0000000-0000-0000-0000-000000000001';
  const PREV_RUN = 'run_prev';
  const NEW_RUN = 'run_new';
  await seedProject(db, { projectId: PROJ, orgId: ORG, activeRun: PREV_RUN });

  // Prev-run dep + PDV: runtime-confirmed (reachability_level='confirmed',
  // runtime_confirmed_* populated by a prior RPC flip).
  const OLD_DEP = 'd1000000-0000-0000-0000-000000000001';
  const NEW_DEP = 'd1000000-0000-0000-0000-000000000002';
  await seedDep(db, { id: OLD_DEP, projectId: PROJ, name: 'tomcat', version: '9.0.0', runId: PREV_RUN });
  await seedDep(db, { id: NEW_DEP, projectId: PROJ, name: 'tomcat', version: '9.0.1', runId: NEW_RUN });

  const tCarry = await seedTarget(db, PROJ, ORG);
  const findingId = await seedNucleiFinding(db, { projectId: PROJ, orgId: ORG, targetId: tCarry, dastRunId: 'dast_carry', linkedDepId: OLD_DEP, cveIds: ['CVE-2017-12615'] });

  // Prev-run PDV starts at 'module'; flip it via the RPC so runtime_confirmed_*
  // are set the way production would set them.
  await seedPdv(db, { projectId: PROJ, depId: OLD_DEP, osvId: 'CVE-2017-12615', runId: PREV_RUN, reachability: 'module' });
  await callRpc(db, PROJ, 'dast_carry');

  const prevConfirmed = await db.query<{ reachability_level: string; runtime_confirmed_at: string | null }>(
    `SELECT reachability_level, runtime_confirmed_at FROM project_dependency_findings
     WHERE project_id = '${PROJ}' AND extraction_run_id = '${PREV_RUN}'`,
  );
  assert(prevConfirmed.rows[0].reachability_level === 'confirmed', `[D] pre: prev-run PDV is confirmed`);
  assert(prevConfirmed.rows[0].runtime_confirmed_at !== null, `[D] pre: prev-run PDV has runtime_confirmed_at`);

  // New-run PDV: a fresh generation, reachability re-computed to 'module'
  // (the classifier has no knowledge of the runtime confirmation).
  await seedPdv(db, { projectId: PROJ, depId: NEW_DEP, osvId: 'CVE-2017-12615', runId: NEW_RUN, reachability: 'module' });

  // finalize_extraction runs the carry_forward block.
  await db.query(`SELECT finalize_extraction($1::uuid, $1::uuid, $2::text)`, [PROJ, NEW_RUN]);

  const carried = await db.query<{
    reachability_level: string;
    runtime_confirmed_at: string | null;
    runtime_confirmed_dast_finding_id: string | null;
    runtime_confirmed_prior_level: string | null;
  }>(
    `SELECT reachability_level, runtime_confirmed_at, runtime_confirmed_dast_finding_id, runtime_confirmed_prior_level
     FROM project_dependency_findings
     WHERE project_id = '${PROJ}' AND extraction_run_id = '${NEW_RUN}'`,
  );
  assert(carried.rows.length === 1, `[D] one new-run PDV exists`);
  assert(carried.rows[0].reachability_level === 'confirmed', `[D] new-run PDV reachability forced back to confirmed`);
  assert(carried.rows[0].runtime_confirmed_at !== null, `[D] new-run PDV keeps runtime_confirmed_at`);
  assert(
    carried.rows[0].runtime_confirmed_dast_finding_id === findingId,
    `[D] new-run PDV keeps runtime_confirmed_dast_finding_id`,
  );
  assert(
    carried.rows[0].runtime_confirmed_prior_level === 'module',
    `[D] new-run PDV keeps runtime_confirmed_prior_level (module)`,
  );

  await db.close();
}

async function main(): Promise<void> {
  const t0 = Date.now();
  console.log('phase25a (DAST v2.1c) PGLite migration gate\n');
  await testSchema();
  await testRpcFlips();
  await testReReviewGating();
  await testCarryForwardSurvival();
  console.log(
    `\nphase25a verification ${failures === 0 ? 'PASSED' : 'FAILED'} in ${Date.now() - t0}ms ` +
      `(${passed} passed, ${failures} failure${failures === 1 ? '' : 's'})`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
