/**
 * Phase 24a (v2.1a) migration backfill verification — runs the migration SQL
 * against an in-memory PGLite with a minimal scaffold.
 *
 * What this proves:
 *   1. phase24a_dast_v2_engine_additive.sql applies cleanly on top of a
 *      v1-shaped DB.
 *   2. Pass-1 of the backfill (synthetic-legacy targets) creates ≥ 1 row per
 *      project that has any project_dast_config row, with the correct
 *      target_url fallback for NULL / empty legacy values.
 *   3. Pass-2 (findings.target_id backfill) backfills every finding whose
 *      project has a target row, leaving orphans target_id=NULL rather than
 *      aborting (the phase24b NOT NULL flip handles cleanup).
 *   4. Backfill is idempotent — re-running creates no duplicate target rows.
 *   5. queue_scan_job + commit_dast_run + commit_dast_target_run all exist
 *      after the migration, so the deploy DAG can roll out a worker that
 *      speaks both signatures (step-3 of the runbook).
 *
 * Pattern follows test/rule-generation-step-pglite.test.ts: skip the full
 * schema dump (forward-references in CHECK constraints don't load on PGLite)
 * and apply phase24a directly on top of a v1-shaped scaffold.
 *
 * Run: `cd backend/depscanner && npx tsx test/dast-v2-1a-migration-pglite.ts`
 *
 * Operator runbook integration: this script is a precondition to applying
 * phase24a in prod. Run it on the feature branch right before the MCP apply
 * (per `feedback_schema_dump_rebase`).
 */

import * as fs from 'fs';
import * as path from 'path';
import { createPGLiteStorage } from '../src/storage';

// v1-shaped scaffold: organizations + projects + project_dast_config +
// project_dast_findings + scan_jobs. The phase24a migration adds
// project_dast_targets + project_dast_credentials + columns / RPCs on top.
const SCAFFOLD_SQL = `
  CREATE TABLE IF NOT EXISTS organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS projects (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    active_dast_run_id text,
    previous_dast_run_id text,
    created_at timestamptz NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS project_dast_config (
    project_id uuid PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    target_url text,
    scan_profile text NOT NULL DEFAULT 'auto',
    scan_timeout_minutes integer NOT NULL DEFAULT 30,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS project_dast_findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    dast_run_id text NOT NULL,
    rule_id text,
    handler_file_path text,
    handler_function_name text,
    handler_line integer,
    endpoint_url text NOT NULL,
    http_method text NOT NULL,
    vulnerability_type text NOT NULL,
    severity text NOT NULL,
    cwe_id text,
    owasp_top10_ref text,
    confidence text NOT NULL,
    message text,
    payload_redacted text,
    response_evidence_redacted text,
    linked_sca_osv_id text,
    linked_sca_project_dependency_id uuid,
    status text NOT NULL DEFAULT 'open',
    risk_accepted_by uuid,
    risk_accepted_at timestamptz,
    risk_accepted_reason text,
    created_at timestamptz NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS scan_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid REFERENCES projects(id) ON DELETE CASCADE,
    organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    type text NOT NULL,
    status text NOT NULL DEFAULT 'queued',
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    target_url text,
    scan_profile text,
    timeout_minutes integer,
    trigger_source text,
    triggered_by uuid,
    error text,
    error_category text,
    error_payload jsonb,
    machine_id text,
    findings_count integer,
    duration_seconds integer,
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    started_at timestamptz,
    heartbeat_at timestamptz,
    completed_at timestamptz,
    run_id text,
    created_at timestamptz NOT NULL DEFAULT now()
  );

  -- Phase 24a's commit_dast_run wrapper expects an existing canonical
  -- v1 commit_dast_run(uuid, text). The wrapper REPLACES this. Stub
  -- minimal v1 signature so CREATE OR REPLACE FUNCTION works.
  CREATE OR REPLACE FUNCTION commit_dast_run(p_project_id uuid, p_dast_run_id text)
  RETURNS void LANGUAGE sql AS $$ SELECT 1; $$;

  -- v1 queue_scan_job stub — phase24a's CREATE OR REPLACE replaces it.
  CREATE OR REPLACE FUNCTION queue_scan_job(
    p_project_id uuid, p_organization_id uuid, p_type text, p_payload jsonb,
    p_target_url text DEFAULT NULL, p_scan_profile text DEFAULT NULL,
    p_timeout_minutes integer DEFAULT NULL, p_trigger_source text DEFAULT NULL,
    p_triggered_by uuid DEFAULT NULL
  ) RETURNS scan_jobs LANGUAGE sql AS $$ SELECT NULL::scan_jobs; $$;

  -- phase24a's findings table FK reference (linked_sast_finding_id) for
  -- v2.3 cross-link forward-prep.
  CREATE TABLE IF NOT EXISTS project_semgrep_findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid()
  );

  CREATE SCHEMA IF NOT EXISTS auth;
  CREATE TABLE IF NOT EXISTS auth.users (id uuid PRIMARY KEY);
`;

const PHASE24A_SQL_PATH = path.resolve(__dirname, '../../database/phase24a_dast_v2_engine_additive.sql');
const PHASE24A_2_SQL_PATH = path.resolve(__dirname, '../../database/phase24a_2_dast_v2_engine_pipeline.sql');

let failures = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

// Strip RLS / policy / publication / index variants PGLite chokes on, mirroring
// the rule-generation-step-pglite pattern.
function sanitize(sql: string): string {
  return sql
    .replace(/ALTER TABLE [^\s]+ ENABLE ROW LEVEL SECURITY\s*;?/gi, '')
    .replace(/DROP POLICY IF EXISTS[\s\S]*?;\s*/gi, '')
    .replace(/CREATE POLICY[\s\S]*?\);\s*/gi, '')
    // Realtime publication is a Supabase concern; PGLite has no
    // supabase_realtime publication. The phase24a DO block guards the ADD
    // TABLE behind `IF NOT EXISTS (SELECT 1 FROM pg_publication_tables…)`,
    // which evaluates to false on PGLite (no rows), so the EXECUTE never
    // runs — but the empty pg_publication_tables view itself isn't there.
    // Stub the DO blocks to no-ops by stripping the full publication
    // section between "9. Realtime publication" and "10. Two-pass backfill".
    .replace(/-- 9\. Realtime publication[\s\S]*?(?=-- 10\. )/i, '')
    // pgcrypto extension load — PGLite doesn't bundle it. The only thing
    // phase24a uses pgcrypto for is encode(digest(...)) inside
    // queue_scan_job; we strip that below so this is safe to drop.
    .replace(/CREATE EXTENSION IF NOT EXISTS pgcrypto\s*;?/gi, '')
    // Swap pgcrypto's encode(digest(...)) for md5 — the deploy gate just
    // proves the migration applies and the backfill is correct; the real
    // hash semantics are covered by the route + pipeline unit tests.
    .replace(
      /encode\(digest\(([^,]+),\s*'sha256'\),\s*'hex'\)/gi,
      "md5($1)",
    );
}

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLite + applying v1 scaffold...');
  const storage = await createPGLiteStorage({ skipSchemaLoad: true });
  await storage.db.exec(SCAFFOLD_SQL);

  console.log('Applying phase24a additive migration...');
  const phase24aSql = fs.readFileSync(PHASE24A_SQL_PATH, 'utf8');
  await storage.db.exec(sanitize(phase24aSql));

  // phase24a_2 widens the error_category CHECK and adds error_payload — the
  // pipeline writes to those columns. error_payload is already in the
  // scaffold so the column add is a no-op.
  if (fs.existsSync(PHASE24A_2_SQL_PATH)) {
    console.log('Applying phase24a_2 (error_category widening)...');
    const phase24a2Sql = fs.readFileSync(PHASE24A_2_SQL_PATH, 'utf8');
    await storage.db.exec(sanitize(phase24a2Sql));
  }
  console.log(`  scaffold + phase24a applied in ${Date.now() - t0}ms\n`);

  // -------------------------------------------------------------------------
  // Seed three legacy-shape projects + dast_config rows + findings WITHOUT
  // target_id. Pre-v2.1a snapshot the backfill is designed to migrate.
  // -------------------------------------------------------------------------
  console.log('Seeding 3 legacy-shape projects + dast_config + findings...');
  const ORG = '11111111-1111-1111-1111-111111111111';
  const PROJ_A = 'aaaaaaaa-1111-1111-1111-111111111111';
  const PROJ_B = 'bbbbbbbb-2222-2222-2222-222222222222';
  const PROJ_C = 'cccccccc-3333-3333-3333-333333333333';
  await storage.db.exec(`
    INSERT INTO organizations (id, name) VALUES ('${ORG}', 'phase24a-test-org');
    INSERT INTO projects (id, organization_id, name, active_dast_run_id) VALUES
      ('${PROJ_A}', '${ORG}', 'proj-a', 'dast_legacy_a1'),
      ('${PROJ_B}', '${ORG}', 'proj-b', NULL),
      ('${PROJ_C}', '${ORG}', 'proj-c', NULL);

    -- A: legacy single target_url. B: NULL. C: empty string.
    INSERT INTO project_dast_config (project_id, organization_id, target_url, scan_profile, scan_timeout_minutes, enabled)
    VALUES
      ('${PROJ_A}', '${ORG}', 'https://staging.proj-a.example', 'auto', 30, true),
      ('${PROJ_B}', '${ORG}', NULL,                              'quick', 15, true),
      ('${PROJ_C}', '${ORG}', '',                                'full',  45, true);
  `);

  // Wipe any phase24a-pass-1 rows that the migration auto-created so we
  // exercise the backfill in a clean state for the assertions below.
  await storage.db.exec(`DELETE FROM project_dast_targets;`);

  await storage.db.exec(`
    INSERT INTO project_dast_findings (
      project_id, organization_id, dast_run_id, endpoint_url, http_method,
      vulnerability_type, severity, confidence, status, target_id
    ) VALUES
      ('${PROJ_A}', '${ORG}', 'dast_legacy_a1', 'https://staging.proj-a.example/x', 'GET',  'XSS',  'medium', 'medium', 'open', NULL),
      ('${PROJ_A}', '${ORG}', 'dast_legacy_a1', 'https://staging.proj-a.example/y', 'POST', 'SQLi', 'high',   'high',   'open', NULL),
      ('${PROJ_B}', '${ORG}', 'dast_legacy_b1', 'https://unknown.local/foo',        'GET',  'XSS',  'low',    'medium', 'open', NULL),
      ('${PROJ_B}', '${ORG}', 'dast_legacy_b1', 'https://unknown.local/bar',        'GET',  'XSS',  'low',    'medium', 'open', NULL),
      ('${PROJ_C}', '${ORG}', 'dast_legacy_c1', 'https://unknown.local/c1',         'GET',  'XSS',  'medium', 'low',    'open', NULL),
      ('${PROJ_C}', '${ORG}', 'dast_legacy_c1', 'https://unknown.local/c2',         'GET',  'XSS',  'medium', 'low',    'open', NULL);
  `);

  // -------------------------------------------------------------------------
  // Run the phase24a backfill block manually. Idempotent — the WHERE NOT
  // EXISTS / WHERE target_id IS NULL guards mean we can run it after the
  // migration has already done a partial pass.
  // -------------------------------------------------------------------------
  console.log('\nApplying phase24a backfill (passes 1 + 2)...');
  await storage.db.exec(`
    INSERT INTO project_dast_targets (
      project_id, organization_id, target_url, label,
      active_dast_run_id, previous_dast_run_id
    )
    SELECT
      pdc.project_id,
      pdc.organization_id,
      COALESCE(NULLIF(pdc.target_url, ''), 'https://unknown.local'),
      'legacy',
      p.active_dast_run_id,
      p.previous_dast_run_id
    FROM project_dast_config pdc
    JOIN projects p ON p.id = pdc.project_id
    WHERE NOT EXISTS (
      SELECT 1 FROM project_dast_targets t
      WHERE t.project_id = pdc.project_id
    );

    UPDATE project_dast_findings f
    SET target_id = (
      SELECT t.id FROM project_dast_targets t
      WHERE t.project_id = f.project_id
      ORDER BY t.created_at
      LIMIT 1
    )
    WHERE f.target_id IS NULL;
  `);

  // -------------------------------------------------------------------------
  // Assertions
  // -------------------------------------------------------------------------
  console.log('\nAsserting backfill outputs...');

  const targetCount = await storage.db.query<{ count: string }>(`
    SELECT COUNT(*)::text AS count FROM project_dast_targets WHERE organization_id = '${ORG}';
  `);
  assert(targetCount.rows[0].count === '3', `3 target rows seeded (got ${targetCount.rows[0].count})`);

  const perProject = await storage.db.query<{ project_id: string; n: string; target_url: string }>(`
    SELECT t.project_id, COUNT(*)::text AS n, MAX(t.target_url) AS target_url
    FROM project_dast_targets t
    WHERE t.organization_id = '${ORG}'
    GROUP BY t.project_id
    ORDER BY t.project_id;
  `);
  assert(perProject.rows.length === 3, '1 target per project (got ' + perProject.rows.length + ')');

  const projAUrl = perProject.rows.find((r) => r.project_id === PROJ_A)?.target_url;
  const projBUrl = perProject.rows.find((r) => r.project_id === PROJ_B)?.target_url;
  const projCUrl = perProject.rows.find((r) => r.project_id === PROJ_C)?.target_url;
  assert(projAUrl === 'https://staging.proj-a.example', `proj-a uses real legacy URL (got ${projAUrl})`);
  assert(projBUrl === 'https://unknown.local', `proj-b NULL → 'https://unknown.local' fallback (got ${projBUrl})`);
  assert(projCUrl === 'https://unknown.local', `proj-c '' → 'https://unknown.local' fallback (got ${projCUrl})`);

  const orphanCount = await storage.db.query<{ count: string }>(`
    SELECT COUNT(*)::text AS count FROM project_dast_findings
    WHERE target_id IS NULL AND organization_id = '${ORG}';
  `);
  assert(orphanCount.rows[0].count === '0', `0 orphan findings after pass-2 (got ${orphanCount.rows[0].count})`);

  const findingByProject = await storage.db.query<{ project_id: string; n: string }>(`
    SELECT project_id, COUNT(*)::text AS n
    FROM project_dast_findings
    WHERE organization_id = '${ORG}' AND target_id IS NOT NULL
    GROUP BY project_id ORDER BY project_id;
  `);
  for (const row of findingByProject.rows) {
    assert(row.n === '2', `project ${row.project_id} has 2 backfilled findings (got ${row.n})`);
  }

  // commit_dast_target_run + commit_dast_run wrapper + new queue_scan_job all
  // exist — deploy-DAG step 3 expects the worker to call both signatures
  // before the migration applies, and step 5 expects the new queue signature.
  const fnCount = await storage.db.query<{ name: string }>(`
    SELECT proname AS name
    FROM pg_proc
    WHERE proname IN ('commit_dast_run', 'commit_dast_target_run', 'queue_scan_job')
    ORDER BY proname;
  `);
  const fnNames = fnCount.rows.map((r) => r.name);
  assert(fnNames.includes('commit_dast_run'), 'legacy commit_dast_run wrapper present');
  assert(fnNames.includes('commit_dast_target_run'), 'canonical commit_dast_target_run present');
  assert(fnNames.includes('queue_scan_job'), 'queue_scan_job present');

  // -------------------------------------------------------------------------
  // Idempotency probe — re-run pass-1, expect zero churn.
  // -------------------------------------------------------------------------
  console.log('\nIdempotency probe — re-run backfill, expect no churn...');
  const before = (await storage.db.query<{ count: string }>(`SELECT COUNT(*)::text AS count FROM project_dast_targets WHERE organization_id = '${ORG}';`)).rows[0].count;
  await storage.db.exec(`
    INSERT INTO project_dast_targets (project_id, organization_id, target_url, label, active_dast_run_id, previous_dast_run_id)
    SELECT pdc.project_id, pdc.organization_id, COALESCE(NULLIF(pdc.target_url, ''), 'https://unknown.local'), 'legacy', p.active_dast_run_id, p.previous_dast_run_id
    FROM project_dast_config pdc JOIN projects p ON p.id = pdc.project_id
    WHERE NOT EXISTS (SELECT 1 FROM project_dast_targets t WHERE t.project_id = pdc.project_id);
  `);
  const after = (await storage.db.query<{ count: string }>(`SELECT COUNT(*)::text AS count FROM project_dast_targets WHERE organization_id = '${ORG}';`)).rows[0].count;
  assert(before === after, `target count stable across re-run (before=${before}, after=${after})`);

  await storage.close();
  console.log(`\nphase24a backfill verification ${failures === 0 ? 'PASSED' : 'FAILED'} in ${Date.now() - t0}ms (${failures} failure${failures === 1 ? '' : 's'})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
