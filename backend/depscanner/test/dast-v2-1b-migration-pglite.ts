/**
 * Phase 24b (v2.1b) destructive migration verification — applies phase24a
 * THEN phase24b to an in-memory PGLite, then exercises 13 RPC + schema
 * assertions against the post-v2.1b state.
 *
 * What this proves:
 *   1. phase24a + phase24b apply cleanly back-to-back.
 *   2. commit_dast_target_run rotates the per-target active_dast_run_id
 *      pointer (canonical RPC; survives v2.1b).
 *   3. commit_dast_target_run handles the first-ever-commit path
 *      (active_dast_run_id starts NULL, no suppression carry).
 *   4. Suppression carry-forward via handler-identity (handler_file_path +
 *      handler_function_name match across runs).
 *   5. Suppression carry-forward via endpoint-identity (handler_file_path
 *      IS NULL on both old and new — fall back to endpoint_url + method).
 *   6. queue_scan_job rejects NULL p_target_id with the expected message
 *      AND ERRCODE='P0001'.
 *   7. queue_scan_job happy path inserts exactly one scan_jobs row.
 *   8. queue_scan_job tenant-drift check raises P0001.
 *   9. queue_scan_job SSRF check rejects link-local, RFC1918, and Fly
 *      internal hosts — three distinct host classes.
 *   10. queue_scan_job per-project cap raises after one queued/processing.
 *   11. queue_scan_job per-org cap raises after five queued across five
 *       distinct projects in the same org.
 *   12. project_dast_findings.target_id is NOT NULL (insert with NULL fails).
 *   13. Forward-compat CHECK widenings preserved: engine='nuclei'|'merged'
 *       accepted, engine='garbage' rejected; auth_strategy='recorded'
 *       accepted on credentials.
 *   14. Exactly one queue_scan_job overload exists post-migration.
 *
 * Run: `cd backend/depscanner && npx tsx test/dast-v2-1b-migration-pglite.ts`
 *
 * Pattern: skip schema.sql (forward-references in CHECK constraints don't
 * load on PGLite); apply phase24a + phase24b directly on a v1-shaped scaffold.
 */

import * as fs from 'fs';
import * as path from 'path';
import { createPGLiteStorage } from '../src/storage';

// v1-shaped scaffold (organizations + projects + project_dast_config +
// project_dast_findings + scan_jobs). The phase24a stubs that v2.1a needed
// (legacy commit_dast_run wrapper + 9-arg queue_scan_job) are gone — phase24a
// creates both fresh, and phase24b drops the wrapper anyway.
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
const PHASE24B_SQL_PATH = path.resolve(__dirname, '../../database/phase24b_dast_v2_engine_destructive.sql');

let failures = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

// Strip RLS / policy / publication / pgcrypto bits PGLite chokes on,
// mirroring the rule-generation-step-pglite pattern.
function sanitize(sql: string): string {
  return sql
    .replace(/ALTER TABLE [^\s]+ ENABLE ROW LEVEL SECURITY\s*;?/gi, '')
    .replace(/DROP POLICY IF EXISTS[\s\S]*?;\s*/gi, '')
    .replace(/CREATE POLICY[\s\S]*?\);\s*/gi, '')
    .replace(/-- 9\. Realtime publication[\s\S]*?(?=-- 10\. )/i, '')
    .replace(/CREATE EXTENSION IF NOT EXISTS pgcrypto\s*;?/gi, '')
    .replace(
      /encode\(digest\(([^,]+),\s*'sha256'\),\s*'hex'\)/gi,
      "md5($1)",
    );
}

const ORG = '11111111-1111-1111-1111-111111111111';
const PROJ_A = 'aaaaaaaa-1111-1111-1111-111111111111';
const PROJ_B = 'bbbbbbbb-2222-2222-2222-222222222222';
const PROJ_C = 'cccccccc-3333-3333-3333-333333333333';
const PROJ_D = 'dddddddd-4444-4444-4444-444444444444';
const PROJ_E = 'eeeeeeee-5555-5555-5555-555555555555';
const PROJ_F = 'ffffffff-6666-6666-6666-666666666666';
const ORG_OTHER = '22222222-2222-2222-2222-222222222222';
const PROJ_OTHER = 'a0000000-0000-0000-0000-000000000001';

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLite + applying v1 scaffold...');
  const storage = await createPGLiteStorage({ skipSchemaLoad: true });
  await storage.db.exec(SCAFFOLD_SQL);

  console.log('Applying phase24a additive migration...');
  const phase24aSql = fs.readFileSync(PHASE24A_SQL_PATH, 'utf8');
  await storage.db.exec(sanitize(phase24aSql));

  if (fs.existsSync(PHASE24A_2_SQL_PATH)) {
    console.log('Applying phase24a_2 (error_category widening)...');
    const phase24a2Sql = fs.readFileSync(PHASE24A_2_SQL_PATH, 'utf8');
    await storage.db.exec(sanitize(phase24a2Sql));
  }

  console.log('Applying phase24b destructive migration...');
  const phase24bSql = fs.readFileSync(PHASE24B_SQL_PATH, 'utf8');
  await storage.db.exec(sanitize(phase24bSql));
  console.log(`  scaffold + phase24a + phase24b applied in ${Date.now() - t0}ms\n`);

  // ---------------------------------------------------------------------------
  // Seed: 1 org, 6 projects, 1 target each. PROJ_F is held in reserve for the
  // 6th-call in the per-org cap assertion. PROJ_OTHER lives in a different org
  // and powers the tenant-drift assertion.
  // ---------------------------------------------------------------------------
  console.log('Seeding orgs + projects + targets...');
  await storage.db.exec(`
    INSERT INTO organizations (id, name) VALUES
      ('${ORG}',       'phase24b-test-org'),
      ('${ORG_OTHER}', 'phase24b-other-org');

    INSERT INTO projects (id, organization_id, name) VALUES
      ('${PROJ_A}',     '${ORG}',       'proj-a'),
      ('${PROJ_B}',     '${ORG}',       'proj-b'),
      ('${PROJ_C}',     '${ORG}',       'proj-c'),
      ('${PROJ_D}',     '${ORG}',       'proj-d'),
      ('${PROJ_E}',     '${ORG}',       'proj-e'),
      ('${PROJ_F}',     '${ORG}',       'proj-f'),
      ('${PROJ_OTHER}', '${ORG_OTHER}', 'proj-other');

    INSERT INTO project_dast_targets (project_id, organization_id, target_url, label) VALUES
      ('${PROJ_A}',     '${ORG}',       'https://app-a.example.com/', 'A'),
      ('${PROJ_B}',     '${ORG}',       'https://app-b.example.com/', 'B'),
      ('${PROJ_C}',     '${ORG}',       'https://app-c.example.com/', 'C'),
      ('${PROJ_D}',     '${ORG}',       'https://app-d.example.com/', 'D'),
      ('${PROJ_E}',     '${ORG}',       'https://app-e.example.com/', 'E'),
      ('${PROJ_F}',     '${ORG}',       'https://app-f.example.com/', 'F'),
      ('${PROJ_OTHER}', '${ORG_OTHER}', 'https://app-other.example.com/', 'OTHER');
  `);

  async function targetIdFor(projectId: string): Promise<string> {
    const r = await storage.db.query<{ id: string }>(
      `SELECT id FROM project_dast_targets WHERE project_id = '${projectId}';`,
    );
    return r.rows[0].id;
  }
  const targetA = await targetIdFor(PROJ_A);
  const targetB = await targetIdFor(PROJ_B);
  const targetC = await targetIdFor(PROJ_C);
  const targetD = await targetIdFor(PROJ_D);
  const targetE = await targetIdFor(PROJ_E);
  const targetF = await targetIdFor(PROJ_F);
  const targetOther = await targetIdFor(PROJ_OTHER);

  // ---------------------------------------------------------------------------
  // 1. commit_dast_target_run rotation (canonical RPC, preserved verbatim)
  // ---------------------------------------------------------------------------
  console.log('\n[1] commit_dast_target_run pointer rotation...');
  await storage.db.exec(`
    UPDATE project_dast_targets
       SET active_dast_run_id = 'dast_run_prior'
     WHERE id = '${targetA}';
  `);
  await storage.db.exec(`SELECT commit_dast_target_run('${targetA}'::uuid, 'dast_run_new');`);
  const rotated = await storage.db.query<{ active_dast_run_id: string; previous_dast_run_id: string }>(`
    SELECT active_dast_run_id, previous_dast_run_id
    FROM project_dast_targets WHERE id = '${targetA}';
  `);
  assert(
    rotated.rows[0].active_dast_run_id === 'dast_run_new',
    `[1] target.active_dast_run_id = 'dast_run_new' (got ${rotated.rows[0].active_dast_run_id})`,
  );
  assert(
    rotated.rows[0].previous_dast_run_id === 'dast_run_prior',
    `[1] target.previous_dast_run_id = 'dast_run_prior' (got ${rotated.rows[0].previous_dast_run_id})`,
  );

  // ---------------------------------------------------------------------------
  // 2. commit_dast_target_run first-ever-commit path
  // ---------------------------------------------------------------------------
  console.log('\n[2] commit_dast_target_run first-ever-commit (NULL → run)...');
  await storage.db.exec(`
    UPDATE project_dast_targets
       SET active_dast_run_id = NULL, previous_dast_run_id = NULL
     WHERE id = '${targetB}';
  `);
  let firstCommitErr = '';
  try {
    await storage.db.exec(`SELECT commit_dast_target_run('${targetB}'::uuid, 'dast_run_first');`);
  } catch (e: any) {
    firstCommitErr = String(e?.message ?? '');
  }
  assert(firstCommitErr === '', `[2] first-ever commit does not throw (got: ${firstCommitErr.slice(0, 120)})`);
  const firstCommitRow = await storage.db.query<{ active_dast_run_id: string; previous_dast_run_id: string | null }>(`
    SELECT active_dast_run_id, previous_dast_run_id
    FROM project_dast_targets WHERE id = '${targetB}';
  `);
  assert(
    firstCommitRow.rows[0].active_dast_run_id === 'dast_run_first',
    `[2] active_dast_run_id = 'dast_run_first' (got ${firstCommitRow.rows[0].active_dast_run_id})`,
  );
  assert(
    firstCommitRow.rows[0].previous_dast_run_id === null,
    `[2] previous_dast_run_id IS NULL (got ${firstCommitRow.rows[0].previous_dast_run_id})`,
  );

  // ---------------------------------------------------------------------------
  // 3. Suppression carry-forward — handler-identity branch
  // ---------------------------------------------------------------------------
  console.log('\n[3] Suppression carry-forward (handler-identity branch)...');
  // Reset target C; seed run1 finding with handler identity + suppressed status.
  await storage.db.exec(`
    UPDATE project_dast_targets
       SET active_dast_run_id = NULL, previous_dast_run_id = NULL
     WHERE id = '${targetC}';

    INSERT INTO project_dast_findings (
      project_id, organization_id, target_id, dast_run_id, rule_id,
      handler_file_path, handler_function_name,
      endpoint_url, http_method, vulnerability_type,
      severity, confidence, status, risk_accepted_reason
    ) VALUES (
      '${PROJ_C}', '${ORG}', '${targetC}', 'dast_run_c1', 'rule.xss.reflected',
      'src/users.ts', 'updateUser',
      'https://app-c.example.com/users', 'POST', 'XSS',
      'medium', 'medium', 'risk_accepted', 'WAF rule covers this'
    );

    SELECT commit_dast_target_run('${targetC}'::uuid, 'dast_run_c1');

    INSERT INTO project_dast_findings (
      project_id, organization_id, target_id, dast_run_id, rule_id,
      handler_file_path, handler_function_name,
      endpoint_url, http_method, vulnerability_type,
      severity, confidence, status
    ) VALUES (
      '${PROJ_C}', '${ORG}', '${targetC}', 'dast_run_c2', 'rule.xss.reflected',
      'src/users.ts', 'updateUser',
      'https://app-c.example.com/users', 'POST', 'XSS',
      'medium', 'medium', 'open'
    );

    SELECT commit_dast_target_run('${targetC}'::uuid, 'dast_run_c2');
  `);
  const c2 = await storage.db.query<{ status: string; risk_accepted_reason: string | null }>(`
    SELECT status, risk_accepted_reason FROM project_dast_findings
    WHERE target_id = '${targetC}' AND dast_run_id = 'dast_run_c2';
  `);
  assert(
    c2.rows[0].status === 'risk_accepted',
    `[3] run2 finding inherits status='risk_accepted' (got ${c2.rows[0].status})`,
  );
  assert(
    c2.rows[0].risk_accepted_reason === 'WAF rule covers this',
    `[3] run2 finding inherits reason (got ${c2.rows[0].risk_accepted_reason})`,
  );

  // ---------------------------------------------------------------------------
  // 4. Suppression carry-forward — endpoint-identity branch
  // ---------------------------------------------------------------------------
  console.log('\n[4] Suppression carry-forward (endpoint-identity branch)...');
  await storage.db.exec(`
    UPDATE project_dast_targets
       SET active_dast_run_id = NULL, previous_dast_run_id = NULL
     WHERE id = '${targetD}';

    INSERT INTO project_dast_findings (
      project_id, organization_id, target_id, dast_run_id, rule_id,
      handler_file_path, handler_function_name,
      endpoint_url, http_method, vulnerability_type,
      severity, confidence, status, risk_accepted_reason
    ) VALUES (
      '${PROJ_D}', '${ORG}', '${targetD}', 'dast_run_d1', 'rule.sqli.basic',
      NULL, NULL,
      'https://app-d.example.com/search', 'GET', 'SQLi',
      'high', 'high', 'suppressed', 'False positive — query is parameterized'
    );

    SELECT commit_dast_target_run('${targetD}'::uuid, 'dast_run_d1');

    INSERT INTO project_dast_findings (
      project_id, organization_id, target_id, dast_run_id, rule_id,
      handler_file_path, handler_function_name,
      endpoint_url, http_method, vulnerability_type,
      severity, confidence, status
    ) VALUES (
      '${PROJ_D}', '${ORG}', '${targetD}', 'dast_run_d2', 'rule.sqli.basic',
      NULL, NULL,
      'https://app-d.example.com/search', 'GET', 'SQLi',
      'high', 'high', 'open'
    );

    SELECT commit_dast_target_run('${targetD}'::uuid, 'dast_run_d2');
  `);
  const d2 = await storage.db.query<{ status: string; risk_accepted_reason: string | null }>(`
    SELECT status, risk_accepted_reason FROM project_dast_findings
    WHERE target_id = '${targetD}' AND dast_run_id = 'dast_run_d2';
  `);
  assert(
    d2.rows[0].status === 'suppressed',
    `[4] run2 endpoint-identity finding inherits status='suppressed' (got ${d2.rows[0].status})`,
  );
  assert(
    d2.rows[0].risk_accepted_reason === 'False positive — query is parameterized',
    `[4] run2 endpoint-identity finding inherits reason (got ${d2.rows[0].risk_accepted_reason})`,
  );

  // Clear scan_jobs before queue_scan_job assertions.
  await storage.db.exec(`DELETE FROM scan_jobs;`);

  // ---------------------------------------------------------------------------
  // 5. queue_scan_job NULL p_target_id raises 'p_target_id is required' + P0001
  // ---------------------------------------------------------------------------
  console.log('\n[5] queue_scan_job rejects NULL p_target_id...');
  let nullErr: any;
  try {
    await storage.db.exec(`
      SELECT queue_scan_job(
        '${PROJ_E}'::uuid, '${ORG}'::uuid, 'dast_zap', '{}'::jsonb,
        NULL, 'https://app-e.example.com/', NULL, NULL, NULL, NULL
      );
    `);
  } catch (e: any) {
    nullErr = e;
  }
  const nullMsg = String(nullErr?.message ?? '');
  const nullCode = String(nullErr?.code ?? '');
  assert(
    /p_target_id is required for dast\* types/.test(nullMsg),
    `[5] NULL target_id raises 'p_target_id is required for dast* types' (got: ${nullMsg.slice(0, 120)})`,
  );
  assert(
    nullCode === 'P0001',
    `[5] NULL target_id raises with ERRCODE='P0001' (got: ${nullCode})`,
  );

  // ---------------------------------------------------------------------------
  // 6. queue_scan_job happy path
  // ---------------------------------------------------------------------------
  console.log('\n[6] queue_scan_job happy path...');
  const happy = await storage.db.query<{ id: string }>(`
    SELECT (queue_scan_job(
      '${PROJ_E}'::uuid, '${ORG}'::uuid, 'dast_zap', '{}'::jsonb,
      '${targetE}'::uuid, 'https://app-e.example.com/', NULL, NULL, NULL, NULL
    )).id;
  `);
  assert(happy.rows.length === 1, `[6] queue_scan_job inserts exactly one row (got ${happy.rows.length})`);

  // ---------------------------------------------------------------------------
  // 7. queue_scan_job tenant-drift
  // ---------------------------------------------------------------------------
  console.log('\n[7] queue_scan_job tenant-drift assertion...');
  let driftErr: any;
  try {
    await storage.db.exec(`
      SELECT queue_scan_job(
        '${PROJ_A}'::uuid, '${ORG}'::uuid, 'dast_zap', '{}'::jsonb,
        '${targetOther}'::uuid, 'https://app-other.example.com/', NULL, NULL, NULL, NULL
      );
    `);
  } catch (e: any) {
    driftErr = e;
  }
  assert(
    /tenant drift/i.test(String(driftErr?.message ?? '')),
    `[7] cross-org target_id raises 'tenant drift' (got: ${String(driftErr?.message ?? '').slice(0, 120)})`,
  );
  assert(
    String(driftErr?.code ?? '') === 'P0001',
    `[7] tenant-drift raises with ERRCODE='P0001' (got: ${driftErr?.code})`,
  );

  // ---------------------------------------------------------------------------
  // 8. queue_scan_job SSRF — three distinct host classes
  // ---------------------------------------------------------------------------
  console.log('\n[8] queue_scan_job SSRF — 3 host classes...');
  const ssrfHosts = [
    { url: 'http://169.254.169.254/', label: 'link-local (169.254.x)' },
    { url: 'http://10.0.0.1/',         label: 'RFC1918 (10.x)' },
    { url: 'http://foo.fly.dev.internal/', label: 'Fly internal' },
  ];
  for (const { url, label } of ssrfHosts) {
    let err: any;
    try {
      await storage.db.exec(`
        SELECT queue_scan_job(
          '${PROJ_F}'::uuid, '${ORG}'::uuid, 'dast_zap', '{}'::jsonb,
          '${targetF}'::uuid, '${url}', NULL, NULL, NULL, NULL
        );
      `);
    } catch (e: any) {
      err = e;
    }
    assert(
      /rejected.*private|loopback|internal/i.test(String(err?.message ?? '')),
      `[8] SSRF host class ${label} raises private/loopback/internal (got: ${String(err?.message ?? '').slice(0, 120)})`,
    );
    assert(
      String(err?.code ?? '') === 'P0001',
      `[8] SSRF ${label} raises with ERRCODE='P0001' (got: ${err?.code})`,
    );
  }

  // ---------------------------------------------------------------------------
  // 9. queue_scan_job per-project cap (1 active blocks the second)
  // ---------------------------------------------------------------------------
  console.log('\n[9] queue_scan_job per-project cap...');
  // Step 6 already left a queued scan_job for proj-e + target-e. Try to queue
  // a 2nd on the same project — must raise project_concurrent_dast_blocked.
  let projCapErr: any;
  try {
    await storage.db.exec(`
      SELECT queue_scan_job(
        '${PROJ_E}'::uuid, '${ORG}'::uuid, 'dast_zap', '{}'::jsonb,
        '${targetE}'::uuid, 'https://app-e.example.com/', NULL, NULL, NULL, NULL
      );
    `);
  } catch (e: any) {
    projCapErr = e;
  }
  assert(
    /project_concurrent_dast_blocked/.test(String(projCapErr?.message ?? '')),
    `[9] 2nd queue on same project raises project_concurrent_dast_blocked (got: ${String(projCapErr?.message ?? '').slice(0, 120)})`,
  );
  assert(
    String(projCapErr?.code ?? '') === 'P0001',
    `[9] per-project cap raises with ERRCODE='P0001' (got: ${projCapErr?.code})`,
  );

  // ---------------------------------------------------------------------------
  // 10. queue_scan_job per-org cap (5 across 5 distinct projects, 6th blocks)
  // ---------------------------------------------------------------------------
  console.log('\n[10] queue_scan_job per-org cap (5 across 5 projects)...');
  await storage.db.exec(`DELETE FROM scan_jobs;`);
  // Seed 5 queued DAST scan_jobs across 5 distinct projects in ORG, by direct
  // INSERT (we want to test the cap, not exercise queue_scan_job for setup).
  await storage.db.exec(`
    INSERT INTO scan_jobs (project_id, organization_id, type, status, target_id, target_url) VALUES
      ('${PROJ_A}', '${ORG}', 'dast_zap', 'queued',     '${targetA}', 'https://app-a.example.com/'),
      ('${PROJ_B}', '${ORG}', 'dast_zap', 'queued',     '${targetB}', 'https://app-b.example.com/'),
      ('${PROJ_C}', '${ORG}', 'dast_zap', 'processing', '${targetC}', 'https://app-c.example.com/'),
      ('${PROJ_D}', '${ORG}', 'dast_zap', 'queued',     '${targetD}', 'https://app-d.example.com/'),
      ('${PROJ_E}', '${ORG}', 'dast_zap', 'queued',     '${targetE}', 'https://app-e.example.com/');
  `);
  let orgCapErr: any;
  try {
    await storage.db.exec(`
      SELECT queue_scan_job(
        '${PROJ_F}'::uuid, '${ORG}'::uuid, 'dast_zap', '{}'::jsonb,
        '${targetF}'::uuid, 'https://app-f.example.com/', NULL, NULL, NULL, NULL
      );
    `);
  } catch (e: any) {
    orgCapErr = e;
  }
  assert(
    /org_concurrent_dast_cap/.test(String(orgCapErr?.message ?? '')),
    `[10] 6th queue across distinct projects raises org_concurrent_dast_cap (got: ${String(orgCapErr?.message ?? '').slice(0, 120)})`,
  );
  assert(
    String(orgCapErr?.code ?? '') === 'P0001',
    `[10] per-org cap raises with ERRCODE='P0001' (got: ${orgCapErr?.code})`,
  );

  await storage.db.exec(`DELETE FROM scan_jobs;`);

  // ---------------------------------------------------------------------------
  // 11. project_dast_findings.target_id is NOT NULL (insert with NULL fails)
  // ---------------------------------------------------------------------------
  console.log('\n[11] project_dast_findings.target_id is NOT NULL...');
  let nullTargetErr = '';
  try {
    await storage.db.exec(`
      INSERT INTO project_dast_findings (
        project_id, organization_id, target_id, dast_run_id,
        endpoint_url, http_method, vulnerability_type, severity, confidence
      ) VALUES (
        '${PROJ_A}', '${ORG}', NULL, 'dast_run_z',
        'https://app-a.example.com/x', 'GET', 'XSS', 'low', 'low'
      );
    `);
  } catch (e: any) {
    nullTargetErr = String(e?.message ?? '');
  }
  assert(
    /null value in column "target_id"|not[- ]null|null constraint/i.test(nullTargetErr),
    `[11] INSERT with target_id=NULL raises NOT NULL violation (got: ${nullTargetErr.slice(0, 120)})`,
  );

  // ---------------------------------------------------------------------------
  // 12. Forward-compat CHECK preservation
  // ---------------------------------------------------------------------------
  console.log('\n[12] Forward-compat CHECK preservation (engine + auth_strategy)...');

  // engine='zap' baseline (proves CHECK accepts the canonical value).
  let engineZapErr = '';
  try {
    await storage.db.exec(`
      INSERT INTO project_dast_findings (
        project_id, organization_id, target_id, dast_run_id, engine,
        endpoint_url, http_method, vulnerability_type, severity, confidence
      ) VALUES (
        '${PROJ_A}', '${ORG}', '${targetA}', 'dast_run_engine_zap', 'zap',
        'https://app-a.example.com/zap', 'GET', 'XSS', 'low', 'low'
      );
    `);
  } catch (e: any) {
    engineZapErr = String(e?.message ?? '');
  }
  assert(engineZapErr === '', `[12] engine='zap' accepted (got: ${engineZapErr.slice(0, 120)})`);

  // engine='nuclei' (forward-compat for v2.1c).
  let engineNucleiErr = '';
  try {
    await storage.db.exec(`
      INSERT INTO project_dast_findings (
        project_id, organization_id, target_id, dast_run_id, engine,
        endpoint_url, http_method, vulnerability_type, severity, confidence
      ) VALUES (
        '${PROJ_A}', '${ORG}', '${targetA}', 'dast_run_engine_nuclei', 'nuclei',
        'https://app-a.example.com/nuclei', 'GET', 'XSS', 'low', 'low'
      );
    `);
  } catch (e: any) {
    engineNucleiErr = String(e?.message ?? '');
  }
  assert(engineNucleiErr === '', `[12] engine='nuclei' accepted (got: ${engineNucleiErr.slice(0, 120)})`);

  // engine='merged' (forward-compat for v2.1c merged engine output).
  let engineMergedErr = '';
  try {
    await storage.db.exec(`
      INSERT INTO project_dast_findings (
        project_id, organization_id, target_id, dast_run_id, engine,
        endpoint_url, http_method, vulnerability_type, severity, confidence
      ) VALUES (
        '${PROJ_A}', '${ORG}', '${targetA}', 'dast_run_engine_merged', 'merged',
        'https://app-a.example.com/merged', 'GET', 'XSS', 'low', 'low'
      );
    `);
  } catch (e: any) {
    engineMergedErr = String(e?.message ?? '');
  }
  assert(engineMergedErr === '', `[12] engine='merged' accepted (got: ${engineMergedErr.slice(0, 120)})`);

  // engine='garbage' rejected.
  let engineBadErr = '';
  try {
    await storage.db.exec(`
      INSERT INTO project_dast_findings (
        project_id, organization_id, target_id, dast_run_id, engine,
        endpoint_url, http_method, vulnerability_type, severity, confidence
      ) VALUES (
        '${PROJ_A}', '${ORG}', '${targetA}', 'dast_run_engine_bad', 'garbage',
        'https://app-a.example.com/bad', 'GET', 'XSS', 'low', 'low'
      );
    `);
  } catch (e: any) {
    engineBadErr = String(e?.message ?? '');
  }
  assert(
    /check constraint|engine_check/i.test(engineBadErr),
    `[12] engine='garbage' rejected (got: ${engineBadErr.slice(0, 120)})`,
  );

  // auth_strategy='recorded' accepted on credentials (forward-compat v2.1d).
  let authRecordedErr = '';
  try {
    await storage.db.exec(`
      INSERT INTO project_dast_credentials (
        target_id, organization_id, auth_strategy, encrypted_payload
      ) VALUES (
        '${targetE}', '${ORG}', 'recorded', 'placeholder-ciphertext'
      );
    `);
  } catch (e: any) {
    authRecordedErr = String(e?.message ?? '');
  }
  assert(
    authRecordedErr === '',
    `[12] auth_strategy='recorded' accepted (got: ${authRecordedErr.slice(0, 120)})`,
  );

  // ---------------------------------------------------------------------------
  // 13. Sanity: exactly one queue_scan_job overload
  // ---------------------------------------------------------------------------
  console.log('\n[13] queue_scan_job overload count == 1...');
  const overloadCount = await storage.db.query<{ count: string }>(`
    SELECT COUNT(*)::text AS count FROM pg_proc WHERE proname = 'queue_scan_job';
  `);
  assert(
    overloadCount.rows[0].count === '1',
    `[13] exactly one queue_scan_job overload (got ${overloadCount.rows[0].count})`,
  );

  await storage.close();
  console.log(`\nphase24b verification ${failures === 0 ? 'PASSED' : 'FAILED'} in ${Date.now() - t0}ms (${failures} failure${failures === 1 ? '' : 's'})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
