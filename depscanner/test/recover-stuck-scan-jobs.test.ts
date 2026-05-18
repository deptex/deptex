/**
 * recover_stuck_scan_jobs RPC behavior tests.
 *
 * Boots a fresh PGLite per scenario, loads backend/database/schema.sql, seeds
 * scan_jobs in different states, calls recover_stuck_scan_jobs, and asserts
 * on which rows came back to 'queued'.
 *
 * Regression coverage for the phase 29 fix: prior to the fix the recovery
 * filtered `type = 'extraction'` only, leaving DAST jobs (and any future
 * scan type) stuck in 'processing' forever.
 *
 * Run: npx tsx test/recover-stuck-scan-jobs.test.ts
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
  const schemaSql = fs.readFileSync(SCHEMA_FILE, 'utf8');
  await db.exec(stripPgliteIncompatible(schemaSql));
  return db;
}

/**
 * Mirrors stripPgliteIncompatible() in src/storage/pglite.ts. Schema-dump
 * helpers (pg_catalog_dump_v1) and forward-referenced CHECK constraints are
 * stripped so PGLite can swallow the dump.
 */
function stripPgliteIncompatible(sql: string): string {
  let out = sql;
  out = out.replace(
    /CREATE OR REPLACE FUNCTION public\.pg_catalog_dump_v1(_all)?\([^)]*\)[\s\S]*?\$function\$\s*;\s*/g,
    '',
  );
  out = out.replace(
    /ALTER TABLE public\.organization_generated_rules\s+ADD CONSTRAINT[^;]*framework_spec_osv_matches_cve[^;]*;\s*/g,
    '',
  );
  return out;
}

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const PROJECT_ID = '00000000-0000-0000-0000-000000000002';

async function seedOrgAndProject(db: PGlite): Promise<void> {
  await db.exec(`
    INSERT INTO organizations (id, name, created_at)
    VALUES ('${ORG_ID}', 'test-org', NOW())
    ON CONFLICT (id) DO NOTHING;
  `);
  await db.exec(`
    INSERT INTO projects (id, organization_id, name, created_at)
    VALUES ('${PROJECT_ID}', '${ORG_ID}', 'test-project', NOW())
    ON CONFLICT (id) DO NOTHING;
  `);
}

interface JobSpec {
  id: string;
  type: 'extraction' | 'dast' | 'dast_zap' | 'dast_nuclei';
  status: string;
  /** Minutes ago — null = NOW(). */
  heartbeatMinutesAgo: number | null;
  attempts: number;
  maxAttempts?: number;
  /** Sparse DAST columns required by the type CHECK. */
  withDastCols?: boolean;
}

async function seedJob(db: PGlite, j: JobSpec): Promise<void> {
  const heartbeat =
    j.heartbeatMinutesAgo === null
      ? 'NOW()'
      : `NOW() - INTERVAL '${j.heartbeatMinutesAgo} minutes'`;
  const max = j.maxAttempts ?? 3;
  const isDastType = j.type === 'dast' || j.type === 'dast_zap' || j.type === 'dast_nuclei';
  const dastCols = isDastType
    ? `, target_url, scan_profile, timeout_minutes, trigger_source`
    : '';
  const dastVals = isDastType
    ? `, 'https://example.test', 'quick', 30, 'manual'`
    : '';
  await db.exec(`
    INSERT INTO scan_jobs (
      id, project_id, organization_id, type, status, run_id,
      payload, attempts, max_attempts, heartbeat_at, started_at, machine_id, created_at
      ${dastCols}
    )
    VALUES (
      '${j.id}', '${PROJECT_ID}', '${ORG_ID}', '${j.type}', '${j.status}', gen_random_uuid(),
      '{}'::jsonb, ${j.attempts}, ${max}, ${heartbeat},
      ${heartbeat === 'NOW()' ? 'NOW()' : heartbeat}, 'fake-machine', NOW()
      ${dastVals}
    );
  `);
}

interface ScanJobRow {
  id: string;
  type: string;
  status: string;
  machine_id: string | null;
  heartbeat_at: string | null;
  attempts: number;
}

async function callRecover(db: PGlite): Promise<ScanJobRow[]> {
  const res = await db.query<ScanJobRow>(`SELECT * FROM recover_stuck_scan_jobs()`);
  return res.rows;
}

async function jobsByStatus(db: PGlite): Promise<Record<string, string[]>> {
  const res = await db.query<{ id: string; status: string; type: string }>(
    `SELECT id, status, type FROM scan_jobs ORDER BY created_at`,
  );
  const grouped: Record<string, string[]> = {};
  for (const r of res.rows) {
    const key = `${r.status}:${r.type}`;
    (grouped[key] = grouped[key] ?? []).push(r.id);
  }
  return grouped;
}

// -----------------------------------------------------------------------------
// Test 1: stale-heartbeat extraction job is requeued (regression check on the
// pre-fix happy path).
// -----------------------------------------------------------------------------
async function testExtractionStaleRequeued(): Promise<void> {
  console.log('\nTest 1: stale extraction job is requeued');
  const db = await bootDb();
  await seedOrgAndProject(db);

  await seedJob(db, {
    id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    type: 'extraction',
    status: 'processing',
    heartbeatMinutesAgo: 10,
    attempts: 1,
  });

  const recovered = await callRecover(db);
  assert(recovered.length === 1, `one job recovered (got ${recovered.length})`);
  assert(recovered[0]?.type === 'extraction', 'recovered job is extraction-type');
  assert(recovered[0]?.machine_id === null, 'machine_id cleared on requeue');

  const after = await jobsByStatus(db);
  assert(
    (after['queued:extraction'] ?? []).length === 1,
    'extraction job is now status=queued',
  );

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 2 (THE BUG): stale-heartbeat DAST jobs ALSO get requeued. Pre-phase-29
// they were silently skipped by the type='extraction' filter.
//
// Only type='dast' is exercised here because the existing
// `scan_jobs_dast_columns_match_type` CHECK constraint only allows
// target_url/scan_profile/etc. when type = 'dast' (NOT dast_zap / dast_nuclei,
// even though phase 24a widened scan_jobs_type_check to those values). That
// constraint mismatch is captured in the hardening report as a P1; the
// recovery RPC's type-agnosticism doesn't depend on it being fixed.
// -----------------------------------------------------------------------------
async function testDastStaleRequeued(): Promise<void> {
  console.log('\nTest 2: stale DAST job is requeued (was extraction-only pre-phase-29)');
  const db = await bootDb();
  await seedOrgAndProject(db);

  await seedJob(db, {
    id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1',
    type: 'dast',
    status: 'processing',
    heartbeatMinutesAgo: 10,
    attempts: 1,
  });

  const recovered = await callRecover(db);
  assert(recovered.length === 1, `one DAST job recovered (got ${recovered.length})`);
  assert(recovered[0]?.type === 'dast', 'recovered job is type=dast');
  assert(recovered[0]?.machine_id === null, 'machine_id cleared on requeue');

  const after = await jobsByStatus(db);
  assert(
    (after['queued:dast'] ?? []).length === 1,
    'DAST job is now status=queued',
  );

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 2b: a heterogeneous queue (extraction + dast both stale) gets BOTH
// recovered in a single sweep — the cross-type promise of the phase 29 fix.
// -----------------------------------------------------------------------------
async function testHeterogeneousSweep(): Promise<void> {
  console.log('\nTest 2b: extraction + DAST in same sweep both come back');
  const db = await bootDb();
  await seedOrgAndProject(db);

  await seedJob(db, {
    id: '11111111-1111-1111-1111-111111111111',
    type: 'extraction',
    status: 'processing',
    heartbeatMinutesAgo: 10,
    attempts: 1,
  });
  await seedJob(db, {
    id: '22222222-2222-2222-2222-222222222222',
    type: 'dast',
    status: 'processing',
    heartbeatMinutesAgo: 10,
    attempts: 1,
  });

  const recovered = await callRecover(db);
  assert(recovered.length === 2, `two jobs recovered (got ${recovered.length})`);
  const types = recovered.map((r) => r.type).sort();
  assert(
    JSON.stringify(types) === JSON.stringify(['dast', 'extraction']),
    `recovered both type variants in one sweep (got ${JSON.stringify(types)})`,
  );

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 3: fresh heartbeat is NOT requeued, even if status=processing.
// -----------------------------------------------------------------------------
async function testFreshHeartbeatIgnored(): Promise<void> {
  console.log('\nTest 3: fresh-heartbeat jobs are left alone');
  const db = await bootDb();
  await seedOrgAndProject(db);

  await seedJob(db, {
    id: 'cccccccc-cccc-cccc-cccc-ccccccccccc1',
    type: 'extraction',
    status: 'processing',
    heartbeatMinutesAgo: 1, // fresh
    attempts: 1,
  });
  await seedJob(db, {
    id: 'cccccccc-cccc-cccc-cccc-ccccccccccc2',
    type: 'dast',
    status: 'processing',
    heartbeatMinutesAgo: 2, // also fresh
    attempts: 1,
  });

  const recovered = await callRecover(db);
  assert(recovered.length === 0, `no jobs recovered (got ${recovered.length})`);

  const after = await jobsByStatus(db);
  assert(
    (after['processing:extraction'] ?? []).length === 1,
    'extraction job still processing',
  );
  assert((after['processing:dast'] ?? []).length === 1, 'DAST job still processing');

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 4: jobs that already hit max_attempts are NOT requeued (those are
// owned by fail_exhausted_scan_jobs).
// -----------------------------------------------------------------------------
async function testExhaustedNotRequeued(): Promise<void> {
  console.log('\nTest 4: attempts >= max_attempts is left alone (handed off to fail_exhausted)');
  const db = await bootDb();
  await seedOrgAndProject(db);

  await seedJob(db, {
    id: 'dddddddd-dddd-dddd-dddd-dddddddddd01',
    type: 'extraction',
    status: 'processing',
    heartbeatMinutesAgo: 10,
    attempts: 3,
    maxAttempts: 3,
  });
  await seedJob(db, {
    id: 'dddddddd-dddd-dddd-dddd-dddddddddd02',
    type: 'dast',
    status: 'processing',
    heartbeatMinutesAgo: 10,
    attempts: 5,
    maxAttempts: 3,
  });

  const recovered = await callRecover(db);
  assert(recovered.length === 0, `no jobs recovered (got ${recovered.length})`);

  const after = await jobsByStatus(db);
  assert(
    (after['processing:extraction'] ?? []).length === 1,
    'exhausted extraction job stays processing',
  );
  assert(
    (after['processing:dast'] ?? []).length === 1,
    'exhausted DAST job stays processing',
  );

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 5: requeue rotates run_id (so logs/findings from the dead attempt are
// orphaned and reaped by reap_orphaned_extractions, not blended into the new
// attempt).
// -----------------------------------------------------------------------------
async function testRunIdRotated(): Promise<void> {
  console.log('\nTest 5: requeue rotates run_id (orphan-reap contract)');
  const db = await bootDb();
  await seedOrgAndProject(db);

  const JOB_ID = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
  await seedJob(db, {
    id: JOB_ID,
    type: 'extraction',
    status: 'processing',
    heartbeatMinutesAgo: 10,
    attempts: 1,
  });

  const before = await db.query<{ run_id: string }>(
    `SELECT run_id FROM scan_jobs WHERE id = $1`,
    [JOB_ID],
  );
  const oldRunId = before.rows[0].run_id;
  assert(typeof oldRunId === 'string' && oldRunId.length > 0, 'pre-recover has a run_id');

  await callRecover(db);

  const after = await db.query<{ run_id: string }>(
    `SELECT run_id FROM scan_jobs WHERE id = $1`,
    [JOB_ID],
  );
  assert(after.rows[0].run_id !== oldRunId, 'run_id was rotated by recovery');

  await db.close();
}

// -----------------------------------------------------------------------------
async function main() {
  const t0 = Date.now();
  const tests = [
    testExtractionStaleRequeued,
    testDastStaleRequeued,
    testHeterogeneousSweep,
    testFreshHeartbeatIgnored,
    testExhaustedNotRequeued,
    testRunIdRotated,
  ];

  for (const t of tests) {
    try {
      await t();
    } catch (e) {
      console.error(`    FAIL (threw): ${(e as Error).message}`);
      console.error((e as Error).stack);
      failures++;
    }
  }

  const duration = Date.now() - t0;
  const label = failures === 0 ? 'ALL TESTS PASSED' : `${failures} ASSERTION(S) FAILED`;
  console.log(`\n${label} — ${passed} ok, ${failures} fail — ${duration}ms`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
