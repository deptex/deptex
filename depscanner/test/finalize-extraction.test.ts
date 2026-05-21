/**
 * finalize_extraction RPC behavior tests.
 *
 * Boots a fresh PGLite per scenario, loads backend/database/schema.sql, seeds
 * the exact pre-state each scenario needs, calls finalize_extraction, and
 * asserts on side effects (soft-delete, carry-forward, triggers, events,
 * pointer flip, reap).
 *
 * Covers behaviors that the smoke test (smoke-pglite.ts) only proves "doesn't
 * blow up on an empty PDV set". Intentional gaps: full concurrency (PGLite is
 * single-connection) and idempotent re-run.
 *
 * Run: npx tsx test/finalize-extraction.test.ts
 */

import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite/vector';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import * as fs from 'fs';
import * as path from 'path';
import { stripPgliteIncompatible } from '../src/storage/pglite';

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
  // The schema dump emits functions in name order, so a few forward-reference
  // each other (pg_catalog_dump_v1_all calls pg_catalog_dump_v1, defined
  // later). Disable parse-time body validation so the dump loads on PGLite.
  await db.exec(`SET check_function_bodies = off;`);
  const schemaSql = stripPgliteIncompatible(fs.readFileSync(SCHEMA_FILE, 'utf8'));
  await db.exec(schemaSql);
  return db;
}

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const PROJECT_ID = '00000000-0000-0000-0000-000000000002';

async function seedOrgAndProject(db: PGlite, activeRunId: string | null = null): Promise<void> {
  await db.exec(`
    INSERT INTO organizations (id, name, created_at)
    VALUES ('${ORG_ID}', 'test-org', NOW())
    ON CONFLICT (id) DO NOTHING;
  `);
  const activeLit = activeRunId === null ? 'NULL' : `'${activeRunId}'`;
  await db.exec(`
    INSERT INTO projects (id, organization_id, name, active_extraction_run_id, created_at)
    VALUES ('${PROJECT_ID}', '${ORG_ID}', 'test-project', ${activeLit}, NOW())
    ON CONFLICT (id) DO NOTHING;
  `);
}

async function callFinalize(db: PGlite, runId: string): Promise<Record<string, unknown>> {
  const res = await db.query<{ finalize_extraction: Record<string, unknown> }>(
    `SELECT finalize_extraction($1::uuid, $2::uuid, $3::text) AS finalize_extraction`,
    [PROJECT_ID, PROJECT_ID, runId],
  );
  return res.rows[0].finalize_extraction;
}

// -----------------------------------------------------------------------------
// Test 1: Mark-removed — deps not seen in the new run get removed_at set
// -----------------------------------------------------------------------------
async function testMarkRemoved(): Promise<void> {
  console.log('\nTest 1: mark-removed soft-deletes stale deps');
  const db = await bootDb();
  const PREV_RUN = 'run_prev';
  const NEW_RUN = 'run_new';
  await seedOrgAndProject(db, PREV_RUN);

  // Seed two deps from the previous run, one of which is "no longer present"
  // (still tagged with PREV_RUN's last_seen). The other was re-upserted by
  // the pipeline during NEW_RUN and has its last_seen bumped.
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, removed_at, created_at)
    VALUES
      ('11111111-1111-1111-1111-111111111111', '${PROJECT_ID}', 'lodash',  '4.17.21', true, 'dependencies', '${NEW_RUN}',  NULL, NOW()),
      ('22222222-2222-2222-2222-222222222222', '${PROJECT_ID}', 'express', '4.18.0',  true, 'dependencies', '${PREV_RUN}', NULL, NOW());
  `);

  await callFinalize(db, NEW_RUN);

  const { rows } = await db.query<{ name: string; removed_at: string | null }>(
    `SELECT name, removed_at FROM project_dependencies WHERE project_id = $1 ORDER BY name`,
    [PROJECT_ID],
  );
  const byName = Object.fromEntries(rows.map((r) => [r.name, r.removed_at]));
  assert(byName.lodash === null, 'lodash (seen in new run) has removed_at = NULL');
  assert(byName.express !== null, 'express (missing from new run) has removed_at set');

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 2: Pointer flip — projects.active_extraction_run_id updates atomically
// -----------------------------------------------------------------------------
async function testPointerFlip(): Promise<void> {
  console.log('\nTest 2: pointer flip sets active + previous extraction_run_id');
  const db = await bootDb();
  const OLD_RUN = 'run_old';
  const NEW_RUN = 'run_new';
  await seedOrgAndProject(db, OLD_RUN);

  const before = await db.query<{ active_extraction_run_id: string; previous_extraction_run_id: string | null }>(
    `SELECT active_extraction_run_id, previous_extraction_run_id FROM projects WHERE id = $1`,
    [PROJECT_ID],
  );
  assert(before.rows[0].active_extraction_run_id === OLD_RUN, 'pre: active = OLD_RUN');
  assert(before.rows[0].previous_extraction_run_id === null, 'pre: previous = NULL');

  await callFinalize(db, NEW_RUN);

  const after = await db.query<{ active_extraction_run_id: string; previous_extraction_run_id: string }>(
    `SELECT active_extraction_run_id, previous_extraction_run_id FROM projects WHERE id = $1`,
    [PROJECT_ID],
  );
  assert(after.rows[0].active_extraction_run_id === NEW_RUN, 'post: active = NEW_RUN');
  assert(after.rows[0].previous_extraction_run_id === OLD_RUN, 'post: previous = OLD_RUN');

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 3: Carry-forward PDV state — suppression survives version bump
// -----------------------------------------------------------------------------
async function testCarryForwardSuppression(): Promise<void> {
  console.log('\nTest 3: carry-forward — PDV suppression survives across version bump');
  const db = await bootDb();
  const PREV_RUN = 'run_prev';
  const NEW_RUN = 'run_new';
  await seedOrgAndProject(db, PREV_RUN);

  const OLD_PD_ID = '11111111-1111-1111-1111-111111111111';
  const NEW_PD_ID = '22222222-2222-2222-2222-222222222222';
  const USER_ID = '33333333-3333-3333-3333-333333333333';

  // Seed two PDs for the SAME dep name (lodash), different versions — simulating
  // a version bump from 4.17.20 to 4.17.21 across runs.
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES
      ('${OLD_PD_ID}', '${PROJECT_ID}', 'lodash', '4.17.20', true, 'dependencies', '${PREV_RUN}', NOW()),
      ('${NEW_PD_ID}', '${PROJECT_ID}', 'lodash', '4.17.21', true, 'dependencies', '${NEW_RUN}',  NOW());
  `);

  // Seed the PREV-run PDV with suppressed=true
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, suppressed, suppressed_by, suppressed_at, detected_at, created_at)
    VALUES
      ('${PROJECT_ID}', '${OLD_PD_ID}', 'CVE-2021-23337', 'high', '${PREV_RUN}', 'open', true, '${USER_ID}', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', NOW());
  `);

  // Seed the NEW-run PDV with default state (suppressed=false) — carry-forward
  // should flip it back to suppressed=true.
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, suppressed, detected_at, created_at)
    VALUES
      ('${PROJECT_ID}', '${NEW_PD_ID}', 'CVE-2021-23337', 'high', '${NEW_RUN}', 'open', false, NOW(), NOW());
  `);

  await callFinalize(db, NEW_RUN);

  const { rows } = await db.query<{ suppressed: boolean; suppressed_by: string | null; detected_at: string }>(
    `SELECT suppressed, suppressed_by, detected_at
     FROM project_dependency_vulnerabilities
     WHERE project_id = $1 AND extraction_run_id = $2`,
    [PROJECT_ID, NEW_RUN],
  );
  assert(rows.length === 1, 'exactly one new-run PDV exists');
  assert(rows[0].suppressed === true, 'suppressed carried forward: true');
  assert(rows[0].suppressed_by === USER_ID, `suppressed_by carried forward: ${USER_ID}`);
  assert(
    new Date(rows[0].detected_at).toISOString().startsWith('2026-01-01'),
    'detected_at preserved from original run',
  );

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 4: Re-review trigger — severity escalation fires re_review_triggered_at
// -----------------------------------------------------------------------------
async function testSeverityEscalationTrigger(): Promise<void> {
  console.log('\nTest 4: severity escalation fires re_review_triggered_at + reasons');
  const db = await bootDb();
  const PREV_RUN = 'run_prev';
  const NEW_RUN = 'run_new';
  await seedOrgAndProject(db, PREV_RUN);

  const OLD_PD_ID = '11111111-1111-1111-1111-111111111111';
  const NEW_PD_ID = '22222222-2222-2222-2222-222222222222';

  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES
      ('${OLD_PD_ID}', '${PROJECT_ID}', 'axios', '0.21.0', true, 'dependencies', '${PREV_RUN}', NOW()),
      ('${NEW_PD_ID}', '${PROJECT_ID}', 'axios', '0.21.1', true, 'dependencies', '${NEW_RUN}',  NOW());
  `);

  // Prev-run PDV: severity=low. New-run PDV: severity=critical. Should trigger.
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, detected_at, created_at)
    VALUES
      ('${PROJECT_ID}', '${OLD_PD_ID}', 'CVE-2021-3749', 'low',      '${PREV_RUN}', 'open', NOW(), NOW()),
      ('${PROJECT_ID}', '${NEW_PD_ID}', 'CVE-2021-3749', 'critical', '${NEW_RUN}',  'open', NOW(), NOW());
  `);

  const summary = await callFinalize(db, NEW_RUN);
  assert((summary.vulns_re_review_fired as number) >= 1, 'summary reports >=1 re-review fired');

  const { rows } = await db.query<{ re_review_triggered_at: string | null; re_review_reasons: any }>(
    `SELECT re_review_triggered_at, re_review_reasons
     FROM project_dependency_vulnerabilities
     WHERE project_id = $1 AND extraction_run_id = $2`,
    [PROJECT_ID, NEW_RUN],
  );
  assert(rows.length === 1, 'one new-run PDV');
  assert(rows[0].re_review_triggered_at !== null, 're_review_triggered_at is set');
  const reasons = rows[0].re_review_reasons;
  const flat = Array.isArray(reasons) ? reasons : [];
  const triggers = flat.map((r: any) => r?.trigger).filter(Boolean);
  assert(triggers.includes('severity_escalation'), `reasons contain severity_escalation (got: ${JSON.stringify(triggers)})`);

  // Event row written
  const events = await db.query<{ event_type: string; osv_id: string }>(
    `SELECT event_type, osv_id FROM project_vulnerability_events WHERE project_id = $1`,
    [PROJECT_ID],
  );
  const triggerEvents = events.rows.filter((e) => e.event_type === 'rereview_triggered');
  assert(triggerEvents.length >= 1, 'rereview_triggered event written');
  assert(triggerEvents.some((e) => e.osv_id === 'CVE-2021-3749'), 'event is for the escalated CVE');

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 5: First-run semantics — NULL prev_active writes 'detected' events
// -----------------------------------------------------------------------------
async function testFirstRunDetectedEvents(): Promise<void> {
  console.log('\nTest 5: first run writes detected events for every PDV');
  const db = await bootDb();
  const RUN = 'run_first';
  await seedOrgAndProject(db, null); // active = NULL, first run

  const PD_ID = '11111111-1111-1111-1111-111111111111';
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES ('${PD_ID}', '${PROJECT_ID}', 'lodash', '4.17.21', true, 'dependencies', '${RUN}', NOW());
  `);
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, detected_at, created_at)
    VALUES
      ('${PROJECT_ID}', '${PD_ID}', 'CVE-2021-23337', 'high',     '${RUN}', 'open', NOW(), NOW()),
      ('${PROJECT_ID}', '${PD_ID}', 'CVE-2020-8203',  'critical', '${RUN}', 'open', NOW(), NOW());
  `);

  const summary = await callFinalize(db, RUN);
  assert((summary.vulns_new as number) === 2, `summary.vulns_new = 2 (got ${summary.vulns_new})`);

  const events = await db.query<{ event_type: string; osv_id: string }>(
    `SELECT event_type, osv_id FROM project_vulnerability_events WHERE project_id = $1 ORDER BY osv_id`,
    [PROJECT_ID],
  );
  assert(events.rows.length === 2, `two events written (got ${events.rows.length})`);
  assert(events.rows.every((e) => e.event_type === 'detected'), 'both events are type=detected');
  const osvIds = events.rows.map((e) => e.osv_id).sort();
  assert(osvIds[0] === 'CVE-2020-8203' && osvIds[1] === 'CVE-2021-23337', 'events cover both CVEs');

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 6: Reap — rows older than (active, previous) get hard-deleted
// -----------------------------------------------------------------------------
async function testReapOldRuns(): Promise<void> {
  console.log('\nTest 6: reap hard-deletes findings from pre-previous runs');
  const db = await bootDb();
  const ANCIENT = 'run_ancient';
  const PREV = 'run_prev';
  const NEW = 'run_new';
  await seedOrgAndProject(db, PREV);

  const PD_ID = '11111111-1111-1111-1111-111111111111';
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES ('${PD_ID}', '${PROJECT_ID}', 'lodash', '4.17.21', true, 'dependencies', '${NEW}', NOW());
  `);

  // Seed semgrep findings across 3 runs. After finalize(NEW), active=NEW,
  // previous=PREV. ANCIENT should be reaped.
  await db.exec(`
    INSERT INTO project_semgrep_findings
      (project_id, extraction_run_id, rule_id, file_path, start_line, end_line, severity, message, status, created_at)
    VALUES
      ('${PROJECT_ID}', '${ANCIENT}', 'rule-a', 'a.js', 1, 1, 'info', 'ancient', 'open', NOW()),
      ('${PROJECT_ID}', '${PREV}',    'rule-b', 'b.js', 1, 1, 'info', 'prev',    'open', NOW()),
      ('${PROJECT_ID}', '${NEW}',     'rule-c', 'c.js', 1, 1, 'info', 'new',     'open', NOW());
  `);

  await callFinalize(db, NEW);

  const { rows } = await db.query<{ extraction_run_id: string; message: string }>(
    `SELECT extraction_run_id, message FROM project_semgrep_findings WHERE project_id = $1 ORDER BY message`,
    [PROJECT_ID],
  );
  const keptRuns = rows.map((r) => r.extraction_run_id).sort();
  assert(!keptRuns.includes(ANCIENT), `ANCIENT (${ANCIENT}) reaped (got kept: ${JSON.stringify(keptRuns)})`);
  assert(keptRuns.includes(PREV), `PREV (${PREV}) kept (pointer flipped it to previous)`);
  assert(keptRuns.includes(NEW), `NEW (${NEW}) kept (active)`);

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 7: Monorepo — same dep name at two versions, suppressions don't swap
//
// Regression for Bug-002: prior code joined old→new PDs by (project_id, name)
// only, so with lodash@4.17.20 AND lodash@4.17.21 in both runs the carry-forward
// subquery produced N×M rows and Postgres' UPDATE…FROM picked one arbitrarily
// per target, silently swapping suppression state between the two PDs.
// -----------------------------------------------------------------------------
async function testMonorepoMultiVersionNoCrossSwap(): Promise<void> {
  console.log('\nTest 7: monorepo two-version — suppressions stay on the right PD');
  const db = await bootDb();
  const PREV_RUN = 'run_prev';
  const NEW_RUN = 'run_new';
  await seedOrgAndProject(db, PREV_RUN);

  const PD_20 = '11111111-1111-1111-1111-111111111111';
  const PD_21 = '22222222-2222-2222-2222-222222222222';
  const ALICE = '33333333-3333-3333-3333-333333333333';

  // Both PDs exist in prev AND new runs — UUIDs stable across runs (the
  // upsert conflict key is (project_id, name, version, is_direct, source)).
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES
      ('${PD_20}', '${PROJECT_ID}', 'lodash', '4.17.20', true, 'dependencies', '${NEW_RUN}', NOW()),
      ('${PD_21}', '${PROJECT_ID}', 'lodash', '4.17.21', true, 'dependencies', '${NEW_RUN}', NOW());
  `);

  // Prev run: PD_20's PDV is suppressed by Alice; PD_21's is not.
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, suppressed, suppressed_by, suppressed_at, detected_at, created_at)
    VALUES
      ('${PROJECT_ID}', '${PD_20}', 'CVE-2021-23337', 'high', '${PREV_RUN}', 'open', true,  '${ALICE}', NOW(), NOW(), NOW()),
      ('${PROJECT_ID}', '${PD_21}', 'CVE-2021-23337', 'high', '${PREV_RUN}', 'open', false, NULL,      NULL,  NOW(), NOW());
  `);

  // New run: both PDVs re-inserted with default (unsuppressed) state.
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, suppressed, detected_at, created_at)
    VALUES
      ('${PROJECT_ID}', '${PD_20}', 'CVE-2021-23337', 'high', '${NEW_RUN}', 'open', false, NOW(), NOW()),
      ('${PROJECT_ID}', '${PD_21}', 'CVE-2021-23337', 'high', '${NEW_RUN}', 'open', false, NOW(), NOW());
  `);

  await callFinalize(db, NEW_RUN);

  const { rows } = await db.query<{ project_dependency_id: string; suppressed: boolean; suppressed_by: string | null }>(
    `SELECT project_dependency_id, suppressed, suppressed_by
     FROM project_dependency_vulnerabilities
     WHERE project_id = $1 AND extraction_run_id = $2
     ORDER BY project_dependency_id`,
    [PROJECT_ID, NEW_RUN],
  );
  const byPd = Object.fromEntries(rows.map((r) => [r.project_dependency_id, r]));
  assert(byPd[PD_20]?.suppressed === true, 'PD_20 (originally suppressed) stays suppressed');
  assert(byPd[PD_20]?.suppressed_by === ALICE, 'PD_20 suppressed_by preserved');
  assert(byPd[PD_21]?.suppressed === false, 'PD_21 (originally unsuppressed) stays unsuppressed (NO cross-swap)');
  assert(byPd[PD_21]?.suppressed_by === null, 'PD_21 has no suppressed_by (NO cross-swap)');

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 8: Unchanged version — severity escalation fires for same PD across runs
//
// Regression for Bug-001: prior code filtered opd via
// "last_seen_extraction_run_id IS DISTINCT FROM current_run", which for
// unchanged-version deps (upsert updates row in place, advancing last_seen
// to current run) silently excluded every candidate — so triggers never fired
// for the most common re-review case: stable installed version, drifted CVE
// severity.
// -----------------------------------------------------------------------------
async function testUnchangedVersionSeverityEscalationFires(): Promise<void> {
  console.log('\nTest 8: unchanged-version severity escalation fires (same PD UUID across runs)');
  const db = await bootDb();
  const PREV_RUN = 'run_prev';
  const NEW_RUN = 'run_new';
  await seedOrgAndProject(db, PREV_RUN);

  const PD_ID = '11111111-1111-1111-1111-111111111111';

  // Single PD row — same UUID across runs, last_seen advances to current run
  // (simulating the upsert's in-place update for unchanged-version deps).
  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES ('${PD_ID}', '${PROJECT_ID}', 'lodash', '4.17.21', true, 'dependencies', '${NEW_RUN}', NOW());
  `);

  // Prev run: CVE at severity=low. New run: OSV reclassified to critical.
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, detected_at, created_at)
    VALUES
      ('${PROJECT_ID}', '${PD_ID}', 'CVE-2021-23337', 'low',      '${PREV_RUN}', 'open', NOW(), NOW()),
      ('${PROJECT_ID}', '${PD_ID}', 'CVE-2021-23337', 'critical', '${NEW_RUN}',  'open', NOW(), NOW());
  `);

  const summary = await callFinalize(db, NEW_RUN);
  assert((summary.vulns_re_review_fired as number) >= 1, 'summary reports >=1 re-review fired for unchanged dep');

  const { rows } = await db.query<{ re_review_triggered_at: string | null; re_review_reasons: any }>(
    `SELECT re_review_triggered_at, re_review_reasons
     FROM project_dependency_vulnerabilities
     WHERE project_id = $1 AND extraction_run_id = $2`,
    [PROJECT_ID, NEW_RUN],
  );
  assert(rows[0]?.re_review_triggered_at !== null, 're_review_triggered_at set for unchanged dep');
  const reasons = Array.isArray(rows[0]?.re_review_reasons) ? rows[0].re_review_reasons : [];
  const triggers = reasons.map((r: any) => r?.trigger).filter(Boolean);
  assert(triggers.includes('severity_escalation'), `severity_escalation fires (got: ${JSON.stringify(triggers)})`);

  const events = await db.query<{ event_type: string }>(
    `SELECT event_type FROM project_vulnerability_events WHERE project_id = $1 AND event_type = 'rereview_triggered'`,
    [PROJECT_ID],
  );
  assert(events.rows.length >= 1, 'rereview_triggered event written');

  await db.close();
}

// -----------------------------------------------------------------------------
// Test 9: Monorepo same CVE on two PDs — first-run emits one event per PD
//
// Regression for B1: the partial unique index idx_pve_unique_per_run originally
// keyed on (project_id, osv_id, event_type, extraction_run_id) only. When two
// PDs in the same project shared a CVE (e.g. lodash@4.17.20 direct +
// lodash@4.17.21 nested-transitive, both with CVE-X), both INSERTs produced the
// same conflict key and the second was ON CONFLICT DO NOTHING'd — so only one
// `detected` event was emitted, contradicting the per-PD notification intent.
// Phase 19.6 adds project_dependency_id to the unique key so distinct PDs
// under the same CVE each emit their own event while retries (same pd_id)
// still dedup cleanly.
// -----------------------------------------------------------------------------
async function testMonorepoSameCveTwoPDsEmitTwoEvents(): Promise<void> {
  console.log('\nTest 9: monorepo same-CVE two PDs — two detected events, one per PD');
  const db = await bootDb();
  const RUN = 'run_first';
  await seedOrgAndProject(db, null); // first run

  const PD_20 = '11111111-1111-1111-1111-111111111111';
  const PD_21 = '22222222-2222-2222-2222-222222222222';

  await db.exec(`
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
    VALUES
      ('${PD_20}', '${PROJECT_ID}', 'lodash', '4.17.20', true,  'dependencies', '${RUN}', NOW()),
      ('${PD_21}', '${PROJECT_ID}', 'lodash', '4.17.21', false, 'dependencies', '${RUN}', NOW());
  `);
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities
      (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, detected_at, created_at)
    VALUES
      ('${PROJECT_ID}', '${PD_20}', 'CVE-2021-23337', 'high', '${RUN}', 'open', NOW(), NOW()),
      ('${PROJECT_ID}', '${PD_21}', 'CVE-2021-23337', 'high', '${RUN}', 'open', NOW(), NOW());
  `);

  await callFinalize(db, RUN);

  const events = await db.query<{ event_type: string; project_dependency_id: string | null }>(
    `SELECT event_type, project_dependency_id
     FROM project_vulnerability_events
     WHERE project_id = $1 AND osv_id = 'CVE-2021-23337'
     ORDER BY project_dependency_id`,
    [PROJECT_ID],
  );
  assert(events.rows.length === 2, `two events written, one per PD (got ${events.rows.length})`);
  assert(events.rows.every((e) => e.event_type === 'detected'), 'both events are type=detected');
  const pdIds = events.rows.map((e) => e.project_dependency_id).sort();
  assert(pdIds[0] === PD_20 && pdIds[1] === PD_21, `events carry distinct pd_ids (got ${JSON.stringify(pdIds)})`);

  // Retry-within-same-run_id isn't a production scenario (recover_stuck_scan_jobs
  // always assigns a new run_id before requeuing). Cross-run retry idempotency is
  // covered by the partial unique index itself: on a different run_id, events from
  // the prior run stay, and the new run's INSERTs only conflict if the same
  // (project, osv, event_type, run_id, pd_id) is re-inserted by the new run's own
  // retry — which happens within a transaction that would've rolled back the events.

  await db.close();
}

// -----------------------------------------------------------------------------
async function main() {
  const t0 = Date.now();
  const tests = [
    testMarkRemoved,
    testPointerFlip,
    testCarryForwardSuppression,
    testSeverityEscalationTrigger,
    testFirstRunDetectedEvents,
    testReapOldRuns,
    testMonorepoMultiVersionNoCrossSwap,
    testUnchangedVersionSeverityEscalationFires,
    testMonorepoSameCveTwoPDsEmitTwoEvents,
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
