/**
 * Integration test: fleet_scan_snapshot (phase42) against an in-memory PGLite
 * running the real schema.sql.
 *
 * The fleet-dispatcher unit suite MOCKS this RPC (setRpcResponse), so its actual
 * SQL aggregation has never run against a real Postgres. This drives it directly
 * and proves the semantics the dispatcher depends on:
 *
 *   1. per_org.queued / per_org.inflight are per-org FILTERed counts.
 *   2. inflight is a ROW count of processing jobs — NOT distinct machines — so it
 *      matches claim_scan_job's per-org cap math.
 *   3. running_machine_ids is DISTINCT machine_id (two processing jobs on one
 *      machine ⇒ one id) and excludes NULL machine_ids.
 *   4. Type isolation: an extraction snapshot ignores dast rows and vice-versa.
 *   5. Status isolation: completed jobs are excluded; an org with only processing
 *      (0 queued) still appears in per_org.
 *   6. An unused type returns the COALESCE empty-array shape ({per_org:[], running_machine_ids:[]}).
 *
 * Run: npx tsx test/fleet-snapshot-pglite.test.ts
 */
import { createPGLiteStorage } from '../src/storage';

let failures = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

const ORG_A = '00000000-0000-0000-0000-00000000000a';
const ORG_B = '00000000-0000-0000-0000-00000000000b';
const ORG_C = '00000000-0000-0000-0000-00000000000c';
const ORG_D = '00000000-0000-0000-0000-00000000000d';

interface OrgRow {
  organization_id: string;
  queued: number;
  inflight: number;
}
interface Snapshot {
  running_machine_ids: string[];
  per_org: OrgRow[];
}

async function main(): Promise<void> {
  console.log('Booting PGLiteStorage (schema.sql)...');
  const storage = await createPGLiteStorage();
  const db = (storage as any).db;
  // FK triggers off so we can insert scan_jobs with synthetic org/project ids
  // without seeding the full organizations/projects graph.
  await db.exec(`SET session_replication_role = 'replica';`);
  await db.exec(`DELETE FROM scan_jobs;`);

  const queued = async (org: string, type = 'extraction') => {
    await db.query(
      `INSERT INTO scan_jobs (project_id, organization_id, type, status, run_id, payload)
       VALUES (gen_random_uuid(), $1, $2, 'queued', gen_random_uuid(), '{}'::jsonb)`,
      [org, type],
    );
  };
  const processing = async (org: string, machineId: string | null, type = 'extraction') => {
    await db.query(
      `INSERT INTO scan_jobs (project_id, organization_id, type, status, run_id, payload, machine_id, started_at, heartbeat_at)
       VALUES (gen_random_uuid(), $1, $2, 'processing', gen_random_uuid(), '{}'::jsonb, $3, NOW(), NOW())`,
      [org, type, machineId],
    );
  };
  const completed = async (org: string) => {
    await db.query(
      `INSERT INTO scan_jobs (project_id, organization_id, type, status, run_id, payload, machine_id, completed_at)
       VALUES (gen_random_uuid(), $1, 'extraction', 'completed', gen_random_uuid(), '{}'::jsonb, 'm-done', NOW())`,
      [org],
    );
  };
  const snapshot = async (type: string): Promise<Snapshot> => {
    const res = await db.query(`SELECT fleet_scan_snapshot($1) AS s`, [type]);
    return res.rows[0].s as Snapshot;
  };
  const byOrg = (s: Snapshot, org: string) => s.per_org.find((o) => o.organization_id === org);

  // --- Seed ---
  // Org A: 3 queued + 2 processing on TWO distinct machines.
  await queued(ORG_A);
  await queued(ORG_A);
  await queued(ORG_A);
  await processing(ORG_A, 'm-a1');
  await processing(ORG_A, 'm-a2');
  // Org B: 1 queued + 1 processing.
  await queued(ORG_B);
  await processing(ORG_B, 'm-b1');
  // Org C: 0 queued + 2 processing on the SAME machine (distinct-dedup probe).
  await processing(ORG_C, 'm-c1');
  await processing(ORG_C, 'm-c1');
  // Org D: 1 processing with NULL machine_id (NULL-exclusion probe).
  await processing(ORG_D, null);
  // Noise that must be ignored by an extraction snapshot:
  await completed(ORG_A); // wrong status
  await queued(ORG_A, 'dast'); // wrong type
  await processing(ORG_A, 'm-dast1', 'dast'); // wrong type

  // --- Test 1: extraction per-org counts ---
  console.log('\n[test] extraction snapshot — per-org queued/inflight');
  const ext = await snapshot('extraction');
  assert(byOrg(ext, ORG_A)?.queued === 3, `A queued=3: got ${byOrg(ext, ORG_A)?.queued}`);
  assert(byOrg(ext, ORG_A)?.inflight === 2, `A inflight=2: got ${byOrg(ext, ORG_A)?.inflight}`);
  assert(byOrg(ext, ORG_B)?.queued === 1, `B queued=1: got ${byOrg(ext, ORG_B)?.queued}`);
  assert(byOrg(ext, ORG_B)?.inflight === 1, `B inflight=1: got ${byOrg(ext, ORG_B)?.inflight}`);

  // --- Test 2: org with 0 queued but processing still appears; inflight is row-count ---
  console.log('\n[test] org C — 0 queued, 2 processing on one machine');
  assert(byOrg(ext, ORG_C) !== undefined, 'C present in per_org despite 0 queued');
  assert(byOrg(ext, ORG_C)?.queued === 0, `C queued=0: got ${byOrg(ext, ORG_C)?.queued}`);
  assert(
    byOrg(ext, ORG_C)?.inflight === 2,
    `C inflight=2 (ROW count, not distinct-machine): got ${byOrg(ext, ORG_C)?.inflight}`,
  );

  // --- Test 3: NULL machine_id processing counts toward inflight, not running ids ---
  console.log('\n[test] org D — processing with NULL machine_id');
  assert(byOrg(ext, ORG_D)?.inflight === 1, `D inflight=1 despite NULL machine: got ${byOrg(ext, ORG_D)?.inflight}`);

  // --- Test 4: running_machine_ids is DISTINCT + excludes NULL + excludes dast ---
  console.log('\n[test] running_machine_ids — distinct, no NULL, no dast');
  const ids = [...ext.running_machine_ids].sort();
  assert(
    JSON.stringify(ids) === JSON.stringify(['m-a1', 'm-a2', 'm-b1', 'm-c1']),
    `running ids = [m-a1,m-a2,m-b1,m-c1] (m-c1 deduped, NULL+dast excluded): got ${JSON.stringify(ids)}`,
  );

  // --- Test 5: type isolation — dast snapshot sees only dast rows ---
  console.log('\n[test] dast snapshot — only dast rows');
  const dast = await snapshot('dast');
  assert(
    JSON.stringify(dast.running_machine_ids) === JSON.stringify(['m-dast1']),
    `dast running ids = [m-dast1]: got ${JSON.stringify(dast.running_machine_ids)}`,
  );
  assert(byOrg(dast, ORG_A)?.queued === 1, `dast A queued=1: got ${byOrg(dast, ORG_A)?.queued}`);
  assert(byOrg(dast, ORG_A)?.inflight === 1, `dast A inflight=1: got ${byOrg(dast, ORG_A)?.inflight}`);

  // --- Test 6: unused type returns the COALESCE empty shape ---
  console.log('\n[test] unused type — empty COALESCE shape');
  const empty = await snapshot('fix');
  assert(Array.isArray(empty.per_org) && empty.per_org.length === 0, 'fix per_org = []');
  assert(
    Array.isArray(empty.running_machine_ids) && empty.running_machine_ids.length === 0,
    'fix running_machine_ids = []',
  );

  console.log(failures === 0 ? '\nALL PASSED' : `\n${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
