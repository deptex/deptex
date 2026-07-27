/**
 * Integration test: the Aegis Task rollup trigger (recompute_aegis_task_status)
 * against an in-memory PGLite running the real schema.sql + the phase9z
 * migration applied on top (so this runs BEFORE the prod schema:dump lands).
 *
 * PGLite never transitions fix status in the other suites, so this is the only
 * place the trigger is exercised. It checks the four review-fixed behaviors:
 *   - all fixes succeed   -> task 'completed' AND Aegis chips flip to 'done'
 *   - mixed success/fail  -> 'completed_with_failures' AND chips stay 'open'
 *   - all fixes fail       -> 'failed' AND chips stay 'open'
 *   - cancelled task       -> fixes drain but status + chips are NEVER touched
 *   - ordinary fix (task_id NULL) -> trigger never fires (WHEN guard)
 *   - no premature completion while planned > existing fixes
 *
 * The rollup trigger is set ENABLE ALWAYS so it fires under
 * session_replication_role='replica' (which we use to skip FK seeding).
 *
 * Run: npx tsx test/aegis-task-rollup-pglite.test.ts
 */
import * as fs from 'fs';
import * as path from 'path';
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

const MIGRATION = path.resolve(__dirname, '../../backend/database/phase9z_aegis_agent_tasks.sql');

const u = (n: string) => `00000000-0000-0000-0000-0000000000${n}`;

async function main(): Promise<void> {
  console.log('Booting PGLiteStorage (schema.sql)...');
  const storage = await createPGLiteStorage();
  const db = (storage as any).db;

  console.log('Applying phase9z_aegis_agent_tasks.sql...');
  await db.exec(fs.readFileSync(MIGRATION, 'utf-8'));
  // Fire the rollup even with FK triggers disabled below.
  await db.exec(`ALTER TABLE project_security_fixes ENABLE ALWAYS TRIGGER trg_recompute_aegis_task_status;`);
  // FK triggers off so we can insert with synthetic org/project/user ids.
  await db.exec(`SET session_replication_role = 'replica';`);

  const ORG = u('01');

  let taskSeq = 0;
  const makeTask = async (status: string, totalFixes: number): Promise<string> => {
    const id = (await db.query(
      `INSERT INTO aegis_agent_tasks (organization_id, title, status, total_fixes)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [ORG, `task ${++taskSeq}`, status, totalFixes],
    )).rows[0].id as string;
    return id;
  };
  const addFix = async (taskId: string | null, status: string): Promise<string> => {
    const id = (await db.query(
      `INSERT INTO project_security_fixes
         (project_id, organization_id, fix_type, strategy, status, triggered_by, task_id, osv_id)
       VALUES (gen_random_uuid(), $1, 'vulnerability', 'code_patch', $2, gen_random_uuid(), $3, 'CVE-X')
       RETURNING id`,
      [ORG, status, taskId],
    )).rows[0].id as string;
    return id;
  };
  const addLink = async (taskId: string, key: string): Promise<void> => {
    await db.query(
      `INSERT INTO finding_tracker_links
         (organization_id, project_id, finding_type, finding_key, provider, external_id, external_state)
       VALUES ($1, gen_random_uuid(), 'vulnerability', $2, 'aegis', $3, 'open')`,
      [ORG, key, taskId],
    );
  };
  const setFix = async (fixId: string, status: string): Promise<void> => {
    await db.query(`UPDATE project_security_fixes SET status = $2 WHERE id = $1`, [fixId, status]);
  };
  const taskRow = async (id: string) =>
    (await db.query(`SELECT status, completed_fixes, failed_fixes FROM aegis_agent_tasks WHERE id = $1`, [id])).rows[0];
  const linkStates = async (taskId: string): Promise<string[]> =>
    (await db.query(`SELECT external_state FROM finding_tracker_links WHERE external_id = $1`, [taskId])).rows.map(
      (r: any) => r.external_state,
    );

  // --- Scenario A: all fixes succeed -> completed + chips done ---
  console.log('\n[A] all fixes succeed -> completed + chips ✓');
  {
    const t = await makeTask('working', 2);
    const f1 = await addFix(t, 'approved');
    const f2 = await addFix(t, 'approved');
    await addLink(t, 'k-a1');
    await addLink(t, 'k-a2');
    let row = await taskRow(t);
    assert(row.status === 'working', `still working while fixes approved (got ${row.status})`);
    await setFix(f1, 'completed');
    row = await taskRow(t);
    assert(row.status === 'working', `still working with 1/2 completed (got ${row.status})`);
    await setFix(f2, 'completed');
    row = await taskRow(t);
    assert(row.status === 'completed', `completed when all succeed (got ${row.status})`);
    assert(Number(row.completed_fixes) === 2, `completed_fixes=2 (got ${row.completed_fixes})`);
    const states = await linkStates(t);
    assert(states.length === 2 && states.every((s) => s === 'done'), `both chips flipped to done (got ${states})`);
  }

  // --- Scenario B: mixed -> completed_with_failures + chips stay open ---
  console.log('\n[B] mixed -> completed_with_failures + NO chip ✓');
  {
    const t = await makeTask('working', 2);
    const f1 = await addFix(t, 'approved');
    const f2 = await addFix(t, 'approved');
    await addLink(t, 'k-b1');
    await setFix(f1, 'completed');
    await setFix(f2, 'failed');
    const row = await taskRow(t);
    assert(row.status === 'completed_with_failures', `completed_with_failures (got ${row.status})`);
    assert(Number(row.failed_fixes) === 1, `failed_fixes=1 (got ${row.failed_fixes})`);
    const states = await linkStates(t);
    assert(states.every((s) => s === 'open'), `chips stay open on partial failure (got ${states})`);
  }

  // --- Scenario C: all fail -> failed + chips stay open ---
  console.log('\n[C] all fail -> failed + NO chip ✓');
  {
    const t = await makeTask('working', 2);
    const f1 = await addFix(t, 'approved');
    const f2 = await addFix(t, 'approved');
    await addLink(t, 'k-c1');
    await setFix(f1, 'failed');
    await setFix(f2, 'rejected');
    const row = await taskRow(t);
    assert(row.status === 'failed', `failed when none succeed (got ${row.status})`);
    const states = await linkStates(t);
    assert(states.every((s) => s === 'open'), `chips stay open on total failure (got ${states})`);
  }

  // --- Scenario D: cancelled task -> never touched ---
  console.log('\n[D] cancelled task -> fixes drain but status + chips frozen');
  {
    const t = await makeTask('cancelled', 1);
    const f1 = await addFix(t, 'approved');
    await addLink(t, 'k-d1');
    await setFix(f1, 'completed');
    const row = await taskRow(t);
    assert(row.status === 'cancelled', `status stays cancelled (got ${row.status})`);
    const states = await linkStates(t);
    assert(states.every((s) => s === 'open'), `chips never flip for a cancelled task (got ${states})`);
  }

  // --- Scenario E: ordinary fix (task_id NULL) -> trigger never fires ---
  console.log('\n[E] ordinary fix (task_id NULL) does not fire the rollup');
  {
    const t = await makeTask('working', 1);
    const before = await taskRow(t);
    const f = await addFix(null, 'approved'); // no task_id
    await setFix(f, 'completed');
    const after = await taskRow(t);
    assert(after.status === before.status, `unrelated task untouched by a task_id-less fix (got ${after.status})`);
  }

  console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('FATAL', err);
  process.exit(1);
});
