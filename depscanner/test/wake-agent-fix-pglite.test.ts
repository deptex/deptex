/**
 * Integration test: the `wake_agent_fix` RPC (Wake the Task Agent) + the
 * `deduct_balance` meter dedup, against an in-memory PGLite running the real
 * schema.sql with backend/database/wake_task_agent.sql applied on top (the
 * migration is idempotent, so this passes both before and after the prod
 * schema:dump lands).
 *
 * What it pins:
 *   - wake resets a terminal ('completed' / 'failed' / 'rejected') AGENT row:
 *     status -> 'approved', run_seq +1, plan.resume = true,
 *     plan.prior_status = <old status>, machine_id / started_at / completed_at
 *     / error_* / rejected_* cleared, attempts = 0, approved_at stamped —
 *     and RETURNS the row id.
 *   - wake returns NULL (and touches nothing) for: an 'executing' row, an
 *     'approved' row, a non-agent-strategy row, and a missing id.
 *   - re-open housekeeping lives IN the RPC: the task's completed_at is
 *     nulled, a 'cancelled' task flips back to 'working', and the task's
 *     provider='aegis' tracker chips flip 'done' -> 'open'.
 *   - THE money-path assertion: `deduct_balance` is idempotent on
 *     (org, idempotency_key) — the same `fix-worker:{fixId}:run-N` key bills
 *     exactly once (a duplicate raises 23505 and the balance update rolls
 *     back with it), while the next run's `:run-N+1` key bills again.
 *
 * FK triggers are disabled (session_replication_role='replica') so rows can
 * use synthetic org/project ids; CHECK constraints + unique indexes still
 * enforce, which is exactly what the dedup assertion relies on.
 *
 * Run: npx tsx test/wake-agent-fix-pglite.test.ts
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

const MIGRATION = path.resolve(__dirname, '../../backend/database/wake_task_agent.sql');

const u = (n: string) => `00000000-0000-0000-0000-0000000000${n}`;
const ORG = u('01');

async function main(): Promise<void> {
  console.log('Booting PGLiteStorage (schema.sql)...');
  const storage = await createPGLiteStorage();
  const db = (storage as any).db;

  console.log('Applying wake_task_agent.sql (idempotent)...');
  await db.exec(fs.readFileSync(MIGRATION, 'utf-8'));
  // FK triggers off so we can insert with synthetic org/project/user ids.
  await db.exec(`SET session_replication_role = 'replica';`);

  let taskSeq = 0;
  const makeTask = async (status: string, completedAt: boolean): Promise<string> =>
    (await db.query(
      `INSERT INTO aegis_agent_tasks (organization_id, title, status, total_fixes, completed_at)
       VALUES ($1, $2, $3, 1, ${completedAt ? 'NOW()' : 'NULL'}) RETURNING id`,
      [ORG, `task ${++taskSeq}`, status],
    )).rows[0].id as string;

  const addFix = async (opts: {
    taskId?: string | null;
    status: string;
    strategy?: string;
  }): Promise<string> =>
    (await db.query(
      `INSERT INTO project_security_fixes
         (project_id, organization_id, fix_type, strategy, status, task_id,
          machine_id, started_at, completed_at, error_message, error_category,
          failure_details, rejected_at, rejected_by_user_id, rejection_reason,
          attempts, max_attempts, plan)
       VALUES (gen_random_uuid(), $1, 'vulnerability', $2, $3, $4,
               'machine-old', NOW(), NOW(), 'old error', 'system_error',
               '{"kind":"old"}'::jsonb, NOW(), gen_random_uuid(), 'stopped',
               1, 1, '{"strategy":"agent","summary":"fix it"}'::jsonb)
       RETURNING id`,
      [ORG, opts.strategy ?? 'agent', opts.status, opts.taskId ?? null],
    )).rows[0].id as string;

  const addLink = async (taskId: string, state: string): Promise<void> => {
    await db.query(
      `INSERT INTO finding_tracker_links
         (organization_id, project_id, finding_type, finding_key, provider, external_id, external_state)
       VALUES ($1, gen_random_uuid(), 'vulnerability', $2, 'aegis', $3, $4)`,
      [ORG, `key-${taskId.slice(0, 8)}`, taskId, state],
    );
  };

  const wake = async (fixId: string): Promise<string | null> =>
    (await db.query(`SELECT public.wake_agent_fix($1) AS id`, [fixId])).rows[0].id as string | null;

  const fixRow = async (id: string) =>
    (await db.query(
      `SELECT status, run_seq, attempts, machine_id, started_at, completed_at,
              error_message, error_category, failure_details, rejected_at,
              rejected_by_user_id, rejection_reason, approved_at,
              plan->>'resume' AS resume, plan->>'prior_status' AS prior_status,
              plan->>'summary' AS summary
       FROM project_security_fixes WHERE id = $1`,
      [id],
    )).rows[0];

  // --- A: wake resets each terminal status and returns the id ---
  console.log('\n[A] wake resets completed / failed / rejected agent rows');
  for (const prior of ['completed', 'failed', 'rejected']) {
    const t = await makeTask('completed', true);
    const f = await addFix({ taskId: t, status: prior });
    const woke = await wake(f);
    assert(woke === f, `${prior}: returns the fix id (got ${woke})`);
    const row = await fixRow(f);
    assert(row.status === 'approved', `${prior}: status -> approved (got ${row.status})`);
    assert(Number(row.run_seq) === 1, `${prior}: run_seq 0 -> 1 (got ${row.run_seq})`);
    assert(Number(row.attempts) === 0, `${prior}: attempts reset to 0 (got ${row.attempts})`);
    assert(row.resume === 'true', `${prior}: plan.resume = true (got ${row.resume})`);
    assert(row.prior_status === prior, `${prior}: plan.prior_status = '${prior}' (got ${row.prior_status})`);
    assert(row.summary === 'fix it', `${prior}: rest of plan preserved (got ${row.summary})`);
    assert(row.machine_id === null, `${prior}: machine_id cleared`);
    assert(row.started_at === null && row.completed_at === null, `${prior}: started_at/completed_at cleared`);
    assert(
      row.error_message === null && row.error_category === null && row.failure_details === null,
      `${prior}: error_* / failure_details cleared`,
    );
    assert(
      row.rejected_at === null && row.rejected_by_user_id === null && row.rejection_reason === null,
      `${prior}: rejected_* cleared`,
    );
    assert(row.approved_at !== null, `${prior}: approved_at stamped`);
  }

  // --- B: NULL (no reset) for non-terminal / non-agent / missing rows ---
  console.log('\n[B] wake no-ops: executing, approved, non-agent strategy, random uuid');
  {
    for (const active of ['executing', 'approved']) {
      const t = await makeTask('working', false);
      const f = await addFix({ taskId: t, status: active });
      const woke = await wake(f);
      const row = await fixRow(f);
      assert(woke === null, `${active} row: returns NULL (got ${woke})`);
      assert(row.status === active, `${active} row: status untouched (got ${row.status})`);
      assert(Number(row.run_seq) === 0, `${active} row: run_seq unchanged (got ${row.run_seq})`);
      assert(row.resume === null, `${active} row: plan not stamped`);
    }
    const t = await makeTask('completed', true);
    const f = await addFix({ taskId: t, status: 'completed', strategy: 'code_patch' });
    const woke = await wake(f);
    const row = await fixRow(f);
    assert(woke === null, `non-agent strategy: returns NULL (got ${woke})`);
    assert(row.status === 'completed' && Number(row.run_seq) === 0, `non-agent strategy: row untouched`);
    const missing = await wake(u('ff'));
    assert(missing === null, `missing id: returns NULL (got ${missing})`);
  }

  // --- C: re-open housekeeping (task completed_at + aegis chips) ---
  console.log('\n[C] re-open housekeeping: chips done -> open, task completed_at nulled');
  {
    const t = await makeTask('completed', true);
    const f = await addFix({ taskId: t, status: 'completed' });
    await addLink(t, 'done');
    await wake(f);
    const task = (await db.query(
      `SELECT status, completed_at FROM aegis_agent_tasks WHERE id = $1`, [t],
    )).rows[0];
    assert(task.completed_at === null, `task completed_at nulled (got ${task.completed_at})`);
    assert(task.status === 'completed', `non-cancelled task status left to the rollup trigger (got ${task.status})`);
    const link = (await db.query(
      `SELECT external_state, external_state_synced_at FROM finding_tracker_links WHERE external_id = $1`, [t],
    )).rows[0];
    assert(link.external_state === 'open', `aegis chip flipped done -> open (got ${link.external_state})`);
    assert(link.external_state_synced_at !== null, `chip synced_at stamped`);
  }

  // --- D: a 'cancelled' task is un-cancelled (rollup trigger early-returns on it) ---
  console.log("\n[D] wake un-cancels a 'cancelled' task");
  {
    const t = await makeTask('cancelled', true);
    const f = await addFix({ taskId: t, status: 'rejected' });
    await wake(f);
    const task = (await db.query(
      `SELECT status, completed_at FROM aegis_agent_tasks WHERE id = $1`, [t],
    )).rows[0];
    assert(task.status === 'working', `cancelled -> working (got ${task.status})`);
    assert(task.completed_at === null, `completed_at nulled`);
  }

  // --- E: a second wake of the SAME row bumps run_seq again (each wake = one billed run) ---
  console.log('\n[E] repeated wake keeps bumping run_seq');
  {
    const t = await makeTask('completed', true);
    const f = await addFix({ taskId: t, status: 'completed' });
    await wake(f);
    await db.query(`UPDATE project_security_fixes SET status = 'failed' WHERE id = $1`, [f]);
    const again = await wake(f);
    const row = await fixRow(f);
    assert(again === f, `second wake returns the id`);
    assert(Number(row.run_seq) === 2, `run_seq 1 -> 2 (got ${row.run_seq})`);
    assert(row.prior_status === 'failed', `prior_status re-stamped to the latest terminal (got ${row.prior_status})`);
  }

  // --- F: deduct_balance meter dedup on (org, idempotency_key) ---
  console.log('\n[F] deduct_balance: same run key bills once, next run key bills again');
  {
    const FIX = u('e1');
    await db.query(
      `INSERT INTO organization_billing (organization_id, balance_cents) VALUES ($1, 1000)`,
      [ORG],
    );
    const meta = (runSeq: number) =>
      JSON.stringify({
        event_type: 'worker_minutes',
        provider: 'fly',
        feature: 'aegis.fix_task',
        quantity: 120,
        unit: 'seconds',
        attribution_resource_type: 'fix_task',
        attribution_resource_id: FIX,
        // run_seq=0 keeps the historical ':final' key; wakes use ':run-N'.
        idempotency_key: runSeq === 0 ? `fix-worker:${FIX}:final` : `fix-worker:${FIX}:run-${runSeq}`,
      });
    const deduct = async (runSeq: number): Promise<{ bal: number | null; err: string | null }> => {
      try {
        const r = await db.query(
          `SELECT public.deduct_balance($1, 100, 'fix run', $2::jsonb) AS bal`,
          [ORG, meta(runSeq)],
        );
        return { bal: r.rows[0].bal === null ? null : Number(r.rows[0].bal), err: null };
      } catch (e: any) {
        return { bal: null, err: String(e?.message ?? e) };
      }
    };
    const balance = async (): Promise<number> =>
      Number((await db.query(
        `SELECT balance_cents FROM organization_billing WHERE organization_id = $1`, [ORG],
      )).rows[0].balance_cents);

    const first = await deduct(0);
    assert(first.err === null && first.bal === 900, `run-0 bills once (bal ${first.bal}, err ${first.err})`);

    const dup = await deduct(0);
    assert(dup.err !== null && /duplicate key|unique/i.test(dup.err), `duplicate run-0 key raises 23505 (got ${dup.err ?? dup.bal})`);
    assert((await balance()) === 900, `balance NOT deducted twice for the same key (got ${await balance()})`);

    const second = await deduct(1);
    assert(second.err === null && second.bal === 800, `run-1 (a wake) bills again (bal ${second.bal}, err ${second.err})`);
    assert((await balance()) === 800, `final balance reflects exactly two billed runs`);
  }

  console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('FATAL', err);
  process.exit(1);
});
