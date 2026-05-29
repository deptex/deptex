/**
 * Read-only / dry probe for the fleet dispatcher against REAL infra.
 *
 * Unlike e2e-fleet-live.ts (which spins a real billable Fly machine), this
 * probe NEVER provisions: it only runs when the extraction queue is empty, so
 * every tick computes startN=0. Its job is to prove the parts the unit suite
 * had to fake — the Redis lock CAS, the starting-set sorted-set ops, the live
 * fleet_scan_snapshot RPC, and listMachines() — all behave against the real
 * Upstash + Supabase + Fly services. Zero spend.
 *
 *   npm run fleet:probe        (in backend/)
 *
 * What it checks:
 *  1. Redis is actually configured (lock path is real, not the lockless CE fallback).
 *  2. getFleetMetrics() round-trips against live Supabase + Upstash + Fly.
 *  3. A single dispatchFleet() tick acquires + releases the lock, queue empty ⇒ 0 starts.
 *  4. TWO concurrent ticks: exactly one holds the lock, the other collapses
 *     (lockHeld:false) — the single-flight guarantee, against real SET NX.
 */
import 'dotenv/config';
import { getRedisClient } from '../src/lib/cache';
import { getFleetMetrics, dispatchFleet } from '../src/lib/fleet-dispatcher';

const TYPE = 'extraction';

function line() {
  console.log('─'.repeat(64));
}

async function main(): Promise<void> {
  let failures = 0;

  // 1. Redis presence — the lock path must be real, not the lockless fallback.
  line();
  const redis = getRedisClient();
  if (!redis) {
    console.error(
      '✗ Redis NOT configured locally — the dispatcher would run in lockless CE mode, ' +
        'so this probe cannot exercise the single-flight lock. Set UPSTASH_REDIS_URL/TOKEN.',
    );
    process.exit(2);
  }
  console.log('✓ Redis client configured (real Upstash) — lock path is live.');

  // 2. getFleetMetrics — pure read against Supabase + Upstash + Fly.
  line();
  console.log('Probe 2: getFleetMetrics (read-only)…');
  const metrics = await getFleetMetrics(TYPE);
  console.log(JSON.stringify(metrics, null, 2));
  if (typeof metrics.queued !== 'number' || typeof metrics.maxFleet !== 'number') {
    console.error('✗ metrics shape unexpected');
    failures++;
  } else {
    console.log(
      `✓ metrics round-tripped — queued=${metrics.queued} running=${metrics.running} ` +
        `starting=${metrics.starting} flyActive=${metrics.flyActive} inflight=${metrics.inflight} ` +
        `maxFleet=${metrics.maxFleet}`,
    );
  }

  // Safety gate: only run provisioning ticks when the queue is empty. A
  // non-empty queue + a warm stopped-machine pool could make dispatchFleet
  // start a real (billable) machine via the reuse path even without an image.
  if (metrics.queued > 0) {
    line();
    console.warn(
      `⚠ ${metrics.queued} extraction job(s) queued — skipping the dispatch ticks so the probe ` +
        'never provisions. Re-run when the queue is idle to exercise the lock.',
    );
    process.exit(failures ? 1 : 0);
  }

  // 3. One dispatch tick — acquires + releases the lock; queue empty ⇒ 0 starts.
  line();
  console.log('Probe 3: single dispatchFleet tick (queue empty ⇒ must start 0)…');
  const tick = await dispatchFleet(TYPE);
  console.log(JSON.stringify(tick, null, 2));
  if (tick.error) {
    console.error(`✗ tick returned error: ${tick.error}`);
    failures++;
  } else if (!tick.lockHeld) {
    console.error('✗ tick did not hold the lock — expected lockHeld:true on a solo run');
    failures++;
  } else if (tick.started !== 0) {
    console.error(`✗ tick started ${tick.started} machines on an EMPTY queue — should be 0`);
    failures++;
  } else {
    console.log('✓ single tick acquired+released the real lock, started 0 (empty queue).');
  }

  // 4. Two concurrent ticks — single-flight: exactly one wins the lock.
  line();
  console.log('Probe 4: TWO concurrent dispatchFleet ticks (single-flight against real SET NX)…');
  const [a, b] = await Promise.all([dispatchFleet(TYPE), dispatchFleet(TYPE)]);
  const held = [a, b].filter((r) => r.lockHeld).length;
  const collapsed = [a, b].filter((r) => !r.lockHeld && !r.error).length;
  console.log(`  tick A: lockHeld=${a.lockHeld} started=${a.started} error=${a.error ?? '—'}`);
  console.log(`  tick B: lockHeld=${b.lockHeld} started=${b.started} error=${b.error ?? '—'}`);
  if (held === 1 && collapsed === 1) {
    console.log('✓ single-flight confirmed against real Upstash — one tick held, one collapsed.');
  } else {
    console.error(
      `✗ single-flight NOT confirmed: ${held} held the lock, ${collapsed} cleanly collapsed ` +
        '(expected exactly 1 and 1). Note: a sub-millisecond release can let both acquire — re-run.',
    );
    failures++;
  }

  line();
  if (failures === 0) {
    console.log('PASS — real-infra read + lock mechanics verified, zero spend.');
  } else {
    console.error(`FAIL — ${failures} probe(s) failed.`);
  }
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error('[fleet-probe] FAILED:', e?.message ?? e);
  process.exit(1);
});
