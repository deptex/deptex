import { randomUUID } from 'crypto';
import { supabase } from './supabase';
import { getRedisClient } from './cache';
import {
  DEPSCANNER_CONFIG,
  listMachines,
  startMachine,
  createDepscannerBurst,
  resolveDepscannerImage,
  machineMatchesScanType,
  ACTIVE_MACHINE_STATES,
  FlyRateLimitError,
  type FlyMachine,
} from './fly-machines';

/**
 * Fleet dispatcher — the horizontally-scalable autoscaler for the depscanner
 * worker fleet. See `.cursor/plans/scalable-extraction-infra.plan.md`.
 *
 * One tick reconciles `desired = min(MAX_FLEET, claimable backlog)` against the
 * current `inflight` machine count and creates the difference (batched). It is
 * single-flight via a Redis lock so MAX_FLEET is a hard cap across all backend
 * instances; it fails CLOSED when Redis is configured but unreachable (never
 * silently runs lock-free in multi-instance prod). Triggered by an in-process
 * nudge on enqueue and a per-minute safety-net cron.
 */

export interface FleetTickResult {
  type: string;
  queued: number;
  running: number;
  starting: number;
  flyActive: number;
  inflight: number;
  desired: number;
  started: number;
  capped: boolean; // hit MAX_FLEET
  spendBlocked: boolean;
  lockHeld: boolean; // false ⇒ another tick held the lock (no-op) or fail-closed
  error?: string;
}

interface PerOrgRow {
  organization_id: string;
  queued: number;
  inflight: number;
}

function cfg() {
  return {
    maxFleet: parseInt(process.env.FLY_MAX_FLEET || '25', 10),
    maxPerOrg: parseInt(process.env.FLY_MAX_PER_ORG || '5', 10),
    lockTtlSec: parseInt(process.env.FLEET_LOCK_TTL_SEC || '120', 10),
    batchPerTick: parseInt(process.env.FLEET_BATCH_PER_TICK || '8', 10),
    startingTtlSec: parseInt(process.env.FLEET_STARTING_TTL_SEC || '180', 10),
    allowLockless: process.env.FLEET_ALLOW_LOCKLESS === 'true',
    spendCapUsd: process.env.FLY_MAX_SPEND_PER_HOUR_USD
      ? parseFloat(process.env.FLY_MAX_SPEND_PER_HOUR_USD)
      : null,
    estPerMachineUsd: parseFloat(process.env.FLY_EST_MACHINE_USD || '0.15'),
  };
}

type RedisClient = NonNullable<ReturnType<typeof getRedisClient>>;

const lockKey = (app: string, type: string) => `fleet:lock:${app}:${type}`;
const startingKey = (app: string, type: string) => `fleet:starting:${app}:${type}`;
const spendKey = (type: string) => `fleet:spend:${type}:${Math.floor(Date.now() / 3_600_000)}`;
const spendAlertKey = (type: string) => `fleet:spendalert:${type}:${Math.floor(Date.now() / 3_600_000)}`;

// Lua compare-and-delete so a tick can't release another tick's lock after its
// own TTL expired (Upstash REST has no atomic CAS via separate get+del).
const RELEASE_LUA =
  "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
const EXTEND_LUA =
  "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end";

async function releaseLock(redis: RedisClient, key: string, token: string): Promise<void> {
  try {
    await redis.eval(RELEASE_LUA, [key], [token]);
  } catch {
    // TTL will expire the lock; safe to ignore.
  }
}

async function extendLock(redis: RedisClient, key: string, token: string, ttlSec: number): Promise<void> {
  try {
    await redis.eval(EXTEND_LUA, [key], [token, String(ttlSec)]);
  } catch {
    /* best-effort */
  }
}

async function getHourlySpend(redis: RedisClient, type: string): Promise<number> {
  try {
    const cents = await redis.get<number>(spendKey(type));
    return cents ? Number(cents) / 100 : 0;
  } catch {
    return 0;
  }
}

async function incrHourlySpend(redis: RedisClient, type: string, usd: number): Promise<number> {
  try {
    const total = await redis.incrby(spendKey(type), Math.round(usd * 100));
    await redis.expire(spendKey(type), 7200);
    return total / 100;
  } catch {
    return 0;
  }
}

/**
 * On the first tick of an hour that trips the spend cap, alert ops and write a
 * single user-facing log row per currently-queued run so the project card shows
 * "paused at spend cap" instead of a dead-looking spinner. Guarded by a
 * once-per-hour Redis flag so it doesn't spam every tick.
 */
async function notifySpendBlocked(redis: RedisClient, type: string): Promise<void> {
  try {
    const first = await redis.set(spendAlertKey(type), '1', { nx: true, ex: 7200 });
    if (first !== 'OK') return; // already alerted this hour
  } catch {
    return;
  }
  console.error(
    `[FLEET] HOURLY SPEND CAP reached for ${type} — pausing new machines until the hour rolls over. ` +
      `Raise FLY_MAX_SPEND_PER_HOUR_USD or investigate a runaway.`,
  );
  if (type !== 'extraction') return;
  try {
    const { data: queued } = await supabase
      .from('scan_jobs')
      .select('project_id, run_id')
      .eq('type', 'extraction')
      .eq('status', 'queued')
      .limit(200);
    if (queued?.length) {
      await supabase.from('extraction_logs').insert(
        queued.map((j: { project_id: string; run_id: string }) => ({
          project_id: j.project_id,
          run_id: j.run_id,
          step: 'cloning',
          level: 'info',
          message: 'Queued — fleet paused at the hourly spend cap. Your scan resumes automatically.',
        })),
      );
    }
  } catch {
    /* best-effort */
  }
}

/**
 * Run one dispatcher tick for a scan type (extraction today; type-generic so
 * dast/fix can adopt it later). Idempotent and single-flight.
 */
export async function dispatchFleet(type: string = 'extraction'): Promise<FleetTickResult> {
  const c = cfg();
  const app = DEPSCANNER_CONFIG.app;
  const redis = getRedisClient();
  const token = randomUUID();
  const result: FleetTickResult = {
    type,
    queued: 0,
    running: 0,
    starting: 0,
    flyActive: 0,
    inflight: 0,
    desired: 0,
    started: 0,
    capped: false,
    spendBlocked: false,
    lockHeld: false,
  };

  // 1. Single-flight lock — fail CLOSED when Redis is configured but failing.
  if (redis) {
    try {
      const acquired = await redis.set(lockKey(app, type), token, { nx: true, ex: c.lockTtlSec });
      if (acquired !== 'OK') return result; // another tick holds it — no-op (nudges collapse)
      result.lockHeld = true;
    } catch (e: any) {
      console.error(`[FLEET] lock acquire failed — skipping tick (fail-closed): ${e?.message ?? e}`);
      result.error = 'redis_error';
      return result;
    }
  } else if (c.allowLockless) {
    result.lockHeld = true; // explicit single-instance / CE mode
  } else {
    console.warn('[FLEET] Redis not configured and FLEET_ALLOW_LOCKLESS!=true — skipping tick');
    result.error = 'no_redis';
    return result;
  }

  try {
    // 2. One DB snapshot: running machine ids + per-org {queued, inflight}.
    const { data: snap, error: snapErr } = await supabase.rpc('fleet_scan_snapshot', { p_type: type });
    if (snapErr) {
      result.error = `snapshot_failed: ${snapErr.message}`;
      console.error(`[FLEET] ${result.error}`);
      return result;
    }
    const runningIds: string[] = (snap?.running_machine_ids as string[] | null) ?? [];
    const perOrg: PerOrgRow[] = ((snap?.per_org as PerOrgRow[] | null) ?? []).map((o) => ({
      organization_id: o.organization_id,
      queued: Number(o.queued),
      inflight: Number(o.inflight),
    }));

    // 3. Starting set (machines created but not yet claimed): prune + read.
    let startingIds: string[] = [];
    if (redis) {
      try {
        await redis.zremrangebyscore(startingKey(app, type), 0, Date.now() - c.startingTtlSec * 1000);
        startingIds = await redis.zrange<string[]>(startingKey(app, type), 0, -1);
      } catch {
        /* degrade to running+fly only */
      }
    }

    // 4. Fly machine list — authoritative ceiling + stopped pool for reuse.
    let flyMachines: FlyMachine[] = [];
    try {
      flyMachines = await listMachines(app);
    } catch (e: any) {
      console.warn(`[FLEET] listMachines failed; inflight from DB+Redis only: ${e?.message ?? e}`);
    }
    const flyActiveIds = flyMachines
      .filter((m) => ACTIVE_MACHINE_STATES.includes(m.state) && machineMatchesScanType(m, type))
      .map((m) => m.id);

    // 5. Inflight = union of the three machine-id sets (deduped).
    const inflightSet = new Set<string>([...runningIds, ...startingIds, ...flyActiveIds]);
    const inflight = inflightSet.size;

    // 6. Claimable-aware desired — never provision for jobs the per-org cap
    //    blocks (else machines boot, claim nothing, idle-exit, churn).
    const queuedTotal = perOrg.reduce((s, o) => s + o.queued, 0);
    const claimable = perOrg.reduce(
      (s, o) => s + Math.min(o.queued, Math.max(0, c.maxPerOrg - o.inflight)),
      0,
    );
    const desired = Math.min(c.maxFleet, claimable);

    result.queued = queuedTotal;
    result.running = runningIds.length;
    result.starting = startingIds.length;
    result.flyActive = flyActiveIds.length;
    result.inflight = inflight;
    result.desired = desired;
    result.capped = desired >= c.maxFleet && claimable > c.maxFleet;

    // 7. Spend guard (read).
    let remainingByBudget = Number.POSITIVE_INFINITY;
    if (c.spendCapUsd != null && redis) {
      const spent = await getHourlySpend(redis, type);
      if (spent >= c.spendCapUsd) {
        result.spendBlocked = true;
        await notifySpendBlocked(redis, type);
      } else {
        remainingByBudget = Math.floor((c.spendCapUsd - spent) / Math.max(c.estPerMachineUsd, 0.001));
      }
    }

    // 8. startN — clamped by fleet headroom, per-tick batch, and spend budget.
    let startN = result.spendBlocked
      ? 0
      : Math.max(
          0,
          Math.min(desired - inflight, c.maxFleet - inflight, c.batchPerTick, remainingByBudget),
        );

    // 9. Provision: reuse stopped machines first, then burst.
    const stoppedPool = flyMachines
      .filter((m) => m.state === 'stopped' && machineMatchesScanType(m, type))
      .map((m) => m.id);

    // Resolve the burst image ONCE per tick from this tick's machine list. It
    // tracks the live deployment (the persistent machine carries the current
    // release after each `flyctl deploy`) so there's no manual re-pin, and it
    // avoids a per-burst API call. If it can't resolve (no pin + no machine
    // carrying an image), still reuse stopped machines but never gamble on
    // `:latest` for a fresh burst.
    let burstImage: string | undefined;
    try {
      burstImage = await resolveDepscannerImage(flyMachines);
    } catch (e: any) {
      console.warn(`[FLEET] burst image unresolved — reusing stopped only this tick: ${e?.message ?? e}`);
    }

    for (let i = 0; i < startN; i++) {
      let id: string | null = null;
      try {
        const reuseId = stoppedPool.pop();
        if (reuseId) {
          await startMachine(app, reuseId);
          id = reuseId;
        } else if (burstImage) {
          id = await createDepscannerBurst(burstImage);
        } else {
          console.warn('[FLEET] no stopped machine to reuse and no resolvable image — stopping tick');
          break;
        }
      } catch (e: any) {
        if (e instanceof FlyRateLimitError) {
          console.warn('[FLEET] Fly 429 — stopping tick early; cron/nudge will resume');
          break;
        }
        console.error(`[FLEET] machine provision failed (job stays queued): ${e?.message ?? e}`);
        continue;
      }
      if (!id) continue;
      result.started++;

      if (redis) {
        try {
          await redis.zadd(startingKey(app, type), { score: Date.now(), member: id });
        } catch {
          /* the Fly-list ceiling still counts this machine next tick */
        }
      }

      // In-loop spend accounting so a single tick can't blow past the cap.
      if (c.spendCapUsd != null && redis) {
        const total = await incrHourlySpend(redis, type, c.estPerMachineUsd);
        if (total >= c.spendCapUsd) {
          result.spendBlocked = true;
          await notifySpendBlocked(redis, type);
          break;
        }
      }

      // Re-extend the lock so a long provision burst can't outlive its TTL.
      if (redis && result.lockHeld && result.started % 4 === 0) {
        await extendLock(redis, lockKey(app, type), token, c.lockTtlSec);
      }
    }

    return result;
  } catch (e: any) {
    result.error = e?.message ?? String(e);
    console.error(`[FLEET] tick failed: ${result.error}`);
    return result;
  } finally {
    if (redis && result.lockHeld) {
      await releaseLock(redis, lockKey(app, type), token);
    }
  }
}

/**
 * Fire-and-forget, in-process nudge — runs a dispatcher tick off the request
 * hot path. Used by queueExtractionJob after the scan_jobs row commits, so
 * creating a project never blocks on the Fly API. Multiple nudges collapse via
 * the single-flight lock.
 */
export function nudgeDispatcher(type: string = 'extraction'): void {
  setImmediate(() => {
    dispatchFleet(type).catch((e) => console.warn(`[FLEET] nudge failed: ${e?.message ?? e}`));
  });
}

/**
 * Stop machines that are running on Fly but doing no work — closes the
 * hung-worker cost leak. A machine is reaped only if it is `started`, of this
 * scan kind, NOT in the running set, NOT in the starting set, has no scan_jobs
 * row heartbeating within the stale threshold, and is older than the boot grace
 * (so a legitimately-booting machine is never killed). Runs under the fleet
 * lock so its snapshot is consistent with provisioning.
 */
export async function reapZombieMachines(type: string = 'extraction'): Promise<{ stopped: number; error?: string }> {
  const c = cfg();
  const app = DEPSCANNER_CONFIG.app;
  const redis = getRedisClient();
  const token = randomUUID();
  const reapLock = `fleet:reaplock:${app}:${type}`;
  const graceMs = (c.startingTtlSec + 60) * 1000;
  const staleHeartbeatMs = 5 * 60 * 1000;

  if (redis) {
    try {
      const acquired = await redis.set(reapLock, token, { nx: true, ex: 60 });
      if (acquired !== 'OK') return { stopped: 0 };
    } catch (e: any) {
      return { stopped: 0, error: 'redis_error' };
    }
  } else if (!c.allowLockless) {
    return { stopped: 0, error: 'no_redis' };
  }

  const { stopFlyMachine } = await import('./fly-machines');
  let stopped = 0;
  try {
    const flyMachines = await listMachines(app);
    const candidates = flyMachines.filter(
      (m) => m.state === 'started' && machineMatchesScanType(m, type),
    );
    if (candidates.length === 0) return { stopped: 0 };

    // running machine ids (processing) + recently-heartbeating machine ids.
    const { data: snap } = await supabase.rpc('fleet_scan_snapshot', { p_type: type });
    const runningIds = new Set<string>((snap?.running_machine_ids as string[] | null) ?? []);

    const { data: hb } = await supabase
      .from('scan_jobs')
      .select('machine_id')
      .gte('heartbeat_at', new Date(Date.now() - staleHeartbeatMs).toISOString())
      .not('machine_id', 'is', null);
    const heartbeatingIds = new Set<string>((hb ?? []).map((r: { machine_id: string }) => r.machine_id));

    let startingIds = new Set<string>();
    if (redis) {
      try {
        startingIds = new Set(await redis.zrange<string[]>(startingKey(app, type), 0, -1));
      } catch {
        /* ignore */
      }
    }

    for (const m of candidates) {
      const ageMs = m.created_at ? Date.now() - new Date(m.created_at).getTime() : Number.POSITIVE_INFINITY;
      if (ageMs < graceMs) continue; // still legitimately booting
      if (runningIds.has(m.id) || startingIds.has(m.id) || heartbeatingIds.has(m.id)) continue;
      try {
        await stopFlyMachine(app, m.id);
        stopped++;
        console.log(`[FLEET] reaped zombie machine ${m.id} (started, no job, no heartbeat)`);
      } catch (e: any) {
        console.warn(`[FLEET] failed to stop zombie ${m.id}: ${e?.message ?? e}`);
      }
    }
    return { stopped };
  } catch (e: any) {
    return { stopped, error: e?.message ?? String(e) };
  } finally {
    if (redis) await releaseLock(redis, reapLock, token);
  }
}

/** Live fleet metrics for the admin panel. */
export async function getFleetMetrics(type: string = 'extraction'): Promise<{
  type: string;
  queued: number;
  running: number;
  starting: number;
  flyActive: number;
  inflight: number;
  maxFleet: number;
  spendThisHourUsd: number;
  spendCapUsd: number | null;
  spendBlocked: boolean;
  p50QueueSeconds: number | null;
  p95QueueSeconds: number | null;
  throughputPerHour: number;
}> {
  const c = cfg();
  const app = DEPSCANNER_CONFIG.app;
  const redis = getRedisClient();

  const { data: snap } = await supabase.rpc('fleet_scan_snapshot', { p_type: type });
  const runningIds: string[] = (snap?.running_machine_ids as string[] | null) ?? [];
  const perOrg: PerOrgRow[] = ((snap?.per_org as PerOrgRow[] | null) ?? []).map((o) => ({
    organization_id: o.organization_id,
    queued: Number(o.queued),
    inflight: Number(o.inflight),
  }));
  const queued = perOrg.reduce((s, o) => s + o.queued, 0);

  let startingIds: string[] = [];
  let flyActiveIds: string[] = [];
  if (redis) {
    try {
      startingIds = await redis.zrange<string[]>(startingKey(app, type), 0, -1);
    } catch {
      /* ignore */
    }
  }
  try {
    const flyMachines = await listMachines(app);
    flyActiveIds = flyMachines
      .filter((m) => ACTIVE_MACHINE_STATES.includes(m.state) && machineMatchesScanType(m, type))
      .map((m) => m.id);
  } catch {
    /* ignore */
  }
  const inflight = new Set<string>([...runningIds, ...startingIds, ...flyActiveIds]).size;

  // queue-wait percentiles + throughput from the last hour of jobs.
  const sinceIso = new Date(Date.now() - 3_600_000).toISOString();
  const { data: recent } = await supabase
    .from('scan_jobs')
    .select('created_at, started_at, completed_at, status')
    .eq('type', type)
    .gte('created_at', sinceIso);
  const waits = (recent ?? [])
    .filter((j: any) => j.started_at)
    .map((j: any) => (new Date(j.started_at).getTime() - new Date(j.created_at).getTime()) / 1000)
    .filter((s: number) => s >= 0)
    .sort((a: number, b: number) => a - b);
  const pct = (p: number): number | null => {
    if (waits.length === 0) return null;
    const idx = Math.min(waits.length - 1, Math.floor((p / 100) * waits.length));
    return Math.round(waits[idx]);
  };
  const throughputPerHour = (recent ?? []).filter((j: any) => j.status === 'completed').length;

  const spendThisHourUsd = redis ? await getHourlySpend(redis, type) : 0;

  return {
    type,
    queued,
    running: runningIds.length,
    starting: startingIds.length,
    flyActive: flyActiveIds.length,
    inflight,
    maxFleet: c.maxFleet,
    spendThisHourUsd,
    spendCapUsd: c.spendCapUsd,
    spendBlocked: c.spendCapUsd != null && spendThisHourUsd >= c.spendCapUsd,
    p50QueueSeconds: pct(50),
    p95QueueSeconds: pct(95),
    throughputPerHour,
  };
}
