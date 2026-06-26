/**
 * Fleet dispatcher unit tests — the load-bearing guarantees:
 *  - hard MAX_FLEET cap holds under CONCURRENT ticks (single-flight lock)
 *  - fail-CLOSED when Redis is configured but throwing
 *  - claimable-aware desired never over-provisions past the per-org cap
 *  - inflight dedups running ∪ starting ∪ fly-active
 *
 * Fly machine creation is faked (counts invocations); Redis is an in-process
 * fake whose SET NX actually blocks a second concurrent tick. All variables
 * referenced inside jest.mock() factories are `mock`-prefixed per jest's hoist
 * rule.
 */

class FakeRedis {
  kv = new Map<string, string>();
  zsets = new Map<string, Map<string, number>>();
  throwOnSet = false;

  async set(key: string, val: string, opts?: { nx?: boolean; xx?: boolean; ex?: number }) {
    if (this.throwOnSet) throw new Error('redis down');
    const exists = this.kv.has(key);
    if (opts?.nx && exists) return null;
    if (opts?.xx && !exists) return null;
    this.kv.set(key, val);
    return 'OK';
  }
  async get(key: string) {
    return this.kv.has(key) ? this.kv.get(key)! : null;
  }
  async eval(script: string, keys: string[], args: string[]) {
    const cur = this.kv.get(keys[0]);
    if (cur === args[0]) {
      if (script.includes('del')) this.kv.delete(keys[0]);
      return 1;
    }
    return 0;
  }
  async zadd(key: string, m: { score: number; member: string }) {
    if (!this.zsets.has(key)) this.zsets.set(key, new Map());
    this.zsets.get(key)!.set(m.member, m.score);
    return 1;
  }
  async zrange(key: string) {
    return Array.from(this.zsets.get(key)?.keys() ?? []);
  }
  async zremrangebyscore(key: string, min: number, max: number) {
    const z = this.zsets.get(key);
    if (!z) return 0;
    let n = 0;
    for (const [member, score] of z) {
      if (score >= min && score <= max) {
        z.delete(member);
        n++;
      }
    }
    return n;
  }
  async incrby(key: string, by: number) {
    const cur = Number(this.kv.get(key) ?? '0') + by;
    this.kv.set(key, String(cur));
    return cur;
  }
  async expire() {
    return 1;
  }
}

import { setRpcResponse, clearRpcRegistry } from '../../test/mocks/supabaseSingleton';

let mockFakeRedis: FakeRedis | null = new FakeRedis();
let mockBurstCount = 0;
let mockListMachinesReturn: any[] = [];
let mockThrowRateLimit = false;

jest.mock('../cache', () => ({
  getRedisClient: () => mockFakeRedis,
}));

jest.mock('../supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
}));

jest.mock('../fly-machines', () => {
  class MockFlyRateLimitError extends Error {}
  return {
    DEPSCANNER_CONFIG: { app: 'deptex-depscanner', scanType: 'extraction' },
    ACTIVE_MACHINE_STATES: ['created', 'starting', 'started', 'replacing'],
    FlyRateLimitError: MockFlyRateLimitError,
    machineMatchesScanType: () => true,
    listMachines: async () => mockListMachinesReturn,
    startMachine: async () => undefined,
    resolveDepscannerImage: async () => 'registry.fly.io/deptex-depscanner@sha256:test',
    createDepscannerBurst: async () => {
      if (mockThrowRateLimit) throw new MockFlyRateLimitError('429');
      const id = `burst-${mockBurstCount}`;
      mockBurstCount++;
      return id;
    },
  };
});

import { dispatchFleet } from '../fleet-dispatcher';

function snapshot(
  perOrg: Array<{ organization_id: string; queued: number; inflight: number }>,
  runningIds: string[] = [],
) {
  return { data: { running_machine_ids: runningIds, per_org: perOrg }, error: null };
}

beforeEach(() => {
  jest.clearAllMocks();
  clearRpcRegistry();
  mockFakeRedis = new FakeRedis();
  mockBurstCount = 0;
  mockListMachinesReturn = [];
  mockThrowRateLimit = false;
  process.env.FLY_MAX_FLEET = '25';
  process.env.FLY_MAX_PER_ORG = '5';
  process.env.FLEET_BATCH_PER_TICK = '100';
  process.env.FLEET_STARTING_TTL_SEC = '180';
  process.env.FLEET_LOCK_TTL_SEC = '120';
  delete process.env.FLEET_ALLOW_LOCKLESS;
  delete process.env.FLY_MAX_SPEND_PER_HOUR_USD;
});

describe('hard MAX_FLEET cap', () => {
  it('never creates more than MAX_FLEET machines for a big backlog (single tick)', async () => {
    process.env.FLY_MAX_FLEET = '5';
    process.env.FLY_MAX_PER_ORG = '100';
    setRpcResponse('fleet_scan_snapshot', snapshot([{ organization_id: 'o1', queued: 50, inflight: 0 }]));

    const r = await dispatchFleet('extraction');

    expect(r.started).toBe(5);
    expect(mockBurstCount).toBe(5);
    expect(r.inflight).toBe(0);
  });

  it('holds the cap under TWO concurrent ticks (single-flight lock serializes)', async () => {
    process.env.FLY_MAX_FLEET = '5';
    process.env.FLY_MAX_PER_ORG = '100';
    setRpcResponse('fleet_scan_snapshot', snapshot([{ organization_id: 'o1', queued: 50, inflight: 0 }]));

    const [a, b] = await Promise.all([dispatchFleet('extraction'), dispatchFleet('extraction')]);

    expect(mockBurstCount).toBeLessThanOrEqual(5);
    const workers = [a, b].filter((r) => r.lockHeld);
    const noops = [a, b].filter((r) => !r.lockHeld);
    expect(workers.length).toBe(1);
    expect(noops.length).toBe(1);
    expect(workers[0].started).toBe(5);
  });
});

describe('fail-closed on Redis error', () => {
  it('provisions nothing when a configured Redis throws on lock acquire', async () => {
    mockFakeRedis!.throwOnSet = true;
    setRpcResponse('fleet_scan_snapshot', snapshot([{ organization_id: 'o1', queued: 50, inflight: 0 }]));

    const r = await dispatchFleet('extraction');

    expect(r.lockHeld).toBe(false);
    expect(r.error).toBe('redis_error');
    expect(mockBurstCount).toBe(0);
  });

  it('skips the tick (no lock-free fallback) when Redis is unconfigured and lockless not allowed', async () => {
    mockFakeRedis = null;
    setRpcResponse('fleet_scan_snapshot', snapshot([{ organization_id: 'o1', queued: 50, inflight: 0 }]));

    const r = await dispatchFleet('extraction');

    expect(r.error).toBe('no_redis');
    expect(mockBurstCount).toBe(0);
  });

  it('runs lock-free only when FLEET_ALLOW_LOCKLESS=true and Redis unconfigured', async () => {
    mockFakeRedis = null;
    process.env.FLEET_ALLOW_LOCKLESS = 'true';
    process.env.FLY_MAX_FLEET = '3';
    process.env.FLY_MAX_PER_ORG = '100';
    setRpcResponse('fleet_scan_snapshot', snapshot([{ organization_id: 'o1', queued: 10, inflight: 0 }]));

    const r = await dispatchFleet('extraction');

    expect(r.lockHeld).toBe(true);
    expect(r.started).toBe(3);
  });
});

describe('claimable-aware desired (per-org cap)', () => {
  it('does not provision for jobs blocked by the per-org cap', async () => {
    process.env.FLY_MAX_FLEET = '25';
    process.env.FLY_MAX_PER_ORG = '5';
    setRpcResponse('fleet_scan_snapshot',
      snapshot([{ organization_id: 'o1', queued: 20, inflight: 5 }], ['m1', 'm2', 'm3', 'm4', 'm5']),
    );

    const r = await dispatchFleet('extraction');

    // The 20 queued jobs are all blocked by the per-org cap (5 inflight = cap),
    // so claimable = 0. desired = busyMachines(5) + claimable(0) = 5, which the
    // 5 already-running machines fully cover → start nothing. The guarantee is
    // that nothing is provisioned for cap-blocked jobs.
    expect(r.desired).toBe(5);
    expect(r.started).toBe(0);
    expect(mockBurstCount).toBe(0);
  });

  it('boots a fresh machine for a queued job when the only machine is busy', async () => {
    process.env.FLY_MAX_FLEET = '25';
    process.env.FLY_MAX_PER_ORG = '5';
    // One machine busy on a (possibly slow/hung) job for o1; one more job queued
    // for the same org. A busy machine can't claim the queued job until it
    // finishes, so the dispatcher must boot a second machine rather than let the
    // queue wait behind it (the ~9-min stall observed when the only machine was
    // stuck on a hanging extraction).
    mockListMachinesReturn = [{ id: 'm1', state: 'started' }];
    setRpcResponse('fleet_scan_snapshot',
      snapshot([{ organization_id: 'o1', queued: 1, inflight: 1 }], ['m1']),
    );

    const r = await dispatchFleet('extraction');

    expect(r.running).toBe(1);
    expect(r.inflight).toBe(1); // m1 only (running ∪ flyActive dedup)
    expect(r.desired).toBe(2); // keep m1 on its job + 1 for the queued job
    expect(r.started).toBe(1);
    expect(mockBurstCount).toBe(1);
  });

  it('caps new machines to remaining per-org headroom across orgs', async () => {
    process.env.FLY_MAX_FLEET = '25';
    process.env.FLY_MAX_PER_ORG = '5';
    // o1: 20 queued, 3 inflight → 2 claimable. o2: 10 queued, 0 inflight → 5 claimable.
    setRpcResponse('fleet_scan_snapshot',
      snapshot(
        [
          { organization_id: 'o1', queued: 20, inflight: 3 },
          { organization_id: 'o2', queued: 10, inflight: 0 },
        ],
        ['r1', 'r2', 'r3'],
      ),
    );

    const r = await dispatchFleet('extraction');

    // claimable = 2 + 5 = 7; the 3 running machines are busy, so desired =
    // busy(3) + claimable(7) = 10; inflight = 3 → startN = 10 - 3 = 7. Each
    // claimable queued job gets its own machine instead of serializing behind a
    // busy one (still bounded by FLY_MAX_FLEET and the per-org cap).
    expect(r.desired).toBe(10);
    expect(r.started).toBe(7);
  });
});

describe('inflight dedup + Fly ceiling', () => {
  it('counts a machine present in BOTH running and starting only once', async () => {
    process.env.FLY_MAX_FLEET = '10';
    process.env.FLY_MAX_PER_ORG = '100';
    await mockFakeRedis!.zadd('fleet:starting:deptex-depscanner:extraction', { score: Date.now(), member: 'm1' });
    await mockFakeRedis!.zadd('fleet:starting:deptex-depscanner:extraction', { score: Date.now(), member: 'm2' });
    setRpcResponse('fleet_scan_snapshot', snapshot([{ organization_id: 'o1', queued: 10, inflight: 1 }], ['m1']));

    const r = await dispatchFleet('extraction');

    // union {m1} ∪ {m1, m2} = {m1, m2} → inflight 2 (not 3).
    expect(r.inflight).toBe(2);
    expect(r.desired).toBe(10);
    expect(r.started).toBe(8);
  });

  it('uses listMachines as a ceiling so it never exceeds real machine count', async () => {
    process.env.FLY_MAX_FLEET = '10';
    process.env.FLY_MAX_PER_ORG = '100';
    mockListMachinesReturn = Array.from({ length: 8 }, (_, i) => ({ id: `fly-${i}`, state: 'started' }));
    setRpcResponse('fleet_scan_snapshot', snapshot([{ organization_id: 'o1', queued: 10, inflight: 0 }]));

    const r = await dispatchFleet('extraction');

    expect(r.flyActive).toBe(8);
    expect(r.inflight).toBe(8);
    expect(r.started).toBe(2);
  });
});

describe('429 handling', () => {
  it('stops the tick early on a Fly rate-limit error', async () => {
    process.env.FLY_MAX_FLEET = '10';
    process.env.FLY_MAX_PER_ORG = '100';
    mockThrowRateLimit = true;
    setRpcResponse('fleet_scan_snapshot', snapshot([{ organization_id: 'o1', queued: 10, inflight: 0 }]));

    const r = await dispatchFleet('extraction');

    expect(r.started).toBe(0);
  });
});
