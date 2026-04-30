import {
  checkPlatformAiBudget,
  recordActualPlatformCost,
  PLATFORM_AI_LIMITS,
} from '../ai/platform-cost-cap';

const mockIncr = jest.fn<Promise<number>, [string]>();
const mockDecr = jest.fn<Promise<number>, [string]>();
const mockIncrby = jest.fn<Promise<number>, [string, number]>();
const mockDecrby = jest.fn<Promise<number>, [string, number]>();
const mockExpire = jest.fn().mockResolvedValue(1);

jest.mock('@upstash/redis', () => ({
  Redis: jest.fn().mockImplementation(() => ({
    incr: (k: string) => mockIncr(k),
    decr: (k: string) => mockDecr(k),
    incrby: (k: string, v: number) => mockIncrby(k, v),
    decrby: (k: string, v: number) => mockDecrby(k, v),
    expire: mockExpire,
  })),
}));

beforeEach(() => {
  jest.resetModules();
  jest.clearAllMocks();
  process.env.UPSTASH_REDIS_URL = 'https://example.upstash.io';
  process.env.UPSTASH_REDIS_TOKEN = 'token';
});

describe('checkPlatformAiBudget', () => {
  it('allows the call when both daily count and monthly cost are under their caps', async () => {
    mockIncr.mockResolvedValueOnce(1);
    mockIncrby.mockResolvedValueOnce(3);

    const result = await checkPlatformAiBudget('malicious_explainer', 0.0003);

    expect(result.allowed).toBe(true);
    expect(mockIncr).toHaveBeenCalledTimes(1);
    expect(mockIncrby).toHaveBeenCalledTimes(1);
  });

  it('rejects + rolls back the daily counter when the daily call cap is exceeded', async () => {
    const cap = PLATFORM_AI_LIMITS.malicious_explainer.daily_calls;
    mockIncr.mockResolvedValueOnce(cap + 1);
    mockDecr.mockResolvedValueOnce(cap);

    const result = await checkPlatformAiBudget('malicious_explainer', 0.0003);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Daily');
    expect(mockDecr).toHaveBeenCalledTimes(1);
    expect(mockIncrby).not.toHaveBeenCalled();
  });

  it('rejects + rolls back BOTH counters when the monthly cost cap is exceeded', async () => {
    const monthlyCapCents = PLATFORM_AI_LIMITS.malicious_explainer.monthly_cost_usd * 100;
    mockIncr.mockResolvedValueOnce(1);
    mockIncrby.mockResolvedValueOnce(monthlyCapCents + 1);
    mockDecrby.mockResolvedValueOnce(monthlyCapCents - 1);
    mockDecr.mockResolvedValueOnce(0);

    const result = await checkPlatformAiBudget('malicious_explainer', 0.0003);

    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/Monthly platform AI budget reached/);
    expect(mockDecrby).toHaveBeenCalledTimes(1);
    expect(mockDecr).toHaveBeenCalledTimes(1);
  });

  it('sets a TTL the first time the daily counter is created', async () => {
    mockIncr.mockResolvedValueOnce(1);
    // 0.0003 USD -> max(1, ceil(0.03)) = 1 cent; first-time write returns 1
    mockIncrby.mockResolvedValueOnce(1);

    await checkPlatformAiBudget('malicious_explainer', 0.0003);

    expect(mockExpire).toHaveBeenCalledWith(expect.stringMatching(/^ai:platform:feature:malicious_explainer:/), 2 * 24 * 60 * 60);
    expect(mockExpire).toHaveBeenCalledWith(expect.stringMatching(/^ai:platform:cost:/), 35 * 24 * 60 * 60);
  });

  it('does NOT re-set the TTL on subsequent increments', async () => {
    mockIncr.mockResolvedValueOnce(2);
    mockIncrby.mockResolvedValueOnce(20);

    await checkPlatformAiBudget('malicious_explainer', 0.0003);

    expect(mockExpire).not.toHaveBeenCalled();
  });

  it('fails open (allowed=true) when Redis is unreachable', async () => {
    delete process.env.UPSTASH_REDIS_URL;
    delete process.env.UPSTASH_REDIS_TOKEN;
    jest.isolateModules(() => {
      // re-require so the cached client is null
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { checkPlatformAiBudget: fresh } = require('../ai/platform-cost-cap');
      return fresh('malicious_explainer', 0.0003).then((r: any) => {
        expect(r.allowed).toBe(true);
      });
    });
  });

  it('fails open when Redis throws', async () => {
    mockIncr.mockRejectedValueOnce(new Error('redis dropped'));

    const result = await checkPlatformAiBudget('malicious_explainer', 0.0003);

    expect(result.allowed).toBe(true);
  });

  it('rejects an unknown feature without touching Redis', async () => {
    const result = await checkPlatformAiBudget('not_a_feature' as any, 0.0003);
    expect(result.allowed).toBe(false);
    expect(mockIncr).not.toHaveBeenCalled();
  });
});

describe('recordActualPlatformCost', () => {
  it('increments the monthly counter when actual > estimate', async () => {
    mockIncrby.mockResolvedValueOnce(50);

    await recordActualPlatformCost(0.0003, 0.0010);

    expect(mockIncrby).toHaveBeenCalledTimes(1);
    expect(mockIncrby).toHaveBeenCalledWith(expect.stringMatching(/^ai:platform:cost:/), expect.any(Number));
  });

  it('is a no-op when actual <= estimate', async () => {
    await recordActualPlatformCost(0.0010, 0.0005);

    expect(mockIncrby).not.toHaveBeenCalled();
  });
});
