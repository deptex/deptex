/**
 * Phase 33: per-scan AI telemetry rollup + per-scan cost-cap enforcement.
 *
 * The tests use a hand-rolled FakeStorage that captures every rpc() /
 * from().select().eq().maybeSingle() call so we can assert:
 *  - recordScanJobAiUsage calls add_scan_job_ai_usage with the right args
 *  - capExceeded flag tracks the cap stored on the scan_jobs row
 *  - checkScanJobCostCap reads the live total + cap and computes wouldExceed
 *  - jobId=undefined is a no-op (CLI mode)
 *  - per-scan cap interaction with monthly cap (per-scan tighter wins)
 *
 * No real Supabase / PGLite — we drive the helpers directly with the
 * Storage interface contract.
 */

import {
  recordScanJobAiUsage,
  checkScanJobCostCap,
} from '../ai-telemetry';
import type { Storage } from '../storage';

interface ScanJobRow {
  id: string;
  ai_total_cost_usd: number;
  ai_cost_cap_usd: number | null;
}

class FakeStorage {
  rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
  /** Stub return values for `rpc()`, indexed in call order. */
  rpcReturns: Array<{ data: unknown; error: unknown }> = [];
  scanJobs = new Map<string, ScanJobRow>();

  from(table: string): any {
    const filters: Array<{ col: string; val: unknown }> = [];
    const get = () => {
      let rows = table === 'scan_jobs' ? Array.from(this.scanJobs.values()) : [];
      for (const f of filters) {
        rows = rows.filter((r) => (r as any)[f.col] === f.val);
      }
      return rows;
    };
    const builder: any = {
      select() { return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      maybeSingle: () => Promise.resolve({ data: get()[0] ?? null, error: null }),
    };
    return builder;
  }

  rpc(name: string, args: Record<string, unknown>): Promise<{ data: unknown; error: unknown }> {
    this.rpcCalls.push({ name, args });
    const ret = this.rpcReturns.shift() ?? { data: null, error: null };
    return Promise.resolve(ret);
  }
}

const storage = () => new FakeStorage() as unknown as Storage & FakeStorage;

describe('recordScanJobAiUsage', () => {
  it('is a no-op when jobId is undefined (CLI mode)', async () => {
    const s = storage();
    const result = await recordScanJobAiUsage(s, {
      jobId: undefined,
      organizationId: 'org-1',
      provider: 'anthropic',
      model: 'claude-sonnet-4-6',
      promptTokens: 100,
      completionTokens: 200,
      costUsd: 0.05,
    });
    expect(result).toEqual({ capExceeded: false, newTotalUsd: 0 });
    expect(s.rpcCalls).toHaveLength(0);
  });

  it('calls add_scan_job_ai_usage with floored / non-negative token counts', async () => {
    const s = storage();
    s.scanJobs.set('job-1', { id: 'job-1', ai_total_cost_usd: 0.5, ai_cost_cap_usd: null });
    s.rpcReturns.push({ data: 0.55, error: null });

    await recordScanJobAiUsage(s, {
      jobId: 'job-1',
      organizationId: 'org-1',
      provider: 'openai',
      model: 'gpt-4o-mini',
      promptTokens: 123.7, // should floor to 123
      completionTokens: -5, // should clamp to 0
      costUsd: 0.05,
    });

    expect(s.rpcCalls[0]).toEqual({
      name: 'add_scan_job_ai_usage',
      args: {
        p_job_id: 'job-1',
        p_organization_id: 'org-1',
        p_provider: 'openai',
        p_model: 'gpt-4o-mini',
        p_prompt_tokens: 123,
        p_completion_tokens: 0,
        p_cost_usd: 0.05,
      },
    });
  });

  it('returns capExceeded=true when the new running total exceeds the cap', async () => {
    const s = storage();
    s.scanJobs.set('job-1', { id: 'job-1', ai_total_cost_usd: 0.5, ai_cost_cap_usd: 0.6 });
    // After-rollup total is 0.7 > cap 0.6 → exceeded
    s.rpcReturns.push({ data: 0.7, error: null });

    const result = await recordScanJobAiUsage(s, {
      jobId: 'job-1',
      organizationId: 'org-1',
      provider: 'anthropic',
      model: 'claude-sonnet-4-6',
      promptTokens: 100,
      completionTokens: 200,
      costUsd: 0.2,
    });

    expect(result.capExceeded).toBe(true);
    expect(result.newTotalUsd).toBe(0.7);
  });

  it('returns capExceeded=false when cap is NULL (no per-scan cap)', async () => {
    const s = storage();
    s.scanJobs.set('job-1', { id: 'job-1', ai_total_cost_usd: 9.99, ai_cost_cap_usd: null });
    s.rpcReturns.push({ data: 19.99, error: null });

    const result = await recordScanJobAiUsage(s, {
      jobId: 'job-1',
      organizationId: 'org-1',
      provider: 'anthropic',
      model: 'claude-opus-4-7',
      promptTokens: 1000,
      completionTokens: 5000,
      costUsd: 10,
    });

    expect(result.capExceeded).toBe(false);
    expect(result.newTotalUsd).toBe(19.99);
  });

  it('swallows RPC errors and returns capExceeded=false (non-fatal telemetry)', async () => {
    const s = storage();
    s.rpcReturns.push({ data: null, error: { message: 'connection refused' } });

    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const result = await recordScanJobAiUsage(s, {
      jobId: 'job-1',
      organizationId: 'org-1',
      provider: 'openai',
      model: 'gpt-4o-mini',
      promptTokens: 100,
      completionTokens: 200,
      costUsd: 0.05,
    });
    expect(result.capExceeded).toBe(false);
    expect(Number.isNaN(result.newTotalUsd)).toBe(true);
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});

describe('checkScanJobCostCap', () => {
  it('returns wouldExceed=false when the row has no cap', async () => {
    const s = storage();
    s.scanJobs.set('job-1', { id: 'job-1', ai_total_cost_usd: 0.5, ai_cost_cap_usd: null });
    const result = await checkScanJobCostCap(s, 'job-1', 0.1);
    expect(result).toEqual({ wouldExceed: false, cap: null, currentTotal: 0.5 });
  });

  it('returns wouldExceed=true when projected cost pushes over the cap', async () => {
    const s = storage();
    s.scanJobs.set('job-1', { id: 'job-1', ai_total_cost_usd: 0.55, ai_cost_cap_usd: 0.6 });
    const result = await checkScanJobCostCap(s, 'job-1', 0.1);
    // 0.55 + 0.1 = 0.65 > 0.6
    expect(result.wouldExceed).toBe(true);
    expect(result.cap).toBe(0.6);
    expect(result.currentTotal).toBe(0.55);
  });

  it('returns wouldExceed=false when projected cost stays within the cap', async () => {
    const s = storage();
    s.scanJobs.set('job-1', { id: 'job-1', ai_total_cost_usd: 0.30, ai_cost_cap_usd: 0.50 });
    const result = await checkScanJobCostCap(s, 'job-1', 0.10);
    // 0.30 + 0.10 = 0.40 ≤ 0.50
    expect(result.wouldExceed).toBe(false);
  });

  it('is a no-op when jobId is undefined', async () => {
    const s = storage();
    const result = await checkScanJobCostCap(s, undefined, 100);
    expect(result).toEqual({ wouldExceed: false, cap: null, currentTotal: 0 });
  });
});

describe('per-scan cap > monthly cap interaction', () => {
  // The per-scan cap is checked BEFORE the monthly cap in each pipeline
  // step (rule-gen, fp-filter, EPD-anthropic-fallback). When per-scan is
  // tighter than the monthly-remaining bucket, per-scan wins outright —
  // the helper module enforces that on its own.
  it('a tight per-scan cap trips first even when monthly cap has plenty of headroom', async () => {
    const s = storage();
    s.scanJobs.set('job-1', { id: 'job-1', ai_total_cost_usd: 0.45, ai_cost_cap_usd: 0.50 });
    // Imagine monthly cap is $100 and only $1 spent this month — checks
    // sit on completely different storage (Redis + ai_usage_logs SUM).
    // The per-scan helper doesn't know or care; the call simply trips
    // here.
    const result = await checkScanJobCostCap(s, 'job-1', 0.10);
    expect(result.wouldExceed).toBe(true);
  });

  it('a loose per-scan cap defers to whatever the monthly path decides', async () => {
    const s = storage();
    s.scanJobs.set('job-1', { id: 'job-1', ai_total_cost_usd: 0.45, ai_cost_cap_usd: 100 });
    const result = await checkScanJobCostCap(s, 'job-1', 0.10);
    // Per-scan: 0.55 / 100 → not exceeded. Monthly path runs separately
    // and stays the authoritative cap when per-scan is loose / unset.
    expect(result.wouldExceed).toBe(false);
  });
});
