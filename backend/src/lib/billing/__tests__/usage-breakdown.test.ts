import {
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../../test/mocks/supabaseSingleton';
import { loadUsageBreakdown } from '../usage-breakdown';

// loadUsageBreakdown now aggregates in the DB (get_usage_breakdown) and assembles the
// chart-shaped result from pre-aggregated rows. These pin the assembly: bucket gap-fill,
// per-product totals, the overall total, the category filter, and that bigint/numeric
// values arriving as strings (PostgREST) are coerced.

const ORG = '00000000-0000-0000-0000-000000000001';
const start = new Date('2026-06-10T00:00:00Z');
const end = new Date('2026-06-12T00:00:00Z');

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
});

describe('loadUsageBreakdown', () => {
  it('assembles buckets, products, and total from aggregated rows (string-coerced)', async () => {
    setRpcResponse('get_usage_breakdown', {
      data: [
        { bucket: '2026-06-10', feature: 'aegis.chat', event_type: 'ai_tokens', cents: '150', quantity: '1000' },
        { bucket: '2026-06-10', feature: 'depscanner.scan', event_type: 'worker_minutes', cents: '50', quantity: '30' },
        { bucket: '2026-06-11', feature: 'aegis.chat', event_type: 'ai_tokens', cents: '250', quantity: '2000' },
      ],
      error: null,
    });

    const result = await loadUsageBreakdown({ organizationId: ORG, start, end, granularity: 'day' });

    expect(result.totalCents).toBe(450);
    // Products sorted by cents desc; aegis.chat aggregates across both days.
    expect(result.products.map((p) => [p.feature, p.totalCents])).toEqual([
      ['aegis.chat', 400],
      ['depscanner.scan', 50],
    ]);
    expect(result.products.find((p) => p.feature === 'aegis.chat')!.totalQuantity).toBe(3000);
    const day10 = result.buckets.find((b) => b.ts === '2026-06-10')!;
    expect(day10.totalCents).toBe(200);
    expect(day10.byFeature['aegis.chat']).toBe(150);
  });

  it('applies the category filter (ai drops worker rows)', async () => {
    setRpcResponse('get_usage_breakdown', {
      data: [
        { bucket: '2026-06-10', feature: 'aegis.chat', event_type: 'ai_tokens', cents: 150, quantity: 1000 },
        { bucket: '2026-06-10', feature: 'depscanner.scan', event_type: 'worker_minutes', cents: 50, quantity: 30 },
      ],
      error: null,
    });

    const result = await loadUsageBreakdown({ organizationId: ORG, start, end, granularity: 'day', category: 'ai' });

    expect(result.totalCents).toBe(150);
    expect(result.products.map((p) => p.feature)).toEqual(['aegis.chat']);
  });

  it('returns zero-filled buckets when there is no usage in the range', async () => {
    setRpcResponse('get_usage_breakdown', { data: [], error: null });

    const result = await loadUsageBreakdown({ organizationId: ORG, start, end, granularity: 'day' });

    expect(result.totalCents).toBe(0);
    expect(result.products).toEqual([]);
    expect(result.buckets.map((b) => b.ts)).toEqual(['2026-06-10', '2026-06-11', '2026-06-12']);
  });

  it('surfaces an RPC error', async () => {
    setRpcResponse('get_usage_breakdown', { data: null, error: { message: 'boom' } });
    await expect(loadUsageBreakdown({ organizationId: ORG, start, end, granularity: 'day' })).rejects.toThrow(/boom/);
  });
});
