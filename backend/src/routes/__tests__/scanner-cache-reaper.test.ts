/**
 * scanner-cache-reaper — the daily QStash cron that prunes container-scan
 * maintenance tables.
 *
 * Phase 2 close-out folded a second reaper into this handler:
 * `cleanup_dismissed_base_image_recommendations` runs alongside the existing
 * `cleanup_container_image_scan_cache` on the same retention window. These
 * tests pin both invocations and the widened response shape.
 */

import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setRpcResponse,
  clearRpcRegistry,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

const REAP_URL = '/api/workers/scanner-cache-reap';

const ORIGINAL_INTERNAL_KEY = process.env.INTERNAL_API_KEY;

beforeEach(() => {
  jest.clearAllMocks();
  clearRpcRegistry();
  clearTableRegistry();
  process.env.INTERNAL_API_KEY = 'test-internal-key';
  // Default: both reaps succeed with explicit row counts.
  setRpcResponse('cleanup_container_image_scan_cache', { data: 7, error: null });
  setRpcResponse('cleanup_dismissed_base_image_recommendations', { data: 3, error: null });
});

afterAll(() => {
  if (ORIGINAL_INTERNAL_KEY === undefined) {
    delete process.env.INTERNAL_API_KEY;
  } else {
    process.env.INTERNAL_API_KEY = ORIGINAL_INTERNAL_KEY;
  }
});

describe('POST /api/workers/scanner-cache-reap', () => {
  it('rejects an unauthenticated request', async () => {
    const res = await request(app).post(REAP_URL).send({});
    expect(res.status).toBe(401);
  });

  it('invokes BOTH reaps and returns both row counts; recommendation retention defaults to 90 even with a 45-day cache retention', async () => {
    const rpcSpy = jest.spyOn(supabase, 'rpc');
    const res = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({ retention_days: 45 });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      ok: true,
      cache_rows_deleted: 7,
      recommendation_rows_deleted: 3,
      retention_days: 45,
      recommendation_retention_days: 90,
    });
    // Cache uses the body's retention_days; recommendations use the 90d
    // default (RPC's own DEFAULT 90), NOT the cache's window.
    const calls = rpcSpy.mock.calls.map((c) => [c[0], c[1]]);
    expect(calls).toEqual(
      expect.arrayContaining([
        ['cleanup_container_image_scan_cache', { retention_days: 45 }],
        ['cleanup_dismissed_base_image_recommendations', { retention_days: 90 }],
      ])
    );
  });

  it('allows an explicit recommendation_retention_days override', async () => {
    const rpcSpy = jest.spyOn(supabase, 'rpc');
    const res = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({ retention_days: 30, recommendation_retention_days: 14 });

    expect(res.status).toBe(200);
    expect(res.body.recommendation_retention_days).toBe(14);
    const calls = rpcSpy.mock.calls.map((c) => [c[0], c[1]]);
    expect(calls).toEqual(
      expect.arrayContaining([
        ['cleanup_container_image_scan_cache', { retention_days: 30 }],
        ['cleanup_dismissed_base_image_recommendations', { retention_days: 14 }],
      ])
    );
  });

  it('defaults to retention_days=30 + recommendation_retention_days=90 when the body omits both', async () => {
    const rpcSpy = jest.spyOn(supabase, 'rpc');
    const res = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});
    expect(res.status).toBe(200);
    expect(res.body.retention_days).toBe(30);
    expect(res.body.recommendation_retention_days).toBe(90);
    const calls = rpcSpy.mock.calls.map((c) => [c[0], c[1]]);
    expect(calls).toEqual(
      expect.arrayContaining([
        ['cleanup_container_image_scan_cache', { retention_days: 30 }],
        ['cleanup_dismissed_base_image_recommendations', { retention_days: 90 }],
      ])
    );
  });

  it('rejects an out-of-range recommendation_retention_days', async () => {
    const res = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({ recommendation_retention_days: 999 });
    expect(res.status).toBe(400);
  });

  it('rejects an out-of-range retention_days', async () => {
    const tooLow = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({ retention_days: 0 });
    expect(tooLow.status).toBe(400);

    const tooHigh = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({ retention_days: 999 });
    expect(tooHigh.status).toBe(400);
  });

  it('returns 500 when the cache reap RPC fails', async () => {
    setRpcResponse('cleanup_container_image_scan_cache', {
      data: null,
      error: { message: 'pg down' },
    });
    const res = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});
    expect(res.status).toBe(500);
  });

  it('returns 500 when the recommendation reap RPC fails', async () => {
    setRpcResponse('cleanup_dismissed_base_image_recommendations', {
      data: null,
      error: { message: 'pg down' },
    });
    const res = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});
    expect(res.status).toBe(500);
  });

  it('coerces a non-numeric RPC return into 0 (defensive)', async () => {
    setRpcResponse('cleanup_container_image_scan_cache', { data: null, error: null });
    setRpcResponse('cleanup_dismissed_base_image_recommendations', { data: 'oops', error: null });
    const res = await request(app)
      .post(REAP_URL)
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});
    expect(res.status).toBe(200);
    expect(res.body.cache_rows_deleted).toBe(0);
    expect(res.body.recommendation_rows_deleted).toBe(0);
  });
});
