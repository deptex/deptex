/**
 * Retention pruner route tests.
 *
 * Covers the critical INTERNAL_API_KEY contract — the actual delete
 * fan-out is exercised by the smoke test against a live DB. Mocking
 * arbitrary Supabase chained delete().lt({ count: 'exact' }) calls in
 * the unit-test mock harness is more brittle than it's worth.
 */
import request from 'supertest';
import app from '../../index';

const ORIGINAL_KEY = process.env.INTERNAL_API_KEY;

beforeAll(() => {
  process.env.INTERNAL_API_KEY = 'test-internal-key';
});

afterAll(() => {
  process.env.INTERNAL_API_KEY = ORIGINAL_KEY;
});

describe('POST /api/internal/malicious/retention-prune', () => {
  it('returns 401 without an internal key', async () => {
    const res = await request(app).post('/api/internal/malicious/retention-prune');
    expect(res.status).toBe(401);
  });

  it('returns 401 with the wrong key', async () => {
    const res = await request(app)
      .post('/api/internal/malicious/retention-prune')
      .set('X-Internal-Api-Key', 'wrong-key');
    expect(res.status).toBe(401);
  });
});
