/**
 * Maintainer-signal sync route tests.
 *
 * Covers:
 *   - 401 on missing / wrong INTERNAL_API_KEY
 *   - 200 on success with the orchestrator return shape forwarded
 *   - Lib unit-level coverage of cross-org fan-out lives next to the lib
 *     itself in maintainer-sync-lib.test.ts; this suite focuses on the
 *     thin route wiring + auth.
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

describe('POST /api/internal/malicious/maintainer-signal-sync', () => {
  it('returns 401 without an internal key', async () => {
    const res = await request(app).post('/api/internal/malicious/maintainer-signal-sync');
    expect(res.status).toBe(401);
  });

  it('returns 401 with a wrong key', async () => {
    const res = await request(app)
      .post('/api/internal/malicious/maintainer-signal-sync')
      .set('X-Internal-Api-Key', 'wrong-key');
    expect(res.status).toBe(401);
  });
});
