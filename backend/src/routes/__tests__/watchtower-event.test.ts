/**
 * Phase 10B: Watchtower event endpoint unit tests
 */

jest.mock('../../lib/features', () => ({
  isEeEdition: jest.fn().mockReturnValue(false),
}));

const mockEmitEvent = jest.fn().mockResolvedValue(undefined);
jest.mock('../../../../ee/backend/lib/event-bus', () => ({
  emitEvent: (...args: unknown[]) => mockEmitEvent(...args),
}));

process.env.INTERNAL_API_KEY = 'test-internal-key';

import request from 'supertest';
import express from 'express';
import watchtowerEventRouter from '../watchtower-event';

const app = express();
app.use(express.json());
app.use('/api/internal/watchtower-event', watchtowerEventRouter);

const originalEnv = process.env.INTERNAL_API_KEY;

beforeEach(() => {
  jest.clearAllMocks();
  process.env.INTERNAL_API_KEY = 'test-internal-key';
  const { isEeEdition } = require('../../lib/features');
  (isEeEdition as jest.Mock).mockReturnValue(false);
});

afterAll(() => {
  process.env.INTERNAL_API_KEY = originalEnv;
});

describe('POST /api/internal/watchtower-event', () => {
  it('requires X-Internal-Api-Key header', async () => {
    const res = await request(app)
      .post('/api/internal/watchtower-event')
      .send({
        event_type: 'supply_chain_anomaly',
        organization_id: 'org-1',
        package_name: 'lodash',
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('returns 400 when required fields are missing', async () => {
    const res = await request(app)
      .post('/api/internal/watchtower-event')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({ organization_id: 'org-1' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/event_type|organization_id|package_name/);
  });

  it('returns 200 with valid body and does not call emitEvent in CE mode', async () => {
    const res = await request(app)
      .post('/api/internal/watchtower-event')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({
        event_type: 'security_analysis_failure',
        organization_id: 'org-1',
        package_name: 'lodash',
        payload: { registry: 'fail' },
        priority: 'high',
      });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(mockEmitEvent).not.toHaveBeenCalled();
  });

  it('in EE mode calls emitEvent with watchtower source', async () => {
    const { isEeEdition } = require('../../lib/features');
    (isEeEdition as jest.Mock).mockReturnValue(true);

    const res = await request(app)
      .post('/api/internal/watchtower-event')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({
        event_type: 'new_version_available',
        organization_id: 'org-1',
        project_id: 'proj-1',
        package_name: 'react',
        payload: { new_version: '19.0.0' },
        priority: 'normal',
      });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(mockEmitEvent).toHaveBeenCalledTimes(1);
    expect(mockEmitEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: 'new_version_available',
        organization_id: 'org-1',
        project_id: 'proj-1',
        source: 'watchtower',
        priority: 'normal',
        payload: expect.objectContaining({
          package_name: 'react',
          new_version: '19.0.0',
        }),
      })
    );
  });

  it('accepts request without project_id (optional)', async () => {
    const res = await request(app)
      .post('/api/internal/watchtower-event')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({
        event_type: 'security_analysis_failure',
        organization_id: 'org-1',
        package_name: 'lodash',
      });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('in EE mode defaults priority to normal when missing', async () => {
    const { isEeEdition } = require('../../lib/features');
    (isEeEdition as jest.Mock).mockReturnValue(true);

    await request(app)
      .post('/api/internal/watchtower-event')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({
        event_type: 'supply_chain_anomaly',
        organization_id: 'org-1',
        package_name: 'pkg',
      });

    expect(mockEmitEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        priority: 'normal',
      })
    );
  });

  it('in EE mode returns 200 when emitEvent throws (fire-and-forget)', async () => {
    const { isEeEdition } = require('../../lib/features');
    (isEeEdition as jest.Mock).mockReturnValue(true);
    mockEmitEvent.mockRejectedValueOnce(new Error('Event bus unavailable'));

    const res = await request(app)
      .post('/api/internal/watchtower-event')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({
        event_type: 'new_version_available',
        organization_id: 'org-1',
        package_name: 'pkg',
      });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });
});
