/**
 * Malicious-allowlist route tests.
 *
 * Covers:
 *   - GET list (active only) + cross-org 404
 *   - POST add (happy path, perm denial, duplicate 409, range-string reject,
 *     invalid ecosystem, missing fields)
 *   - DELETE soft-revoke (happy path, perm denial, cross-org 404,
 *     already-revoked 404)
 */
import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  pushTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

// Mock the audit-log helper so we can assert allowlist mutations are
// surfaced into the canonical org activity feed (P1 AL-1 / AL-2 regression).
jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn().mockResolvedValue(undefined),
}));
const { createActivity: createActivityMock } = require('../../lib/activities') as {
  createActivity: jest.Mock;
};

const ORG_ID = 'org-1';
const OTHER_ORG_ID = 'org-2';
const ENTRY_ID = 'entry-1';
const TOKEN = 'valid-token';
const USER = { id: 'user-1', email: 'henry@example.com' };

function setMember() {
  setTableResponse('organization_members', 'maybeSingle', { data: { user_id: USER.id }, error: null });
}

function setNotMember() {
  setTableResponse('organization_members', 'maybeSingle', { data: null, error: null });
}

function queueMembershipThenPermission(role: string, perms: Record<string, boolean>) {
  // Two `organization_members` lookups happen in sequence:
  //   1. isOrgMember() — `select('user_id')` + maybeSingle (we pin via setTableResponse)
  //   2. hasOrgPermission() — `select('role')` + maybeSingle
  // The mock returns the same `maybeSingle` value every call by default; queue
  // distinct rows via pushTableResponse so each call gets the right shape.
  pushTableResponse('organization_members', { data: { user_id: USER.id }, error: null });
  pushTableResponse('organization_members', { data: { role }, error: null });
  setTableResponse('organization_roles', 'maybeSingle', {
    data: { permissions: perms },
    error: null,
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: USER }, error: null });
  createActivityMock.mockClear();
});

// ─── GET list ───────────────────────────────────────────────────────────────

describe('GET /api/organizations/:id/malicious-allowlist', () => {
  it('returns active entries for org members', async () => {
    setMember();
    setTableResponse('organization_malicious_allowlist', 'then', {
      data: [
        {
          id: 'a1', organization_id: ORG_ID, package_name: 'lodash', version: '4.17.20',
          ecosystem: 'npm', reason: 'used in tests', added_by: USER.id, added_by_email: USER.email,
          added_at: '2026-05-05', revoked_at: null, revoked_by: null, revoked_by_email: null,
        },
      ],
      error: null,
    });

    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0]).toMatchObject({
      package_name: 'lodash',
      version: '4.17.20',
      ecosystem: 'npm',
      reason: 'used in tests',
      added_by_email: USER.email,
    });
  });

  it('returns 404 (not 403) when caller is not a member of the org', async () => {
    setNotMember();
    const res = await request(app)
      .get(`/api/organizations/${OTHER_ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(404);
  });

  it('returns 401 without an auth token', async () => {
    const res = await request(app).get(`/api/organizations/${ORG_ID}/malicious-allowlist`);
    expect(res.status).toBe(401);
  });
});

// ─── POST add ──────────────────────────────────────────────────────────────

describe('POST /api/organizations/:id/malicious-allowlist', () => {
  it('happy path: inserts the entry and returns the public shape', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    pushTableResponse('organization_malicious_allowlist', {
      data: {
        id: 'new-1', organization_id: ORG_ID, package_name: 'lodash', version: '4.17.20',
        ecosystem: 'npm', reason: 'security review 2026-04-15', added_by: USER.id,
        added_by_email: USER.email, added_at: '2026-05-05', revoked_at: null,
        revoked_by: null, revoked_by_email: null,
      },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        package_name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
        reason: 'security review 2026-04-15',
      });

    expect(res.status).toBe(201);
    expect(res.body.package_name).toBe('lodash');
    expect(res.body.version).toBe('4.17.20');
  });

  it('canonicalises ecosystem aliases (php -> composer)', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    pushTableResponse('organization_malicious_allowlist', {
      data: {
        id: 'new-2', organization_id: ORG_ID, package_name: 'symfony/process',
        version: null, ecosystem: 'composer', reason: 'long reason',
        added_by: USER.id, added_by_email: USER.email,
        added_at: '2026-05-05', revoked_at: null, revoked_by: null, revoked_by_email: null,
      },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        package_name: 'symfony/process',
        ecosystem: 'php',                  // alias for composer
        reason: 'long reason',
      });

    expect(res.status).toBe(201);
    expect(res.body.ecosystem).toBe('composer');
  });

  it('rejects semver-range syntax in version', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        package_name: 'lodash',
        version: '^4.0.0',
        ecosystem: 'npm',
        reason: 'long reason',
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/exact version/i);
  });

  it('returns 403 when user lacks manage_organization_settings', async () => {
    queueMembershipThenPermission('member', { manage_organization_settings: false });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        package_name: 'lodash',
        ecosystem: 'npm',
        reason: 'long reason',
      });
    expect(res.status).toBe(403);
  });

  it('returns 404 when user is not a member (cross-org probe)', async () => {
    setNotMember();
    const res = await request(app)
      .post(`/api/organizations/${OTHER_ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        package_name: 'lodash',
        ecosystem: 'npm',
        reason: 'long reason',
      });
    expect(res.status).toBe(404);
  });

  it('returns 409 on duplicate (Postgres 23505)', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    pushTableResponse('organization_malicious_allowlist', {
      data: null,
      error: { code: '23505', message: 'duplicate key value' },
    });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        package_name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
        reason: 'long reason',
      });
    expect(res.status).toBe(409);
  });

  it('rejects unknown ecosystem', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        package_name: 'foo',
        ecosystem: 'hex',                 // not yet supported
        reason: 'long reason',
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/ecosystem/i);
  });

  it('rejects empty reason', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ package_name: 'lodash', ecosystem: 'npm', reason: '' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/reason/i);
  });

  it('writes an audit-log entry on add (P1 AL-1 regression)', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    pushTableResponse('organization_malicious_allowlist', {
      data: {
        id: 'new-3', organization_id: ORG_ID, package_name: 'lodash', version: '4.17.20',
        ecosystem: 'npm', reason: 'security review', added_by: USER.id,
        added_by_email: USER.email, added_at: '2026-05-05', revoked_at: null,
        revoked_by: null, revoked_by_email: null,
      },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/malicious-allowlist`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        package_name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
        reason: 'security review',
      });

    expect(res.status).toBe(201);
    expect(createActivityMock).toHaveBeenCalledTimes(1);
    expect(createActivityMock).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: ORG_ID,
      user_id: USER.id,
      activity_type: 'added_malicious_allowlist_entry',
      description: expect.stringContaining('lodash'),
      metadata: expect.objectContaining({
        entry_id: 'new-3',
        package_name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
      }),
    }));
  });
});

// ─── DELETE revoke ─────────────────────────────────────────────────────────

describe('DELETE /api/organizations/:id/malicious-allowlist/:entryId', () => {
  it('soft-revokes when entry belongs to caller org', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    setTableResponse('organization_malicious_allowlist', 'maybeSingle', {
      data: {
        id: ENTRY_ID, organization_id: ORG_ID, revoked_at: null,
        package_name: 'lodash', version: '4.17.20', ecosystem: 'npm',
        reason: 'security review',
      },
      error: null,
    });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/malicious-allowlist/${ENTRY_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('writes an audit-log entry on revoke (P1 AL-2 regression)', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    setTableResponse('organization_malicious_allowlist', 'maybeSingle', {
      data: {
        id: ENTRY_ID, organization_id: ORG_ID, revoked_at: null,
        package_name: 'lodash', version: '4.17.20', ecosystem: 'npm',
        reason: 'security review',
      },
      error: null,
    });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/malicious-allowlist/${ENTRY_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(createActivityMock).toHaveBeenCalledTimes(1);
    expect(createActivityMock).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: ORG_ID,
      user_id: USER.id,
      activity_type: 'revoked_malicious_allowlist_entry',
      description: expect.stringContaining('lodash'),
      metadata: expect.objectContaining({
        entry_id: ENTRY_ID,
        package_name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
      }),
    }));
  });

  it('returns 404 when the entry belongs to a different org (cross-org probe)', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    setTableResponse('organization_malicious_allowlist', 'maybeSingle', {
      data: { id: ENTRY_ID, organization_id: OTHER_ORG_ID, revoked_at: null },
      error: null,
    });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/malicious-allowlist/${ENTRY_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(404);
  });

  it('returns 404 when the entry is already revoked', async () => {
    queueMembershipThenPermission('admin', { manage_organization_settings: true });
    setTableResponse('organization_malicious_allowlist', 'maybeSingle', {
      data: { id: ENTRY_ID, organization_id: ORG_ID, revoked_at: '2026-05-01' },
      error: null,
    });
    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/malicious-allowlist/${ENTRY_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(404);
  });

  it('returns 403 when user lacks manage_organization_settings', async () => {
    queueMembershipThenPermission('member', { manage_organization_settings: false });
    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/malicious-allowlist/${ENTRY_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(403);
  });
});
