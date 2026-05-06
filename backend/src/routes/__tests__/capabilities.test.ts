/**
 * Capability route tests.
 *
 * Covers:
 *   - happy path returns full capability tag set
 *   - 404 on cache miss (package not yet scanned)
 *   - 404 on unsupported ecosystem
 *   - 401 without auth token
 *   - cross-org 404 (caller not a member of URL's org)
 *   - one detectCapabilities call across two orgs hitting the global cache
 */
import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

const ORG_A = 'org-a';
const ORG_B = 'org-b';
const TOKEN = 'valid-token';
const USER = { id: 'user-1', email: 'henry@example.com' };

function setMember() {
  setTableResponse('organization_members', 'maybeSingle', { data: { user_id: USER.id }, error: null });
}

function setNotMember() {
  setTableResponse('organization_members', 'maybeSingle', { data: null, error: null });
}

const FULL_ROW = {
  package_name: 'evil',
  version: '1.0.0',
  ecosystem: 'npm',
  scanner_version: 'capability@v2.0.0',
  scanned_at: '2026-05-05T12:00:00Z',
  scan_error: null,
  spawns_processes: true,
  network_io: true,
  eval_dynamic: false,
  native_addon_load: false,
  filesystem_write: true,
  crypto_operations: false,
  serialization_deser: false,
  install_script: true,
  dns_query: false,
  websocket: false,
  process_signal: false,
  encrypted_payload: false,
  dynamic_import: false,
  reads_env: true,
  clipboard_access: false,
};

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: USER }, error: null });
});

describe('GET /api/organizations/:id/packages/:eco/:name/:ver/capabilities', () => {
  it('returns the capability row for org members on cache hit', async () => {
    setMember();
    setTableResponse('package_capabilities', 'maybeSingle', { data: FULL_ROW, error: null });

    const res = await request(app)
      .get(`/api/organizations/${ORG_A}/packages/npm/evil/1.0.0/capabilities`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      package_name: 'evil',
      version: '1.0.0',
      ecosystem: 'npm',
      scanner_version: 'capability@v2.0.0',
      scan_error: null,
    });
    expect(res.body.capabilities.spawns_processes).toBe(true);
    expect(res.body.capabilities.eval_dynamic).toBe(false);
    expect(res.body.capabilities.install_script).toBe(true);
  });

  it('returns 404 on cache miss (not yet scanned)', async () => {
    setMember();
    setTableResponse('package_capabilities', 'maybeSingle', { data: null, error: null });

    const res = await request(app)
      .get(`/api/organizations/${ORG_A}/packages/npm/never-scanned/0.0.1/capabilities`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(404);
  });

  it('returns 404 on unrecognised ecosystem', async () => {
    setMember();
    const res = await request(app)
      .get(`/api/organizations/${ORG_A}/packages/something-weird/foo/1.0.0/capabilities`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(404);
  });

  it('returns 401 without an auth token', async () => {
    const res = await request(app)
      .get(`/api/organizations/${ORG_A}/packages/npm/evil/1.0.0/capabilities`);
    expect(res.status).toBe(401);
  });

  it('returns 404 (not 403) when caller is not a member of the org', async () => {
    setNotMember();
    const res = await request(app)
      .get(`/api/organizations/${ORG_B}/packages/npm/evil/1.0.0/capabilities`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(404);
  });

  it('serves the same row to two different orgs (global cache reuse)', async () => {
    // Both orgs are members; both get the same capability row.
    setMember();
    setTableResponse('package_capabilities', 'maybeSingle', { data: FULL_ROW, error: null });

    const res1 = await request(app)
      .get(`/api/organizations/${ORG_A}/packages/npm/evil/1.0.0/capabilities`)
      .set('Authorization', `Bearer ${TOKEN}`);

    setMember(); // org B
    const res2 = await request(app)
      .get(`/api/organizations/${ORG_B}/packages/npm/evil/1.0.0/capabilities`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(res1.body.scanner_version).toBe(res2.body.scanner_version);
    expect(res1.body.capabilities).toEqual(res2.body.capabilities);
  });
});
