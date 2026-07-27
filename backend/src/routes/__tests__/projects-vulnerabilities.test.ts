import request from 'supertest';
import app from '../../index';
import {
  supabase,
  queryBuilder,
  setTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

// Phase 1 (findings-tab-perf): the SCA vulnerabilities endpoint replaced a
// `count(exact, head)` over project_dependency_findings — which makes
// the DB tally every matching CVE just to compare against zero — with a
// single-row existence probe (`select id … limit 1`). These tests pin that the
// probe selects the SAME branch the count head did across all three paths
// (PDV RPC / legacy RPC / rpc-error deps fallback) and that it uses limit(1),
// not a full count.
const mockUser = { id: 'user-1', email: 'henry@example.com' };
const token = 'valid-token';
const orgId = 'org-A';
const projectId = 'proj-1';
const url = `/api/organizations/${orgId}/projects/${projectId}/vulnerabilities`;

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  clearRpcRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: mockUser },
    error: null,
  });
  // Org owner with manage → checkProjectAccess passes via the org branch.
  setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 0 },
    error: null,
  });
  // projectBelongsToOrg (checkProjectAccess) reads projects.maybeSingle.
  setTableResponse('projects', 'maybeSingle', { data: { organization_id: orgId }, error: null });
  // getActiveExtractionId reads projects.single → a finalized run exists.
  setTableResponse('projects', 'single', { data: { active_extraction_run_id: 'run-1' }, error: null });
});

describe('GET /vulnerabilities — SCA branch-selection probe (Phase 1)', () => {
  it('uses a limit(1) existence probe, not a full count, to pick the branch', async () => {
    // ≥1 PDV row → PDV branch.
    setTableResponse('project_dependency_findings', 'then', {
      data: [{ id: 'pdv-x' }],
      error: null,
    });
    setRpcResponse('get_project_dependency_findings_from_pdv', { data: [], error: null });

    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    // The probe bounds the read to a single row instead of counting them all.
    expect(queryBuilder.limit).toHaveBeenCalledWith(1);
  });

  it('PDV branch: ≥1 PDV row → get_project_dependency_findings_from_pdv with reachability fields', async () => {
    setTableResponse('project_dependency_findings', 'then', {
      data: [{ id: 'pdv-x' }],
      error: null,
    });
    setRpcResponse('get_project_dependency_findings_from_pdv', {
      data: [
        {
          id: 'v1',
          osv_id: 'CVE-2024-0001',
          severity: 'high',
          dependency_id: 'dep-1',
          dependency_name: 'lodash',
          dependency_version: '4.17.20',
          is_reachable: true,
          reachability_level: 'function',
          depscore: 80,
        },
      ],
      error: null,
    });

    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].osv_id).toBe('CVE-2024-0001');
    // PDV-only fields are spread in only on the PDV branch.
    expect(res.body[0].is_reachable).toBe(true);
    expect(res.body[0].depscore).toBe(80);
    expect(supabase.rpc).toHaveBeenCalledWith('get_project_dependency_findings_from_pdv', {
      p_project_id: projectId,
    });
    expect(supabase.rpc).not.toHaveBeenCalledWith('get_project_dependency_findings', expect.anything());
  });

  it('legacy branch: zero PDV rows → get_project_dependency_findings, no reachability fields', async () => {
    // Empty probe → usePdv=false → legacy RPC.
    setTableResponse('project_dependency_findings', 'then', { data: [], error: null });
    setRpcResponse('get_project_dependency_findings', {
      data: [
        {
          id: 'v2',
          osv_id: 'CVE-2024-0002',
          severity: 'medium',
          dependency_id: 'dep-2',
          dependency_name: 'express',
        },
      ],
      error: null,
    });

    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].osv_id).toBe('CVE-2024-0002');
    // No PDV branch → reachability/depscore fields are absent, not null.
    expect(res.body[0]).not.toHaveProperty('is_reachable');
    expect(res.body[0]).not.toHaveProperty('depscore');
    expect(supabase.rpc).toHaveBeenCalledWith('get_project_dependency_findings', {
      p_project_id: projectId,
    });
    expect(supabase.rpc).not.toHaveBeenCalledWith(
      'get_project_dependency_findings_from_pdv',
      expect.anything(),
    );
  });

  it('rpc-error fallback: PDV branch RPC errors → per-dependency deps fallback', async () => {
    setTableResponse('project_dependency_findings', 'then', {
      data: [{ id: 'pdv-x' }],
      error: null,
    });
    // The chosen RPC fails (e.g. not yet deployed) → fallback path.
    setRpcResponse('get_project_dependency_findings_from_pdv', {
      data: null,
      error: { message: 'function not found' },
    });
    setTableResponse('project_dependencies', 'then', {
      data: [{ dependency_id: 'dep-3', name: 'minimist', version: '1.2.0' }],
      error: null,
    });
    setTableResponse('dependency_vulnerabilities', 'then', {
      data: [
        {
          id: 'dv-1',
          dependency_id: 'dep-3',
          osv_id: 'CVE-2024-0003',
          severity: 'critical',
          summary: 'prototype pollution',
          published_at: '2024-01-01T00:00:00Z',
        },
      ],
      error: null,
    });

    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].osv_id).toBe('CVE-2024-0003');
    expect(res.body[0].dependency_name).toBe('minimist');
  });

  it('no active extraction run → empty array, no PDV probe or RPC', async () => {
    setTableResponse('projects', 'single', { data: { active_extraction_run_id: null }, error: null });

    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
    expect(supabase.from).not.toHaveBeenCalledWith('project_dependency_findings');
    expect(supabase.rpc).not.toHaveBeenCalled();
  });
});
