import request from 'supertest';
import app from '../../index';
import {
  supabase,
  queryBuilder,
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

// Phase 1 (findings-tab-perf): GET /dast/findings gained an opt-in
// `resolve_target=latest` mode so the Findings tab no longer runs a client-side
// getDastJobs → find(target_id) → getDastFindings waterfall. The server picks
// the latest scan job that carries a target_id (mirroring the old frontend
// rule) and returns that target's findings in one request. These tests pin the
// selection rule, the limit, and that the explicit-target path is unchanged.
const mockUser = { id: 'user-1', email: 'henry@example.com' };
const token = 'valid-token';
const orgId = 'org-A';
const projectId = 'proj-1';
const findingsUrl = `/api/projects/${projectId}/dast/findings`;

function loadedTarget(id: string) {
  return {
    id,
    project_id: projectId,
    organization_id: orgId,
    target_url: 'https://app.example.com',
    detected_runtime: 'browser',
    detected_runtime_at: null,
    detected_runtime_ttl_at: null,
    enabled: true,
    api_spec_source: 'none',
    api_spec_url: null,
    last_synthesized_at: null,
    last_synthesis_endpoint_count: null,
    last_synthesis_ok: null,
    active_dast_run_id: 'run-x',
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  clearRpcRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: mockUser },
    error: null,
  });
  // Org owner → resolveProjectAccess + checkProjectAccess both pass.
  setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 0 },
    error: null,
  });
  // resolveProjectAccess reads projects.single; checkProjectAccess belongs-check
  // reads projects.maybeSingle.
  setTableResponse('projects', 'single', { data: { organization_id: orgId }, error: null });
  setTableResponse('projects', 'maybeSingle', { data: { organization_id: orgId }, error: null });
});

describe('GET /dast/findings?resolve_target=latest (Phase 1)', () => {
  it('selects the latest scan job that has a target_id and returns its findings', async () => {
    // Jobs in created_at desc order: newest has no target, then tgt-A, then tgt-B.
    // The frontend rule (find first with target) picks tgt-A — NOT the older tgt-B.
    setTableResponse('scan_jobs', 'then', {
      data: [{ target_id: null }, { target_id: 'tgt-A' }, { target_id: 'tgt-B' }],
      error: null,
    });
    setTableResponse('project_dast_targets', 'maybeSingle', { data: loadedTarget('tgt-A'), error: null });
    setTableResponse('project_dast_findings', 'then', {
      data: [
        {
          id: 'f1',
          target_id: 'tgt-A',
          engine: 'zap',
          kev: false,
          endpoint_url: 'https://app.example.com/login',
          http_method: 'POST',
          vulnerability_type: 'SQL Injection',
          severity: 'high',
          confidence: 'high',
          linked_sca_osv_id: null,
          status: 'open',
          created_at: '2026-02-02T00:00:00Z',
        },
      ],
      error: null,
    });

    const res = await request(app)
      .get(`${findingsUrl}?limit=200&resolve_target=latest`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].id).toBe('f1');
    // dastDepscore ran: high(72) + confidence high(+6) + injection(+10) = 88.
    expect(res.body[0].depscore).toBe(88);
    // The resolver fetched the recent jobs window (limit 5) and the findings
    // query used the requested limit (200).
    expect(queryBuilder.limit).toHaveBeenCalledWith(5);
    expect(queryBuilder.limit).toHaveBeenCalledWith(200);
    // The resolved target (tgt-A) is the one loaded/queried — never tgt-B.
    expect(queryBuilder.eq).toHaveBeenCalledWith('id', 'tgt-A');
    expect(queryBuilder.eq).not.toHaveBeenCalledWith('id', 'tgt-B');
  });

  it('returns [] when no recent job carries a target_id', async () => {
    setTableResponse('scan_jobs', 'then', {
      data: [{ target_id: null }, { target_id: null }],
      error: null,
    });

    const res = await request(app)
      .get(`${findingsUrl}?limit=200&resolve_target=latest`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
    // Never reached the findings table.
    expect(supabase.from).not.toHaveBeenCalledWith('project_dast_findings');
  });

  it('explicit target_id path is unchanged — does not query scan_jobs', async () => {
    setTableResponse('project_dast_targets', 'maybeSingle', { data: loadedTarget('tgt-A'), error: null });
    setTableResponse('project_dast_findings', 'then', { data: [], error: null });

    const res = await request(app)
      .get(`${findingsUrl}?limit=200&target_id=tgt-A`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
    // No resolve_target flag → server-side resolution is skipped entirely.
    expect(supabase.from).not.toHaveBeenCalledWith('scan_jobs');
  });
});
