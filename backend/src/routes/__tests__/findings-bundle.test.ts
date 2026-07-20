import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

// Phase 2 (findings-tab-perf): the project findings BUNDLE collapses the ~12
// per-project findings endpoints the Findings tab called serially into ONE
// request behind a SINGLE access check, running every slice concurrently. These
// tests pin: (1) the happy-path 12-key shape with slices populated from mocked
// tables, (2) the secret manager-gate removal on the standalone endpoint,
// (3) the no-active-run fast path that skips the run-scoped row queries,
// (4) per-slice failure isolation via degradedSlices, and (5) the single
// access check (a non-member gets 404 from the bundle).
const mockUser = { id: 'user-1', email: 'henry@example.com' };
const token = 'valid-token';
const orgId = 'org-A';
const projectId = 'proj-1';
const bundleUrl = `/api/organizations/${orgId}/projects/${projectId}/findings`;

function grantOrgOwner() {
  setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 0 },
    error: null,
  });
}

function denyOrgAccess() {
  setTableResponse('organization_members', 'single', { data: null, error: { message: 'not found' } });
}

// Org member without manage, but a direct project member → read access, no manage.
function grantProjectMemberOnly() {
  setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: false }, display_order: 0 },
    error: null,
  });
  setTableResponse('project_members', 'single', { data: { role_id: 'role-1' }, error: null });
  setTableResponse('team_members', 'then', { data: [], error: null });
  setTableResponse('project_teams', 'then', { data: [], error: null });
}

function loadedDastTarget(id: string) {
  return {
    id,
    project_id: projectId,
    organization_id: orgId,
    target_url: 'https://app.example.com',
    detected_runtime: 'classic',
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

/** Wire every slice's table so all 12 builders succeed with one row each. */
function stubAllSlicesPopulated() {
  // 1. vulnerabilities — PDV branch (probe returns ≥1 row → PDV RPC).
  setTableResponse('project_dependency_findings', 'then', { data: [{ id: 'pdv-x' }], error: null });
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
        depscore: 80,
      },
    ],
    error: null,
  });
  // 2. secrets
  setTableResponse('project_secret_findings', 'then', {
    data: [{ id: 'sec-1', rule: 'aws', is_verified: true }],
    error: null,
  });
  // 3. semgrep
  setTableResponse('project_semgrep_findings', 'then', { data: [{ id: 'sg-1' }], error: null });
  // 4. iac
  setTableResponse('project_iac_findings', 'then', {
    data: [{ id: 'iac-1', rule_id: 'CKV_AWS_20', severity: 'CRITICAL', status: 'open' }],
    error: null,
  });
  // 5. container
  setTableResponse('project_container_findings', 'then', { data: [{ id: 'cf-1' }], error: null });
  // 6. malicious (+ hydration tables)
  setTableResponse('project_malicious_findings', 'then', {
    data: [{ id: 'mal-1', project_dependency_id: 'pd-1', severity: 'high' }],
    error: null,
  });
  setTableResponse('project_dependencies', 'then', {
    data: [{ id: 'pd-1', version: '1.2.3', dependency_id: 'dep-1' }],
    error: null,
  });
  setTableResponse('dependencies', 'then', {
    data: [{ id: 'dep-1', name: 'evil-pkg', ecosystem: 'npm' }],
    error: null,
  });
  // 7. code-flow findings
  setTableResponse('project_reachable_flows', 'then', {
    data: [{ id: 'flow-1', vuln_class: 'sql_injection', flow_signature_hash: 'h1', flow_length: 3 }],
    error: null,
  });
  setTableResponse('project_reachable_flow_suppressions', 'then', { data: [], error: null });
  // 8. base-image recommendations
  setTableResponse('project_base_image_recommendations', 'then', {
    data: [{ id: 'rec-1', dockerfile_path: 'Dockerfile', cve_delta: 5 }],
    error: null,
  });
  // 9. dast (org-fetch off projects.single, target resolution + findings)
  setTableResponse('scan_jobs', 'then', { data: [{ target_id: 'tgt-A' }], error: null });
  setTableResponse('project_dast_targets', 'maybeSingle', { data: loadedDastTarget('tgt-A'), error: null });
  setTableResponse('project_dast_findings', 'then', {
    data: [
      {
        id: 'dast-1',
        severity: 'high',
        confidence: 'high',
        vulnerability_type: 'SQL Injection',
        endpoint_url: 'https://app.example.com/login',
        http_method: 'POST',
        linked_sca_osv_id: null,
        kev: false,
        status: 'open',
        created_at: '2026-02-02T00:00:00Z',
      },
    ],
    error: null,
  });
  // 10-12. org-wide chip maps
  setTableResponse('finding_tracker_links', 'then', {
    data: [{ id: 'tl-1', project_id: projectId, finding_type: 'vulnerability', finding_key: 'k', provider: 'github' }],
    error: null,
  });
  setTableResponse('project_finding_group_suppressions', 'then', {
    data: [{ project_id: projectId, group_type: 'container_group', group_key: 'g' }],
    error: null,
  });
  setTableResponse('project_finding_acknowledgements', 'then', {
    data: [{ project_id: projectId, finding_type: 'secret', finding_key: 'k' }],
    error: null,
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  clearRpcRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: mockUser }, error: null });
  grantOrgOwner();
  // checkProjectAccess belongs-check reads projects.maybeSingle.
  setTableResponse('projects', 'maybeSingle', { data: { organization_id: orgId }, error: null });
  // getActiveExtractionId + the dast builder's org-fetch read projects.single.
  setTableResponse('projects', 'single', {
    data: { active_extraction_run_id: 'run-1', organization_id: orgId },
    error: null,
  });
});

describe('GET /findings — project findings bundle', () => {
  it('happy path (owner): returns all 12 slice keys + degradedSlices, slices populated', async () => {
    stubAllSlicesPopulated();

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    // All 12 slice keys + degradedSlices present.
    for (const key of [
      'vulnerabilities',
      'secrets',
      'semgrep',
      'iac',
      'container',
      'malicious',
      'codeFlows',
      'baseImageRecs',
      'dast',
      'trackerLinks',
      'groupSuppressions',
      'acknowledgements',
      'degradedSlices',
    ]) {
      expect(res.body).toHaveProperty(key);
    }
    // Spot-check four slices populated from their mocked tables.
    expect(res.body.vulnerabilities[0].osv_id).toBe('CVE-2024-0001');
    expect(res.body.secrets.data).toHaveLength(1);
    expect(res.body.iac.data[0].rule_id).toBe('CKV_AWS_20');
    expect(res.body.trackerLinks).toHaveLength(1);
    // Nothing degraded on the happy path.
    expect(res.body.degradedSlices).toEqual([]);
  });

  it('no active extraction run → run-scoped slices are empty and never query their tables', async () => {
    // projects.single still carries the org (for the dast org-fetch) but no run.
    setTableResponse('projects', 'single', { data: { active_extraction_run_id: null, organization_id: orgId }, error: null });

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.vulnerabilities).toEqual([]);
    expect(res.body.secrets).toMatchObject({ data: [], total: 0 });
    expect(res.body.semgrep).toMatchObject({ data: [], total: 0 });
    expect(res.body.iac).toMatchObject({ data: [], total: 0 });
    expect(res.body.container).toMatchObject({ data: [], total: 0 });
    expect(res.body.malicious).toMatchObject({ data: [], total: 0 });
    expect(res.body.codeFlows).toMatchObject({ data: [], total: 0 });
    expect(res.body.baseImageRecs).toMatchObject({ recommendations: [] });
    expect(res.body.degradedSlices).toEqual([]);
    // The run-scoped finding tables are never touched, and the vuln branch RPC
    // is never run — that's the no-active-run fast path.
    for (const table of [
      'project_dependency_findings',
      'project_secret_findings',
      'project_semgrep_findings',
      'project_iac_findings',
      'project_container_findings',
      'project_malicious_findings',
      'project_reachable_flows',
      'project_base_image_recommendations',
    ]) {
      expect(supabase.from).not.toHaveBeenCalledWith(table);
    }
    expect(supabase.rpc).not.toHaveBeenCalled();
  });

  it('failure isolation: one slice rejecting degrades only that slice (200 + degradedSlices)', async () => {
    // Populate vulns so it still succeeds; make the iac data query reject.
    setTableResponse('project_dependency_findings', 'then', { data: [{ id: 'pdv-x' }], error: null });
    setRpcResponse('get_project_dependency_findings_from_pdv', {
      data: [{ id: 'v1', osv_id: 'CVE-2024-0001', severity: 'high', dependency_id: 'dep-1', dependency_name: 'lodash' }],
      error: null,
    });
    setTableResponse('project_iac_findings', 'then', { data: null, error: { message: 'boom' } });

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.degradedSlices).toContain('iac');
    // The degraded slice falls back to its empty default…
    expect(res.body.iac).toEqual({ data: [], total: 0, page: 1, per_page: 100 });
    // …while other slices still populate.
    expect(res.body.vulnerabilities[0].osv_id).toBe('CVE-2024-0001');
  });

  it('single access check: a non-member gets 404 from the bundle', async () => {
    denyOrgAccess();
    stubAllSlicesPopulated();

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found|access/i);
  });

  it('access is hoisted, not per-slice: a project-member-only caller still gets secrets in the bundle', async () => {
    // No manage permission, but a direct project_members row → read access.
    grantProjectMemberOnly();
    stubAllSlicesPopulated();

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    // Secrets are NOT manager-gated in the bundle — a read-only member sees them.
    expect(res.body.secrets.data).toHaveLength(1);
  });
});

describe('GET /secret-findings — manager gate removed (now access-only)', () => {
  it('a read-only project member (no manage perm) gets 200, not 403', async () => {
    grantProjectMemberOnly();
    setTableResponse('project_secret_findings', 'then', {
      data: [{ id: 'sec-1', rule: 'aws', is_verified: true }],
      error: null,
    });

    const res = await request(app)
      .get(`/api/organizations/${orgId}/projects/${projectId}/secret-findings`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(1);
  });
});
