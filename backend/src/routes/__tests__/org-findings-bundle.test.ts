import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../test/mocks/supabaseSingleton';
import * as overview from '../../lib/overview';
import * as projectFindings from '../../lib/project-findings';
import { assembleFindingsBundle } from '../../lib/findings-bundle';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

// Org Findings BUNDLE — collapses the org page's old 1 + N×~8 browser fan-out into
// ONE request. SCA reads as ONE bounded cross-project query; the other types fan the
// per-project engine in (skipVulns). These tests pin: (1) the access gate is the
// tenant boundary AND the route FORWARDS the gate's accessible set into both the SCA
// read and the per-project fan-in (the mock can't filter `.in()`, so we assert the
// filter ARGUMENT, not the filtered result); (2) project_framework is stamped
// server-side onto every row; (3) a non-member gets 404; (4) — via a direct
// assembleFindingsBundle unit test — all slices merge + stamp + per-project failure
// isolation + the empty-input contract.
const mockUser = { id: 'user-1', email: 'henry@example.com' };
const token = 'valid-token';
const orgId = 'org-A';
const url = `/api/organizations/${orgId}/findings`;

function emptyCore(): any {
  return {
    vulnerabilities: [], secrets: [], semgrep: [], iac: [], container: [],
    malicious: [], codeFlows: [], baseImageRecs: [], dast: [],
    degradedSlices: [], sliceMs: {},
  };
}

beforeEach(() => {
  jest.restoreAllMocks();
  jest.clearAllMocks();
  clearTableRegistry();
  clearRpcRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: mockUser }, error: null });
});

describe('GET /:id/findings — org findings bundle', () => {
  it('forwards the gate\'s accessible set into the SCA read AND the per-project fan-in, and stamps framework', async () => {
    // Gate resolves to ONLY project A. The route must validate + fan over exactly this.
    jest.spyOn(overview, 'getAccessibleProjectIdsInOrganization').mockResolvedValue({ projectIds: ['A'] });
    // Validate read returns A (simulating the DB having applied the org+id filter).
    setTableResponse('projects', 'then', {
      data: [{ id: 'A', name: 'Proj A', framework: 'node', active_extraction_run_id: 'run-A' }],
      error: null,
    });
    // Bulk SCA reads PDV → one CVE row tagged project A.
    setTableResponse('project_dependency_findings', 'then', {
      data: [{ id: 'v1', project_id: 'A', project_dependency_id: 'pd-1', osv_id: 'CVE-2024-1', severity: 'high', depscore: 80, finding_key: 'fk-1', status: 'open' }],
      error: null,
    });
    setTableResponse('project_dependencies', 'then', { data: [{ id: 'pd-1', name: 'lodash', version: '4.17.20', dependency_id: 'dep-1' }], error: null });
    // The per-project fan-in (skipVulns) returns one secret for A.
    const coreSpy = jest.spyOn(projectFindings, 'buildProjectFindingsCoreUnchecked')
      .mockResolvedValue({ ...emptyCore(), secrets: [{ id: 'sec-1', rule: 'aws' }] });

    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.projectIds).toEqual(['A']);
    // Bulk SCA present + stamped with project name + framework.
    expect(res.body.vulnerabilities).toHaveLength(1);
    expect(res.body.vulnerabilities[0].osv_id).toBe('CVE-2024-1');
    expect(res.body.vulnerabilities[0].finding_key).toBe('fk-1'); // kebab fields carried
    expect(res.body.vulnerabilities[0].project_name).toBe('Proj A');
    expect(res.body.vulnerabilities[0].project_framework).toBe('node');
    // Fan-in secret stamped with project_id + framework.
    expect(res.body.secrets).toHaveLength(1);
    expect(res.body.secrets[0].project_id).toBe('A');
    expect(res.body.secrets[0].project_framework).toBe('node');
    // ISOLATION (filter argument, not filtered result): the per-project fan-in was
    // invoked ONLY for the validated/accessible project A, with skipVulns set.
    expect(coreSpy).toHaveBeenCalledTimes(1);
    expect(coreSpy).toHaveBeenCalledWith(orgId, 'A', 'run-A', expect.objectContaining({ skipVulns: true }));
  });

  it('a non-member gets 404 (the gate is the tenant boundary), no fan-in', async () => {
    jest.spyOn(overview, 'getAccessibleProjectIdsInOrganization')
      .mockResolvedValue({ projectIds: [], error: { status: 404, message: 'Organization not found or access denied' } });
    const coreSpy = jest.spyOn(projectFindings, 'buildProjectFindingsCoreUnchecked').mockResolvedValue(emptyCore());

    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found|access/i);
    expect(coreSpy).not.toHaveBeenCalled();
  });

  it('no accessible projects → empty bundle, no fan-in', async () => {
    jest.spyOn(overview, 'getAccessibleProjectIdsInOrganization').mockResolvedValue({ projectIds: [] });
    const coreSpy = jest.spyOn(projectFindings, 'buildProjectFindingsCoreUnchecked').mockResolvedValue(emptyCore());

    const res = await request(app).get(url).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.projectIds).toEqual([]);
    expect(res.body.vulnerabilities).toEqual([]);
    expect(coreSpy).not.toHaveBeenCalled();
  });
});

describe('assembleFindingsBundle — the shared engine', () => {
  it('merges all slices, stamps project_id/name/framework, isolates a per-project failure', async () => {
    // A succeeds with one row in each fan-in slice; B rejects entirely.
    jest.spyOn(projectFindings, 'buildProjectFindingsCoreUnchecked').mockImplementation(async (_org, pid: string) => {
      if (pid === 'B') throw new Error('boom');
      return {
        ...emptyCore(),
        secrets: [{ id: 'sec-A' }],
        semgrep: [{ id: 'sg-A' }],
        iac: [{ id: 'iac-A', framework: 'terraform' }], // IaC rule framework must survive
        container: [{ id: 'cf-A' }],
        malicious: [{ id: 'mal-A' }],
        codeFlows: [{ id: 'flow-A' }],
        dast: [{ id: 'dast-A' }],
        baseImageRecs: [{ id: 'rec-A' }],
      };
    });

    const bundle = await assembleFindingsBundle(
      'org-A',
      [
        { id: 'A', name: 'Proj A', framework: 'node', active_extraction_run_id: 'rA' },
        { id: 'B', name: 'Proj B', framework: 'go', active_extraction_run_id: 'rB' },
      ],
      { scope: 'org', skipVulns: true },
    );

    // Every fan-in slice flowed A's row through the merge.
    for (const s of ['secrets', 'semgrep', 'iac', 'container', 'malicious', 'codeFlows', 'dast', 'baseImageRecs'] as const) {
      expect((bundle as any)[s]).toHaveLength(1);
      expect((bundle as any)[s][0].project_id).toBe('A');
      expect((bundle as any)[s][0].project_name).toBe('Proj A');
      expect((bundle as any)[s][0].project_framework).toBe('node');
    }
    // IaC's own `framework` field is NOT clobbered by the project_framework stamp.
    expect(bundle.iac[0].framework).toBe('terraform');
    expect(bundle.iac[0].project_framework).toBe('node');
    // B failed → zero B rows anywhere + a per-project degraded marker.
    expect(bundle.degradedSlices).toContain('B:project');
    expect(bundle.secrets.some((r: any) => r.project_id === 'B')).toBe(false);
    // projectIds reflects the input set (both attempted).
    expect(bundle.projectIds.sort()).toEqual(['A', 'B']);
  });

  it('empty input → well-formed empty bundle, no per-project reads', async () => {
    const coreSpy = jest.spyOn(projectFindings, 'buildProjectFindingsCoreUnchecked').mockResolvedValue(emptyCore());
    const bundle = await assembleFindingsBundle('org-A', [], { scope: 'org' });
    for (const k of ['vulnerabilities', 'secrets', 'semgrep', 'iac', 'container', 'malicious', 'codeFlows', 'dast', 'baseImageRecs', 'trackerLinks', 'groupSuppressions', 'acknowledgements']) {
      expect((bundle as any)[k]).toEqual([]);
    }
    expect(bundle.projectIds).toEqual([]);
    expect(bundle.degradedSlices).toEqual([]);
    expect(coreSpy).not.toHaveBeenCalled();
  });
});
