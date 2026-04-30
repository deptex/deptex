import { crossLinkFinding } from '../dast/pipeline';
import type { DastFindingRaw } from '../dast/runner';

function rawFinding(overrides: Partial<DastFindingRaw> = {}): DastFindingRaw {
  return {
    endpoint_url: 'https://target.example.com/api/users/42',
    http_method: 'GET',
    vulnerability_type: 'SQL Injection',
    severity: 'high',
    cwe_id: '89',
    owasp_top10_ref: 'A03:2021',
    rule_id: '40018-1',
    message: 'SQLi found',
    payload_redacted: null,
    response_evidence_redacted: null,
    confidence: 'medium',
    ...overrides,
  };
}

describe('crossLinkFinding', () => {
  it('returns "none" when no entry points match the URL', () => {
    const out = crossLinkFinding({
      finding: rawFinding(),
      entryPoints: [
        {
          framework: 'express',
          http_method: 'GET',
          route_pattern: '/different/route',
          handler_name: 'h',
          file_path: 'src/handler.ts',
          line_number: 10,
        },
      ],
      flows: [],
      pdvByPurl: new Map(),
      projectDependencyByPurl: new Map(),
    });
    expect(out.handler_file_path).toBeNull();
    expect(out.linked_sca_osv_id).toBeNull();
    expect(out.cross_link_metadata.match_method).toBe('none');
  });

  it('returns "route_only" when a route matches but no flow does', () => {
    const out = crossLinkFinding({
      finding: rawFinding(),
      entryPoints: [
        {
          framework: 'express',
          http_method: 'GET',
          route_pattern: '/api/users/:id',
          handler_name: 'getUser',
          file_path: 'src/handlers/users.ts',
          line_number: 25,
        },
      ],
      flows: [],
      pdvByPurl: new Map(),
      projectDependencyByPurl: new Map(),
    });
    expect(out.handler_file_path).toBe('src/handlers/users.ts');
    expect(out.handler_function_name).toBe('getUser');
    expect(out.handler_line).toBe(25);
    expect(out.linked_sca_osv_id).toBeNull();
    expect(out.cross_link_metadata.match_method).toBe('route_only');
  });

  it('returns "route_and_flow_no_vuln" when handler has a flow but the dep has no PDV', () => {
    const out = crossLinkFinding({
      finding: rawFinding(),
      entryPoints: [
        {
          framework: 'express',
          http_method: 'GET',
          route_pattern: '/api/users/:id',
          handler_name: 'getUser',
          file_path: 'src/handlers/users.ts',
          line_number: 25,
        },
      ],
      flows: [
        {
          entry_point_file: 'src/handlers/users.ts',
          entry_point_method: 'getUser',
          purl: 'pkg:npm/lodash@4.17.21',
          dependency_id: null,
        },
      ],
      pdvByPurl: new Map(),
      projectDependencyByPurl: new Map(),
    });
    expect(out.handler_file_path).toBe('src/handlers/users.ts');
    expect(out.linked_sca_osv_id).toBeNull();
    expect(out.cross_link_metadata.match_method).toBe('route_and_flow_no_vuln');
  });

  it('returns full SCA link when handler+flow+PDV chain completes', () => {
    const purl = 'pkg:npm/mysql2@2.3.0';
    const out = crossLinkFinding({
      finding: rawFinding(),
      entryPoints: [
        {
          framework: 'express',
          http_method: 'GET',
          route_pattern: '/api/users/:id',
          handler_name: 'getUser',
          file_path: 'src/handlers/users.ts',
          line_number: 25,
        },
      ],
      flows: [
        {
          entry_point_file: 'src/handlers/users.ts',
          entry_point_method: 'getUser',
          purl,
          dependency_id: 'dep-1',
        },
      ],
      pdvByPurl: new Map([
        [
          purl,
          [
            { id: 'pdv-1', project_dependency_id: 'pd-1', osv_id: 'CVE-2021-1234' },
          ],
        ],
      ]),
      projectDependencyByPurl: new Map([
        [
          purl,
          { id: 'pd-1', dependency_id: 'dep-1', purl },
        ],
      ]),
    });
    expect(out.linked_sca_osv_id).toBe('CVE-2021-1234');
    expect(out.linked_sca_project_dependency_id).toBe('pd-1');
    expect(out.cross_link_metadata.match_method).toBe('route_flow_vuln');
  });

  it('respects HTTP-method filter on entry points', () => {
    const out = crossLinkFinding({
      finding: rawFinding({ http_method: 'POST' }),
      entryPoints: [
        {
          framework: 'express',
          http_method: 'GET',
          route_pattern: '/api/users/:id',
          handler_name: 'getUser',
          file_path: 'src/handlers/users.ts',
          line_number: 25,
        },
      ],
      flows: [],
      pdvByPurl: new Map(),
      projectDependencyByPurl: new Map(),
    });
    expect(out.handler_file_path).toBeNull();
    expect(out.cross_link_metadata.match_method).toBe('none');
  });

  it('matches across multiple frameworks when first one fails', () => {
    const out = crossLinkFinding({
      finding: rawFinding({ endpoint_url: '/items/9' }),
      entryPoints: [
        // First: express with mismatching pattern
        {
          framework: 'express',
          http_method: 'GET',
          route_pattern: '/different',
          handler_name: 'no',
          file_path: 'a.ts',
          line_number: 1,
        },
        // Second: fastapi-style brace match
        {
          framework: 'fastapi',
          http_method: 'GET',
          route_pattern: '/items/{id}',
          handler_name: 'getItem',
          file_path: 'app/items.py',
          line_number: 50,
        },
      ],
      flows: [],
      pdvByPurl: new Map(),
      projectDependencyByPurl: new Map(),
    });
    expect(out.handler_file_path).toBe('app/items.py');
    expect(out.handler_function_name).toBe('getItem');
  });

  it('picks worst-severity PDV when multiple vulns exist', () => {
    const purl = 'pkg:npm/lodash@4.17.20';
    const out = crossLinkFinding({
      finding: rawFinding(),
      entryPoints: [
        {
          framework: 'express',
          http_method: 'GET',
          route_pattern: '/api/users/:id',
          handler_name: 'h',
          file_path: 'a.ts',
          line_number: 1,
        },
      ],
      flows: [{ entry_point_file: 'a.ts', entry_point_method: 'h', purl, dependency_id: null }],
      pdvByPurl: new Map([
        [
          purl,
          [
            { id: 'pdv-low', project_dependency_id: 'pd-1', osv_id: 'CVE-2020-LOW', severity: 'low' } as any,
            { id: 'pdv-crit', project_dependency_id: 'pd-1', osv_id: 'CVE-2020-CRIT', severity: 'critical' } as any,
            { id: 'pdv-med', project_dependency_id: 'pd-1', osv_id: 'CVE-2020-MED', severity: 'medium' } as any,
          ],
        ],
      ]),
      projectDependencyByPurl: new Map([[purl, { id: 'pd-1', dependency_id: 'd-1', purl }]]),
    });
    expect(out.linked_sca_osv_id).toBe('CVE-2020-CRIT');
  });

  it('handles entry point with NULL handler_name (matches any method on file)', () => {
    const purl = 'pkg:npm/x@1';
    const out = crossLinkFinding({
      finding: rawFinding(),
      entryPoints: [
        {
          framework: 'express',
          http_method: 'GET',
          route_pattern: '/api/users/:id',
          handler_name: null,
          file_path: 'src/handler.ts',
          line_number: 5,
        },
      ],
      flows: [
        {
          entry_point_file: 'src/handler.ts',
          entry_point_method: 'arbitrary',
          purl,
          dependency_id: null,
        },
      ],
      pdvByPurl: new Map([
        [
          purl,
          [{ id: 'pdv-1', project_dependency_id: 'pd-1', osv_id: 'CVE-X' }],
        ],
      ]),
      projectDependencyByPurl: new Map([[purl, { id: 'pd-1', dependency_id: 'd-1', purl }]]),
    });
    expect(out.linked_sca_osv_id).toBe('CVE-X');
  });
});
