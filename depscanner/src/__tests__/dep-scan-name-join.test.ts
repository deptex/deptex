/**
 * Regression tests for the VDR-vuln → project_dependencies name join
 * (dep-scan.ts). The VDR `affects[].ref` purl carries the registry-normalized
 * (lowercase / PEP-503) name, while a project_dependencies row keeps the name
 * cdxgen read verbatim from the manifest (e.g. requirements.txt `Werkzeug`,
 * `Flask-SQLAlchemy`). A case-sensitive join silently drops EVERY CVE on a
 * capitalized/underscore-declared PyPI package — Flask/Werkzeug/Jinja2/
 * SQLAlchemy/Pillow/PyYAML/… — a false-negative. These lock in the
 * normalized fallback that recovers them without regressing exact matches.
 */

import {
  normalizeDepName,
  resolveDualScopePdMap,
  resolveDualScopePdMapNormalized,
  type DualScopePdRow,
} from '../pipeline-steps/dep-scan';

describe('normalizeDepName', () => {
  it('lowercases and PEP-503-collapses separators for pypi', () => {
    expect(normalizeDepName('Werkzeug', 'pypi')).toBe('werkzeug');
    expect(normalizeDepName('Flask-SQLAlchemy', 'pypi')).toBe('flask-sqlalchemy');
    // PEP 503: runs of -, _, . are equivalent → single '-'.
    expect(normalizeDepName('Flask_SQLAlchemy', 'pypi')).toBe('flask-sqlalchemy');
    expect(normalizeDepName('zope.interface', 'pypi')).toBe('zope-interface');
  });

  it('only lowercases for non-pypi ecosystems (npm names are separator-sensitive)', () => {
    expect(normalizeDepName('My-Pkg', 'npm')).toBe('my-pkg');
    // npm treats a_b, a-b, a.b as DISTINCT packages — must NOT collapse.
    expect(normalizeDepName('a_b', 'npm')).toBe('a_b');
    expect(normalizeDepName('Group:Artifact', 'maven')).toBe('group:artifact');
  });
});

describe('resolveDualScopePdMap (exact) vs resolveDualScopePdMapNormalized (fallback)', () => {
  const rows: DualScopePdRow[] = [
    { id: 'id-wz', name: 'Werkzeug', version: '2.0.1', environment: 'prod' },
    { id: 'id-req', name: 'requests', version: '2.26.0', environment: 'prod' },
  ];

  it('exact map keys on the verbatim manifest name and misses the lowercase purl name (the bug)', () => {
    const exact = resolveDualScopePdMap(rows);
    expect(exact.get('Werkzeug@2.0.1')).toBe('id-wz');
    expect(exact.get('werkzeug@2.0.1')).toBeUndefined();
  });

  it('normalized map recovers a capitalized package via its lowercase purl name', () => {
    const norm = resolveDualScopePdMapNormalized(rows, 'pypi');
    expect(norm.get('werkzeug@2.0.1')).toBe('id-wz');
    // already-lowercase packages still resolve.
    expect(norm.get('requests@2.26.0')).toBe('id-req');
  });

  it('normalized map preserves the prod-scope-wins preference for dual-scope rows', () => {
    const dual: DualScopePdRow[] = [
      { id: 'id-dev', name: 'Jinja2', version: '3.0.1', environment: 'dev' },
      { id: 'id-prod', name: 'Jinja2', version: '3.0.1', environment: 'prod' },
    ];
    expect(resolveDualScopePdMapNormalized(dual, 'pypi').get('jinja2@3.0.1')).toBe('id-prod');
  });
});
