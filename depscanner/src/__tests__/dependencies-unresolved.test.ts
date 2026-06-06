/**
 * Hard-fail-on-unresolved-dependencies — unit tests.
 *
 * When cdxgen produces an empty SBOM AND the project actually declared
 * dependencies, the SBOM step throws (the scan goes to 'error' with a
 * user-facing "fix your manifest" message) instead of silently degrading to a
 * dependency-less "all clear". `npmManifestDeclaresDependencies` is the decision
 * that separates a real resolution failure (declared deps, resolved none) from a
 * legitimately zero-dependency project (no error). npm is the special case: one
 * unpublished dep (e.g. event-stream@3.3.6) aborts the whole `npm install`, so a
 * lockfile-less npm project zeroes its SBOM with rawComponentCount === 0 — the
 * only signal left is the declared-dependency count.
 */

// fs is module-mocked (the worker test convention — jest.spyOn can't redefine
// fs methods in this config). `mock`-prefixed vars are allowed inside the
// jest.mock factory by jest's hoisting rules.
let mockFsContent = '';
let mockFsThrows = false;
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn(() => {
    if (mockFsThrows) throw new Error('ENOENT: no such file');
    return mockFsContent;
  }),
}));

import { npmManifestDeclaresDependencies } from '../sbom';

describe('npmManifestDeclaresDependencies', () => {
  beforeEach(() => {
    mockFsThrows = false;
    mockFsContent = '';
  });

  it('returns true when the manifest declares prod deps — even with an unresolvable one present', () => {
    // The express dogfood fixture: event-stream@3.3.6 is unpublished and zeroes
    // the SBOM, but the manifest clearly declared real dependencies → fail loudly.
    mockFsContent = JSON.stringify({
      name: 'dogfood-express',
      dependencies: { express: '4.18.2', lodash: '4.17.20', 'event-stream': '3.3.6' },
    });
    expect(npmManifestDeclaresDependencies('/ws')).toBe(true);
  });

  it('returns true for dev / optional / peer dependency blocks alone', () => {
    for (const field of ['devDependencies', 'optionalDependencies', 'peerDependencies']) {
      mockFsContent = JSON.stringify({ name: 'x', [field]: { jest: '^29.0.0' } });
      expect(npmManifestDeclaresDependencies('/ws')).toBe(true);
    }
  });

  it('returns false for a manifest that declares zero dependencies (a legitimate zero-dep project)', () => {
    mockFsContent = JSON.stringify({ name: 'x', version: '1.0.0', dependencies: {}, devDependencies: {} });
    expect(npmManifestDeclaresDependencies('/ws')).toBe(false);
  });

  it('returns false for a manifest with no dependency blocks at all', () => {
    mockFsContent = JSON.stringify({ name: 'x', version: '1.0.0', scripts: { start: 'node .' } });
    expect(npmManifestDeclaresDependencies('/ws')).toBe(false);
  });

  it('returns false on malformed JSON (do not fail-hard on a parse error)', () => {
    mockFsContent = '{ this is not json';
    expect(npmManifestDeclaresDependencies('/ws')).toBe(false);
  });

  it('returns false when package.json is missing (read throws)', () => {
    mockFsThrows = true;
    expect(npmManifestDeclaresDependencies('/ws')).toBe(false);
  });
});
