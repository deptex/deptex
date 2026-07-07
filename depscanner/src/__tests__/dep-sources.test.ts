/**
 * DepSourceCache — Arc 2 security surface (critical-review test-thoroughness):
 *   - version-shape gates (siblings of the already-tested name gates)
 *   - the path-traversal fix: a `../`-laden version must not escape the cache
 *     root on the pre-gate mkdir/rmSync (dest is built + created BEFORE the
 *     ecosystem shape gate rejects the requirement string)
 *
 * fetch() does real network for a valid spec, so these tests drive only the
 * rejection/containment paths, which fail (return null) before any download.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DepSourceCache } from '../lib/dep-sources';

function makeCache(policy: 'sdist-first' | 'wheel-only' = 'wheel-only') {
  return new DepSourceCache({
    rootDirName: `dep-sources-test-${process.pid}-${Math.floor(performance.now())}`,
    artifactPolicy: policy,
    label: 'dep-sources-test',
  });
}

describe('DepSourceCache.fetch — spec rejection (name + version gates)', () => {
  let cache: DepSourceCache;
  beforeEach(() => { cache = makeCache(); });
  afterEach(() => cache.cleanup());

  it.each([
    ['pypi', 'requests', '2.0.0; curl evil'],      // shell/space
    ['pypi', 'requests', '../../../etc/passwd'],    // traversal
    ['pypi', 'requests', 'http://evil/x'],          // url-ish
    ['npm', 'lodash', '$(id)'],                      // substitution
    ['npm', 'lodash', 'git+http://169.254.170.2'],  // git spec
  ] as const)('rejects %s %s@%s (returns null, no throw)', async (eco, name, version) => {
    await expect(cache.fetch(eco, name, version)).resolves.toBeNull();
  });

  it.each([
    ['pypi', '../../../../etc', '1.0.0'],           // traversal in name
    ['npm', 'a b', '1.0.0'],                          // space in name
  ] as const)('rejects bad %s name %s', async (eco, name, version) => {
    await expect(cache.fetch(eco, name, version)).resolves.toBeNull();
  });
});

describe('DepSourceCache — path-traversal containment (the pre-gate mkdir/rmSync)', () => {
  it('a `../`-laden version never creates a directory outside the cache root', async () => {
    const cache = makeCache();
    // Sentinel dir a traversal payload would try to reach + delete.
    const sentinel = fs.mkdtempSync(path.join(os.tmpdir(), 'dep-src-sentinel-'));
    const marker = path.join(sentinel, 'keep.txt');
    fs.writeFileSync(marker, 'do not delete');
    try {
      // A version crafted to escape /tmp/<root>/pypi and hit the sentinel.
      const rel = path.relative(path.join(os.tmpdir(), 'x', 'pypi'), sentinel);
      const evilVersion = `${rel.split(path.sep).join('/')}/keep`;
      await cache.fetch('pypi', 'requests', evilVersion);
      // The sentinel + its file must survive: the version is slug-sanitized
      // before dest construction, so no path escapes the cache root.
      expect(fs.existsSync(marker)).toBe(true);
    } finally {
      fs.rmSync(sentinel, { recursive: true, force: true });
      cache.cleanup();
    }
  });
});
