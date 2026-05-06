import {
  parseGhsaRange,
  resolveVulnerableRange,
  makePackumentCache,
  type PackumentCache,
} from '../malicious/version-range';

// ─── parser ────────────────────────────────────────────────────────────────

describe('parseGhsaRange', () => {
  it.each([
    // Bare exact version (no operator)
    ['2.10.1',           [{ op: '=',  version: '2.10.1' }]],
    ['1.0.0-beta.2',     [{ op: '=',  version: '1.0.0-beta.2' }]],

    // Single operator
    ['= 2.10.1',         [{ op: '=',  version: '2.10.1' }]],
    ['=2.10.1',          [{ op: '=',  version: '2.10.1' }]],
    ['< 2.0.0',          [{ op: '<',  version: '2.0.0' }]],
    ['<2.0.0',           [{ op: '<',  version: '2.0.0' }]],
    ['>= 0',             [{ op: '>=', version: '0' }]],
    ['<= 1.5.0',         [{ op: '<=', version: '1.5.0' }]],
    ['> 1.0',            [{ op: '>',  version: '1.0' }]],

    // AND-combined
    ['>= 1.0, < 2.0',    [{ op: '>=', version: '1.0' }, { op: '<', version: '2.0' }]],
    ['>=1.0,<2.0',       [{ op: '>=', version: '1.0' }, { op: '<', version: '2.0' }]],
    ['> 0.0.0, < 1.0.0', [{ op: '>',  version: '0.0.0' }, { op: '<', version: '1.0.0' }]],
  ])('parses %s', (raw, expected) => {
    expect(parseGhsaRange(raw as string)).toEqual(expected);
  });

  it('returns null for empty / whitespace / non-strings', () => {
    expect(parseGhsaRange('')).toBeNull();
    expect(parseGhsaRange('   ')).toBeNull();
    expect(parseGhsaRange(null as any)).toBeNull();
    expect(parseGhsaRange(undefined as any)).toBeNull();
  });

  it('returns null for ranges with unknown operators', () => {
    expect(parseGhsaRange('~> 1.0.0')).toBeNull();
    expect(parseGhsaRange('^1.2.3')).toBeNull();
    expect(parseGhsaRange('!= 1.0.0')).toBeNull();
  });
});

// ─── resolver dispatch (exact-match shortcut) ──────────────────────────────

describe('resolveVulnerableRange — exact-match shortcut', () => {
  let cache: PackumentCache;
  beforeEach(() => { cache = makePackumentCache(); });

  it.each(['npm', 'pypi', 'maven', 'golang', 'rubygems'] as const)(
    '%s exact = X.Y.Z bypasses registry call and returns single version',
    async (eco) => {
      const got = await resolveVulnerableRange(eco, 'any-pkg', '= 1.2.3', cache);
      expect(got).toEqual(['1.2.3']);
      // exact match should not warm the cache (no registry call needed)
      expect(cache.size).toBe(0);
    },
  );

  it.each(['npm', 'pypi', 'maven', 'golang', 'rubygems'] as const)(
    '%s bare X.Y.Z bypasses registry call too',
    async (eco) => {
      const got = await resolveVulnerableRange(eco, 'any-pkg', '4.17.20', cache);
      expect(got).toEqual(['4.17.20']);
    },
  );
});

describe('resolveVulnerableRange — unparseable input', () => {
  it('returns null for ranges the parser rejects', async () => {
    const cache = makePackumentCache();
    expect(await resolveVulnerableRange('npm', 'left-pad', '~> 1.0.0', cache)).toBeNull();
    expect(await resolveVulnerableRange('pypi', 'requests', '!= 1.0', cache)).toBeNull();
  });
});

describe('resolveVulnerableRange — maven/golang fall back', () => {
  it('maven returns null for non-exact ranges (parse-only ecosystem)', async () => {
    const cache = makePackumentCache();
    const got = await resolveVulnerableRange('maven', 'org.apache:commons-text', '< 1.10.0', cache);
    expect(got).toBeNull();
  });

  it('golang returns null for non-exact ranges (parse-only ecosystem)', async () => {
    const cache = makePackumentCache();
    const got = await resolveVulnerableRange('golang', 'github.com/foo/bar', '>= 0.1, < 0.2', cache);
    expect(got).toBeNull();
  });
});

// ─── npm resolver (mocked pacote) ──────────────────────────────────────────

jest.mock('pacote', () => ({
  packument: jest.fn(),
}));

describe('resolveVulnerableRange — npm with mocked registry', () => {
  let cache: PackumentCache;
  let pacote: any;
  beforeEach(() => {
    cache = makePackumentCache();
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    pacote = require('pacote');
    pacote.packument.mockReset();
    pacote.packument.mockResolvedValue({
      versions: {
        '0.9.0': {}, '1.0.0': {}, '1.0.1': {}, '1.5.0': {},
        '2.0.0': {}, '2.0.1': {}, '2.10.1': {}, '3.0.0-rc.1': {},
      },
    });
  });

  it('< 2.0.0 keeps 0.9.0/1.0.0/1.0.1/1.5.0', async () => {
    const got = await resolveVulnerableRange('npm', 'lodash', '< 2.0.0', cache);
    expect(new Set(got)).toEqual(new Set(['0.9.0', '1.0.0', '1.0.1', '1.5.0']));
  });

  it('>= 1.0.0, < 2.0.0 keeps the 1.x band', async () => {
    const got = await resolveVulnerableRange('npm', 'lodash', '>= 1.0.0, < 2.0.0', cache);
    expect(new Set(got)).toEqual(new Set(['1.0.0', '1.0.1', '1.5.0']));
  });

  it('>= 0 with semver coerce sweeps every version', async () => {
    const got = await resolveVulnerableRange('npm', 'lodash', '>= 0', cache);
    expect(got).not.toBeNull();
    // the prerelease 3.0.0-rc.1 is included with includePrerelease:true
    expect(got!.length).toBeGreaterThanOrEqual(7);
  });

  it('per-package cache memoises packument fetch across calls', async () => {
    await resolveVulnerableRange('npm', 'lodash', '< 1.0.0', cache);
    await resolveVulnerableRange('npm', 'lodash', '>= 2.0.0', cache);
    await resolveVulnerableRange('npm', 'lodash', '= 1.5.0', cache);  // hits shortcut, no fetch
    expect(pacote.packument).toHaveBeenCalledTimes(1);
  });

  it('returns null when packument fetch fails', async () => {
    pacote.packument.mockRejectedValueOnce(new Error('npm 404'));
    const got = await resolveVulnerableRange('npm', 'does-not-exist', '< 1.0', cache);
    expect(got).toBeNull();
  });
});

// ─── pypi resolver (mocked fetch) ──────────────────────────────────────────

describe('resolveVulnerableRange — pypi with mocked PyPI JSON', () => {
  let cache: PackumentCache;
  let originalFetch: typeof fetch;

  beforeEach(() => {
    cache = makePackumentCache();
    originalFetch = global.fetch;
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        releases: {
          '0.9.0':  [{}],
          '1.0.0':  [{}],
          '1.0.1':  [{}],
          '1.5.0':  [{}],
          '2.0.0':  [{}],
          '2.0.0rc1': [{}],
          '2.0.0.post1': [{}],
          '2.1.0':  [{}],
          // unreleased / yanked: empty file array → skipped
          '9.9.9':  [],
        },
      }),
    }) as any;
  });
  afterEach(() => { global.fetch = originalFetch; });

  it('< 2.0.0 keeps the 1.x band and the rc1 prerelease', async () => {
    const got = await resolveVulnerableRange('pypi', 'requests', '< 2.0.0', cache);
    expect(got).not.toBeNull();
    expect(got!).toEqual(expect.arrayContaining(['0.9.0', '1.0.0', '1.0.1', '1.5.0', '2.0.0rc1']));
    expect(got!).not.toContain('2.0.0');
    expect(got!).not.toContain('2.0.0.post1');
    expect(got!).not.toContain('9.9.9');
  });

  it('>= 1.0.0, < 2.0.0 keeps the 1.x band plus the 2.0.0 release candidate', async () => {
    // PEP 440: 2.0.0rc1 < 2.0.0, so it falls inside the half-open range.
    // (semver's npm-style "exclude pre-releases by default" rule does NOT apply here.)
    const got = await resolveVulnerableRange('pypi', 'requests', '>= 1.0.0, < 2.0.0', cache);
    expect(got).not.toBeNull();
    expect(new Set(got)).toEqual(new Set(['1.0.0', '1.0.1', '1.5.0', '2.0.0rc1']));
  });

  it('returns null when PyPI 404s', async () => {
    (global.fetch as any).mockResolvedValueOnce({ ok: false, status: 404 });
    const got = await resolveVulnerableRange('pypi', 'does-not-exist', '< 1.0', cache);
    expect(got).toBeNull();
  });
});

// ─── rubygems resolver (mocked fetch) ──────────────────────────────────────

describe('resolveVulnerableRange — rubygems with mocked rubygems.org', () => {
  let cache: PackumentCache;
  let originalFetch: typeof fetch;

  beforeEach(() => {
    cache = makePackumentCache();
    originalFetch = global.fetch;
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => [
        { number: '0.9.0' },
        { number: '1.0.0' },
        { number: '1.5.0' },
        { number: '2.0.0.alpha' },
        { number: '2.0.0' },
        { number: '2.1.0' },
      ],
    }) as any;
  });
  afterEach(() => { global.fetch = originalFetch; });

  it('< 2.0.0 keeps 0.9.0 / 1.0.0 / 1.5.0 plus the prerelease alpha', async () => {
    const got = await resolveVulnerableRange('rubygems', 'rails', '< 2.0.0', cache);
    expect(got).not.toBeNull();
    expect(got!).toEqual(expect.arrayContaining(['0.9.0', '1.0.0', '1.5.0', '2.0.0.alpha']));
    expect(got!).not.toContain('2.0.0');
    expect(got!).not.toContain('2.1.0');
  });

  it('>= 1.0.0, < 2.0.0 keeps 1.0.0 / 1.5.0 plus the 2.0.0 alpha', async () => {
    // Gem::Version: '2.0.0.alpha' < '2.0.0' so the alpha is inside the half-open range.
    const got = await resolveVulnerableRange('rubygems', 'rails', '>= 1.0.0, < 2.0.0', cache);
    expect(new Set(got)).toEqual(new Set(['1.0.0', '1.5.0', '2.0.0.alpha']));
  });
});
