import { canonicalizeEcosystem, isCanonicalEcosystem, CANONICAL_ECOSYSTEMS } from '../malicious/ecosystem';

describe('canonicalizeEcosystem', () => {
  // OSV.dev casing (https://ossf.github.io/osv-schema/) -> canonical
  it.each([
    ['npm', 'npm'],
    ['PyPI', 'pypi'],
    ['Maven', 'maven'],
    ['Go', 'golang'],
    ['RubyGems', 'rubygems'],
    ['GitHub Actions', 'github-actions'],
  ])('OSV %s -> %s', (raw, expected) => {
    expect(canonicalizeEcosystem(raw)).toBe(expected);
  });

  // GHSA enum (uppercase) -> canonical
  it.each([
    ['NPM', 'npm'],
    ['PIP', 'pypi'],
    ['MAVEN', 'maven'],
    ['GO', 'golang'],
    ['RUBYGEMS', 'rubygems'],
  ])('GHSA %s -> %s', (raw, expected) => {
    expect(canonicalizeEcosystem(raw)).toBe(expected);
  });

  // GuardDog flag spellings -> canonical
  it.each([
    ['npm', 'npm'],
    ['pypi', 'pypi'],
    ['maven', 'maven'],
    ['go', 'golang'],
    ['rubygems', 'rubygems'],
    ['github-action', 'github-actions'], // GuardDog ships singular
    ['vscode', 'vscode'],
  ])('GuardDog %s -> %s', (raw, expected) => {
    expect(canonicalizeEcosystem(raw)).toBe(expected);
  });

  // Deptex-internal `dependencies.ecosystem` values -> canonical
  it.each([
    ['npm', 'npm'],
    ['pypi', 'pypi'],
    ['maven', 'maven'],
    ['golang', 'golang'],
    ['gem', 'rubygems'], // internal `gem` matches feed-side `rubygems`
  ])('internal Deptex %s -> %s', (raw, expected) => {
    expect(canonicalizeEcosystem(raw)).toBe(expected);
  });

  it('whitespace is trimmed before lookup', () => {
    expect(canonicalizeEcosystem('  npm  ')).toBe('npm');
    expect(canonicalizeEcosystem(' RubyGems ')).toBe('rubygems');
  });

  it('returns null for unknown ecosystems instead of guessing', () => {
    expect(canonicalizeEcosystem('cargo')).toBeNull();
    expect(canonicalizeEcosystem('nuget')).toBeNull();
    expect(canonicalizeEcosystem('hex')).toBeNull();
    expect(canonicalizeEcosystem('')).toBeNull();
    expect(canonicalizeEcosystem(null)).toBeNull();
    expect(canonicalizeEcosystem(undefined)).toBeNull();
  });
});

describe('isCanonicalEcosystem', () => {
  it('accepts every CANONICAL_ECOSYSTEMS member', () => {
    for (const eco of CANONICAL_ECOSYSTEMS) {
      expect(isCanonicalEcosystem(eco)).toBe(true);
    }
  });

  it('rejects non-canonical values', () => {
    expect(isCanonicalEcosystem('gem')).toBe(false);
    expect(isCanonicalEcosystem('NPM')).toBe(false);
    expect(isCanonicalEcosystem('cargo')).toBe(false);
  });
});
