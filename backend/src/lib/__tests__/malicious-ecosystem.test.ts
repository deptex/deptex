import {
  canonicalizeEcosystem,
  canonicalizePackageName,
  isCanonicalEcosystem,
  CANONICAL_ECOSYSTEMS,
} from '../malicious/ecosystem';

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

  // v2 widened the canonical set to 10 ecosystems for 8-language detector parity.
  it.each([
    ['composer', 'composer'],
    ['packagist', 'composer'],
    ['php', 'composer'],
    ['cargo', 'cargo'],
    ['rust', 'cargo'],
    ['crates.io', 'cargo'],
    ['nuget', 'nuget'],
    ['csharp', 'nuget'],
    ['dotnet', 'nuget'],
    ['.net', 'nuget'],
  ])('v2-added ecosystem %s -> %s', (raw, expected) => {
    expect(canonicalizeEcosystem(raw)).toBe(expected);
  });

  it('whitespace is trimmed before lookup', () => {
    expect(canonicalizeEcosystem('  npm  ')).toBe('npm');
    expect(canonicalizeEcosystem(' RubyGems ')).toBe('rubygems');
  });

  it('returns null for unknown ecosystems instead of guessing', () => {
    expect(canonicalizeEcosystem('hex')).toBeNull();      // Elixir — not yet supported
    expect(canonicalizeEcosystem('pub')).toBeNull();      // Dart — not yet supported
    expect(canonicalizeEcosystem('')).toBeNull();
    expect(canonicalizeEcosystem(null)).toBeNull();
    expect(canonicalizeEcosystem(undefined)).toBeNull();
  });
});

describe('canonicalizePackageName', () => {
  // PEP 503 — lowercase + collapse [-_.]+ to '-'. Drives the P0 fix:
  // GHSA stores `Django` / `Pillow` / `BeautifulSoup`; cdxgen's PURL output
  // produces `django` / `pillow` / `beautifulsoup4`. Without per-ecosystem
  // normalization on both write and read paths, the lookup misses entirely.
  it.each([
    ['Django', 'django'],
    ['BeautifulSoup4', 'beautifulsoup4'],
    ['PyYAML', 'pyyaml'],
    ['Foo_Bar', 'foo-bar'],
    ['foo.bar', 'foo-bar'],
    ['Foo--Bar', 'foo-bar'],
    ['django', 'django'],
  ])('pypi: %s -> %s', (input, expected) => {
    expect(canonicalizePackageName(input, 'pypi')).toBe(expected);
  });

  // npm/nuget/composer/cargo/vscode: lowercase per registry-canonical form.
  it.each([
    ['npm' as const, 'MyPkg', 'mypkg'],
    ['npm' as const, '@Scope/Pkg', '@scope/pkg'],
    ['nuget' as const, 'Newtonsoft.Json', 'newtonsoft.json'],
    ['composer' as const, 'Vendor/Package', 'vendor/package'],
    ['cargo' as const, 'My_Crate', 'my_crate'],
    ['vscode' as const, 'MS.python', 'ms.python'],
  ])('%s: %s -> %s (lowercase only, separators preserved)', (eco, input, expected) => {
    expect(canonicalizePackageName(input, eco)).toBe(expected);
  });

  // Case-sensitive ecosystems: preserve as-is.
  it.each([
    ['maven' as const, 'com.Example:Lib', 'com.Example:Lib'],
    ['golang' as const, 'github.com/Foo/Bar', 'github.com/Foo/Bar'],
    ['rubygems' as const, 'Ruby_OS_Detector', 'Ruby_OS_Detector'],
    ['github-actions' as const, 'Owner/Repo', 'Owner/Repo'],
  ])('%s preserves case: %s -> %s', (eco, input, expected) => {
    expect(canonicalizePackageName(input, eco)).toBe(expected);
  });

  it('matches advisory and SBOM names that differ only in PyPI normalization', () => {
    // Advisory writer (feed-sync) and lookup (lookupFeed) both apply this —
    // matching transforms on both sides preserve the equality, regardless of
    // upstream casing.
    const advisoryName = 'Django';
    const sbomName = 'django';
    expect(canonicalizePackageName(advisoryName, 'pypi'))
      .toBe(canonicalizePackageName(sbomName, 'pypi'));
  });
});

describe('isCanonicalEcosystem', () => {
  it('accepts every CANONICAL_ECOSYSTEMS member', () => {
    for (const eco of CANONICAL_ECOSYSTEMS) {
      expect(isCanonicalEcosystem(eco)).toBe(true);
    }
  });

  it('rejects non-canonical values', () => {
    expect(isCanonicalEcosystem('gem')).toBe(false);     // alias, not canonical
    expect(isCanonicalEcosystem('NPM')).toBe(false);     // canonical is lowercase
    expect(isCanonicalEcosystem('php')).toBe(false);     // alias for composer, not canonical
    expect(isCanonicalEcosystem('rust')).toBe(false);    // alias for cargo, not canonical
    expect(isCanonicalEcosystem('hex')).toBe(false);     // unsupported ecosystem
  });
});
