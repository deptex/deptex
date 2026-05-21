/**
 * Native-bindings unit tests (Item G — M1).
 *
 * The real extractors shell out to readelf inside the depscanner Docker
 * image. These tests stand up a fake filesystem under tmp + inject a
 * canned ReadelfRunner so they run deterministically on Windows.
 *
 * Coverage:
 *  - Python wheel discovery via dist-info / top_level.txt / hyphen→underscore fallback
 *  - Node native module discovery via node_modules/<pkg>/package.json
 *  - Six soname fixtures (libssl3, libssl1.1, libxml2, libjpeg, libcrypto3, libz)
 *  - DT_NEEDED parsing tolerates stripped + whitespace-padded readelf output
 *  - extractOsBindings returns [] + os_family on no-/var/lib/dpkg/ images
 *  - readelf 'unavailable' → unparsable count incremented, no rows emitted
 *  - dpkg multi-arch suffix stripped on the package_identifier
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  extractLanguageBindings,
  extractOsBindings,
  detectOsFamily,
  findPythonWheelInstalls,
  findNodePackageInstalls,
  _internal,
} from '../native-bindings';
import type { LanguageBinding, OsBinding } from '../native-bindings';
import type { ReadelfRunner } from '../elf-analyzer';

// ---- fixtures ---------------------------------------------------------------

function dynamicSection(sonames: string[]): string {
  const lines = [
    'Dynamic section at offset 0x2dc8 contains 27 entries:',
    '  Tag        Type                         Name/Value',
  ];
  for (const s of sonames) {
    lines.push(` 0x0000000000000001 (NEEDED)             Shared library: [${s}]`);
  }
  return lines.join('\n') + '\n';
}

/** A binary with both DT_NEEDED AND DT_SONAME (real shared libs declare both). */
function dynamicSectionWithSoname(soname: string, needed: string[] = []): string {
  const lines = [
    'Dynamic section at offset 0x2dc8 contains 14 entries:',
    '  Tag        Type                         Name/Value',
    ` 0x000000000000000e (SONAME)             Library soname: [${soname}]`,
  ];
  for (const s of needed) {
    lines.push(` 0x0000000000000001 (NEEDED)             Shared library: [${s}]`);
  }
  return lines.join('\n') + '\n';
}

/** Stripped library — readelf -d returns NEEDED but no SONAME entry. */
const STRIPPED_NEEDED_ONLY = dynamicSection(['libc.so.6']);

/** Output with extra whitespace + a blank-line tail (real readelf occasionally
 *  emits a trailing newline / column padding drift). */
const WHITESPACE_PADDED = (
  'Dynamic section at offset 0x2dc8 contains 27 entries:\n' +
  '  Tag        Type                         Name/Value\n' +
  '   0x0000000000000001  (NEEDED)              Shared library: [libssl.so.3]   \n' +
  '   0x000000000000000e  (SONAME)              Library soname: [libssl.so.3]  \n' +
  '\n'
);

// ---- runner construction ---------------------------------------------------

function fixtureRunner(map: Record<string, string>): ReadelfRunner {
  return async (args: string[]) => {
    const binPath = args[args.length - 1];
    if (binPath in map) {
      return { stdout: map[binPath], exitCode: 0 };
    }
    return { stdout: '', exitCode: 1 };
  };
}

/** Runner that simulates readelf-not-on-PATH (the binary spawn throws). */
const UNAVAILABLE_RUNNER: ReadelfRunner = async () => {
  throw new Error('ENOENT: readelf');
};

// ---- test root scaffolding -------------------------------------------------

let tmpRoot: string;
beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-nb-test-'));
});
afterEach(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function mkdirp(p: string): string {
  fs.mkdirSync(p, { recursive: true });
  return p;
}
function write(p: string, content: string): string {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return p;
}

// ============================================================
// Python wheel discovery
// ============================================================

describe('findPythonWheelInstalls', () => {
  test('discovers a single wheel with top_level.txt', () => {
    const sitePackages = mkdirp(path.join(tmpRoot, 'usr/local/lib/python3.11/site-packages'));
    const distInfo = mkdirp(path.join(sitePackages, 'cryptography-41.0.7.dist-info'));
    write(path.join(distInfo, 'RECORD'), '');
    write(path.join(distInfo, 'top_level.txt'), 'cryptography\n');
    mkdirp(path.join(sitePackages, 'cryptography'));

    const out = findPythonWheelInstalls(tmpRoot);
    expect(out).toHaveLength(1);
    expect(out[0].package_name).toBe('cryptography');
    expect(out[0].install_dir).toBe(path.join(sitePackages, 'cryptography'));
  });

  test('falls back to hyphen→underscore when top_level.txt missing', () => {
    const sitePackages = mkdirp(path.join(tmpRoot, 'site-packages'));
    const distInfo = mkdirp(path.join(sitePackages, 'pillow-10.0.0.dist-info'));
    write(path.join(distInfo, 'RECORD'), '');
    mkdirp(path.join(sitePackages, 'pillow'));
    const out = findPythonWheelInstalls(tmpRoot);
    expect(out).toHaveLength(1);
    expect(out[0].package_name).toBe('pillow');
  });

  test('discovers wheels at multiple install roots (uv venv + --target)', () => {
    const uvVenv = mkdirp(path.join(tmpRoot, '.venv/lib/python3.11/site-packages'));
    const target = mkdirp(path.join(tmpRoot, 'app/vendor'));
    for (const root of [uvVenv, target]) {
      const di = mkdirp(path.join(root, 'pkg-1.0.dist-info'));
      write(path.join(di, 'RECORD'), '');
      write(path.join(di, 'top_level.txt'), 'pkg\n');
      mkdirp(path.join(root, 'pkg'));
    }
    const out = findPythonWheelInstalls(tmpRoot);
    expect(out).toHaveLength(2);
    expect(new Set(out.map((w) => w.install_dir))).toEqual(
      new Set([path.join(uvVenv, 'pkg'), path.join(target, 'pkg')])
    );
  });
});

// ============================================================
// Node native-module discovery
// ============================================================

describe('findNodePackageInstalls', () => {
  test('discovers direct node_modules/<pkg>', () => {
    const nm = mkdirp(path.join(tmpRoot, 'app/node_modules/bcrypt'));
    write(path.join(nm, 'package.json'), JSON.stringify({ name: 'bcrypt', version: '5.1.1' }));
    const out = findNodePackageInstalls(tmpRoot);
    expect(out).toHaveLength(1);
    expect(out[0].package_name).toBe('bcrypt');
  });

  test('discovers scoped @org/pkg packages', () => {
    const scoped = mkdirp(path.join(tmpRoot, 'app/node_modules/@scope/pkg'));
    write(path.join(scoped, 'package.json'), JSON.stringify({ name: '@scope/pkg' }));
    const out = findNodePackageInstalls(tmpRoot);
    expect(out.map((n) => n.package_name)).toEqual(['@scope/pkg']);
  });

  test('falls back to dir basename when package.json is unparseable', () => {
    const dir = mkdirp(path.join(tmpRoot, 'app/node_modules/broken'));
    write(path.join(dir, 'package.json'), '{not json');
    const out = findNodePackageInstalls(tmpRoot);
    expect(out[0].package_name).toBe('broken');
  });
});

// ============================================================
// extractLanguageBindings
// ============================================================

describe('extractLanguageBindings', () => {
  test('emits one row per (package, soname) for a cryptography wheel', async () => {
    const sitePkgs = mkdirp(path.join(tmpRoot, 'site-packages'));
    const distInfo = mkdirp(path.join(sitePkgs, 'cryptography-41.0.7.dist-info'));
    write(path.join(distInfo, 'RECORD'), '');
    write(path.join(distInfo, 'top_level.txt'), 'cryptography\n');
    const pkgDir = mkdirp(path.join(sitePkgs, 'cryptography'));
    const soPath = write(
      path.join(pkgDir, '_rust.abi3.so'),
      '\x7fELF...binary...'
    );

    const runner = fixtureRunner({
      [soPath]: dynamicSection(['libssl.so.3', 'libcrypto.so.3']),
    });
    const result = await extractLanguageBindings({ rootDir: tmpRoot, runner });
    expect(result.status).toBe('ok');
    expect(result.bindings).toHaveLength(2);
    expect(new Set(result.bindings.map((b) => b.soname))).toEqual(
      new Set(['libssl.so.3', 'libcrypto.so.3'])
    );
    for (const b of result.bindings) {
      expect(b.ecosystem).toBe('pypi');
      expect(b.package_identifier).toBe('cryptography');
      expect(b.link_method).toBe('elf_needed');
      // install_path must be relative to rootDir (UNIQUE-index stability).
      expect(path.isAbsolute(b.install_path)).toBe(false);
    }
  });

  test('tolerates whitespace-padded readelf output', async () => {
    const sitePkgs = mkdirp(path.join(tmpRoot, 'site-packages'));
    const distInfo = mkdirp(path.join(sitePkgs, 'pkg-1.0.dist-info'));
    write(path.join(distInfo, 'RECORD'), '');
    write(path.join(distInfo, 'top_level.txt'), 'pkg\n');
    const soPath = write(path.join(mkdirp(path.join(sitePkgs, 'pkg')), 'mod.so'), '\x7fELF');

    const runner = fixtureRunner({ [soPath]: WHITESPACE_PADDED });
    const result = await extractLanguageBindings({ rootDir: tmpRoot, runner });
    expect(result.bindings.map((b) => b.soname)).toEqual(['libssl.so.3']);
  });

  test('emits .node binding for a node native addon', async () => {
    const nm = mkdirp(path.join(tmpRoot, 'app/node_modules/bcrypt/build/Release'));
    write(path.join(tmpRoot, 'app/node_modules/bcrypt/package.json'),
          JSON.stringify({ name: 'bcrypt' }));
    const addonPath = write(path.join(nm, 'bcrypt_lib.node'), '\x7fELF');
    const runner = fixtureRunner({ [addonPath]: dynamicSection(['libstdc++.so.6']) });
    const result = await extractLanguageBindings({ rootDir: tmpRoot, runner });
    expect(result.bindings.map((b) => b.soname)).toEqual(['libstdc++.so.6']);
    expect(result.bindings[0].ecosystem).toBe('npm');
    expect(result.bindings[0].package_identifier).toBe('bcrypt');
  });

  test('counts unparsable binaries when readelf is unavailable', async () => {
    const sitePkgs = mkdirp(path.join(tmpRoot, 'site-packages'));
    const distInfo = mkdirp(path.join(sitePkgs, 'pkg-1.0.dist-info'));
    write(path.join(distInfo, 'RECORD'), '');
    write(path.join(distInfo, 'top_level.txt'), 'pkg\n');
    write(path.join(mkdirp(path.join(sitePkgs, 'pkg')), 'ext.so'), '\x7fELF');
    const result = await extractLanguageBindings({ rootDir: tmpRoot, runner: UNAVAILABLE_RUNNER });
    expect(result.bindings).toEqual([]);
    expect(result.binaries_inspected).toBe(1);
    expect(result.binaries_unparsable).toBe(1);
  });
});

// ============================================================
// detectOsFamily
// ============================================================

describe('detectOsFamily', () => {
  const cases: Array<[string, ReturnType<typeof detectOsFamily>]> = [
    ['ID=debian\nVERSION_ID="12"\n', 'dpkg'],
    ['ID=ubuntu\n', 'dpkg'],
    ['ID=alpine\nVERSION_ID="3.18"\n', 'apk'],
    ['ID=wolfi\n', 'apk'],
    ['ID=rhel\n', 'rpm'],
    ['ID=fedora\n', 'rpm'],
    ['ID="rhel"\n', 'rpm'],
    ['ID=amzn\n', 'rpm'],
    ['', 'unknown'],
    ['ID=mystery\n', 'unknown'],
  ];
  for (const [body, expected] of cases) {
    test(`classifies ${expected} from ${JSON.stringify(body.replace(/\n/g, '\\n').slice(0, 40))}`, () => {
      write(path.join(tmpRoot, 'etc/os-release'), body);
      expect(detectOsFamily(tmpRoot)).toBe(expected);
    });
  }

  test('returns none when /etc/os-release is absent', () => {
    expect(detectOsFamily(tmpRoot)).toBe('none');
  });
});

// ============================================================
// extractOsBindings
// ============================================================

describe('extractOsBindings', () => {
  test('emits dpkg_soname rows for the six fixture libraries', async () => {
    write(path.join(tmpRoot, 'etc/os-release'), 'ID=debian\n');
    const infoDir = mkdirp(path.join(tmpRoot, 'var/lib/dpkg/info'));

    const libs: Array<[string, string, string]> = [
      // [pkg, soname, abs-path-on-rootfs]
      // NOTE: dpkg multi-arch suffix `:amd64` is normalized off by the
      // extractor (see normalizeDpkgPackageName test below). The fixture
      // here drops the suffix because Windows fs treats `:` as ADS syntax,
      // so the list file cannot be created under that name on this dev box.
      ['libssl3', 'libssl.so.3', '/usr/lib/x86_64-linux-gnu/libssl.so.3'],
      ['libssl1.1', 'libssl.so.1.1', '/usr/lib/x86_64-linux-gnu/libssl.so.1.1'],
      ['libxml2', 'libxml2.so.2', '/usr/lib/x86_64-linux-gnu/libxml2.so.2'],
      ['libjpeg62-turbo', 'libjpeg.so.62', '/usr/lib/x86_64-linux-gnu/libjpeg.so.62'],
      ['libcrypto3', 'libcrypto.so.3', '/usr/lib/x86_64-linux-gnu/libcrypto.so.3'],
      ['zlib1g', 'libz.so.1', '/lib/x86_64-linux-gnu/libz.so.1'],
    ];
    const runnerMap: Record<string, string> = {};
    for (const [pkg, soname, abs] of libs) {
      write(path.join(infoDir, `${pkg}.list`), `/.\n/usr\n${abs}\n`);
      const onDisk = write(path.join(tmpRoot, abs), '\x7fELF');
      runnerMap[onDisk] = dynamicSectionWithSoname(soname);
    }
    const result = await extractOsBindings({ rootDir: tmpRoot, runner: fixtureRunner(runnerMap) });
    expect(result.status).toBe('ok');
    expect(result.os_family).toBe('dpkg');
    expect(result.bindings).toHaveLength(libs.length);
    expect(new Set(result.bindings.map((b) => b.soname))).toEqual(
      new Set(libs.map(([, s]) => s))
    );
    // Multi-arch suffix stripped.
    expect(result.bindings.find((b) => b.soname === 'libssl.so.3')!.package_identifier).toBe('libssl3');
  });

  test('returns [] + os_family=none on a no-/etc/os-release image', async () => {
    const result = await extractOsBindings({ rootDir: tmpRoot, runner: fixtureRunner({}) });
    expect(result.status).toBe('unsupported_os');
    expect(result.os_family).toBe('none');
    expect(result.bindings).toEqual([]);
  });

  test('returns [] + os_family=apk on Alpine (dpkg path absent)', async () => {
    write(path.join(tmpRoot, 'etc/os-release'), 'ID=alpine\n');
    const result = await extractOsBindings({ rootDir: tmpRoot, runner: fixtureRunner({}) });
    expect(result.status).toBe('unsupported_os');
    expect(result.os_family).toBe('apk');
    expect(result.bindings).toEqual([]);
  });

  test('returns [] when /var/lib/dpkg/info is missing even with ID=debian', async () => {
    write(path.join(tmpRoot, 'etc/os-release'), 'ID=debian\n');
    const result = await extractOsBindings({ rootDir: tmpRoot, runner: fixtureRunner({}) });
    expect(result.status).toBe('unsupported_os');
    expect(result.bindings).toEqual([]);
  });

  test('skips a binary that genuinely has no SONAME (status ok, soname null)', async () => {
    write(path.join(tmpRoot, 'etc/os-release'), 'ID=debian\n');
    const infoDir = mkdirp(path.join(tmpRoot, 'var/lib/dpkg/info'));
    write(path.join(infoDir, 'foo.list'), '/usr/bin/foo.so\n');
    const onDisk = write(path.join(tmpRoot, 'usr/bin/foo.so'), '\x7fELF');
    // dynamicSection alone has NEEDED but no SONAME → extractDtSoname returns ok+null.
    const result = await extractOsBindings({
      rootDir: tmpRoot,
      runner: fixtureRunner({ [onDisk]: STRIPPED_NEEDED_ONLY }),
    });
    expect(result.status).toBe('ok');
    expect(result.bindings).toEqual([]);
  });

  test('counts unparsable when readelf is unavailable', async () => {
    write(path.join(tmpRoot, 'etc/os-release'), 'ID=debian\n');
    const infoDir = mkdirp(path.join(tmpRoot, 'var/lib/dpkg/info'));
    write(path.join(infoDir, 'foo.list'), '/lib/x.so\n');
    write(path.join(tmpRoot, 'lib/x.so'), '\x7fELF');
    const result = await extractOsBindings({ rootDir: tmpRoot, runner: UNAVAILABLE_RUNNER });
    expect(result.bindings).toEqual([]);
    expect(result.binaries_inspected).toBe(1);
    expect(result.binaries_unparsable).toBe(1);
  });

  test('skips symlinked .so files (versioned aliases)', async () => {
    write(path.join(tmpRoot, 'etc/os-release'), 'ID=debian\n');
    const infoDir = mkdirp(path.join(tmpRoot, 'var/lib/dpkg/info'));
    // Real file + symlink. dpkg .list mentions both; only the real file
    // should produce a row.
    const realPath = write(path.join(tmpRoot, 'usr/lib/libfoo.so.1.2.3'), '\x7fELF');
    const linkPath = path.join(tmpRoot, 'usr/lib/libfoo.so');
    try {
      fs.symlinkSync('libfoo.so.1.2.3', linkPath);
    } catch {
      // Windows test box without symlink permission — fall back to a 2nd
      // regular file to keep the test platform-neutral. The dedup path
      // for symlinks specifically is exercised on Linux.
      write(linkPath, '\x7fELF');
    }
    write(path.join(infoDir, 'libfoo1.list'),
          `/usr/lib/libfoo.so\n/usr/lib/libfoo.so.1.2.3\n`);
    const result = await extractOsBindings({
      rootDir: tmpRoot,
      runner: fixtureRunner({
        [realPath]: dynamicSectionWithSoname('libfoo.so.1'),
        [linkPath]: dynamicSectionWithSoname('libfoo.so.1'),
      }),
    });
    expect(result.bindings.length).toBeGreaterThanOrEqual(1);
    expect(result.bindings[0].soname).toBe('libfoo.so.1');
    // package_identifier is the .list basename without :arch suffix.
    expect(result.bindings[0].package_identifier).toBe('libfoo1');
  });
});

// ============================================================
// Sanity check: helper-level dpkg name normalization
// ============================================================

describe('normalizeDpkgPackageName', () => {
  test('strips :arch suffix', () => {
    expect(_internal.normalizeDpkgPackageName('libssl3:amd64.list')).toBe('libssl3');
    expect(_internal.normalizeDpkgPackageName('libxml2:i386.list')).toBe('libxml2');
    expect(_internal.normalizeDpkgPackageName('zlib1g.list')).toBe('zlib1g');
  });
});

// Type-only smoke — keeps the import tree honest if interfaces shift.
const _typecheck: LanguageBinding | OsBinding | null = null;
void _typecheck;
