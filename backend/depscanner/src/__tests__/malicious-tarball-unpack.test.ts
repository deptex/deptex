/**
 * tarball-cache unpackTar regression: whitespace-in-filename (M2.3).
 *
 * The v1 list parser used `line.split(/\s+/)` and joined columns 5..end with
 * a single space, which collapsed runs of whitespace inside filenames and
 * mis-validated zip-slip on archives with paths like `weird name/file.txt`.
 * v2 switches to `tar --list --verbose --numeric-owner --gzip -f` and a
 * regex anchored on the date+time pair so the path is captured verbatim.
 *
 * Test strategy:
 *   1. Build a real .tar.gz at runtime containing a file whose path has
 *      multiple consecutive spaces.
 *   2. Run unpackTar through bracket access (the method is `private` only
 *      at compile time — at runtime it's just a normal property).
 *   3. Verify the file lands at the verbatim path inside the destination
 *      and the contents survive.
 *
 * Skipped silently on platforms where the system `tar` binary isn't on
 * PATH — depscanner is Linux-only in production, but the same source tree
 * is typecheck-tested on every developer machine.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { TarballCache, parseTarListing } from '../malicious/tarball-cache';

function tarAvailable(): boolean {
  try {
    execFileSync('tar', ['--version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// gnu tar on Windows (msys/cygwin) interprets `C:\…` paths as a remote host
// spec ("host:path" for old tape protocols), which makes absolute Windows
// paths unusable as tarball arguments. The depscanner runs Linux-only in
// production (Fly machine + Docker image both use a vanilla glibc tar), and
// CI runs on ubuntu-latest, so skipping the test on Windows costs us nothing.
const HAS_TAR = tarAvailable();
const SHOULD_RUN = HAS_TAR && process.platform !== 'win32';
const describeIfTar = SHOULD_RUN ? describe : describe.skip;

describe('parseTarListing — line parser (cross-platform)', () => {
  it('captures size and path for a simple entry', () => {
    const line = '-rw-r--r-- 1000/1000   12345 2024-01-01 00:00 path/to/file.txt';
    expect(parseTarListing(line)).toEqual([{ size: 12345, entryPath: 'path/to/file.txt' }]);
  });

  it('preserves multiple consecutive whitespace inside the path', () => {
    const line = '-rw-r--r-- 1000/1000   42 2024-01-01 00:00 weird  name/spaced  file.txt';
    expect(parseTarListing(line)).toEqual([
      { size: 42, entryPath: 'weird  name/spaced  file.txt' },
    ]);
  });

  it('strips the symlink target so zip-slip resolves the entry, not the link', () => {
    const line = 'lrwxrwxrwx 0/0          0 2024-01-01 00:00 link -> ../escape/target';
    expect(parseTarListing(line)).toEqual([{ size: 0, entryPath: 'link' }]);
  });

  it('parses a multi-line listing in order', () => {
    const out = [
      'drwxr-xr-x 1000/1000          0 2024-01-01 00:00 pkg/',
      '-rw-r--r-- 1000/1000      1024 2024-01-01 00:00 pkg/index.js',
      '-rw-r--r-- 1000/1000      2048 2024-01-01 00:00 pkg/has  spaces.json',
      '',
    ].join('\n');
    expect(parseTarListing(out)).toEqual([
      { size: 0, entryPath: 'pkg/' },
      { size: 1024, entryPath: 'pkg/index.js' },
      { size: 2048, entryPath: 'pkg/has  spaces.json' },
    ]);
  });

  it('skips blank lines and unrelated header rows', () => {
    const out = [
      '',
      'tar: total bytes 0',
      '-rw-r--r-- 1000/1000      10 2024-01-01 00:00 a.txt',
    ].join('\n');
    expect(parseTarListing(out)).toEqual([{ size: 10, entryPath: 'a.txt' }]);
  });
});

describe('TarballCache.fetch — spec-injection rejection (P1 SSRF-1 regression)', () => {
  // pacote's npa parser accepts URL/git/file specs in addition to registry
  // names. SBOM-derived names from arbitrary user repos must not turn into
  // SSRF / git-clone RCE / LFR primitives. Validate at the gate before the
  // string ever reaches pacote / pip.
  let cache: TarballCache;

  beforeEach(() => {
    cache = new TarballCache(`spec-rej-${Date.now()}`);
  });

  afterEach(() => {
    cache.cleanup();
  });

  // The TarballCache.fetch entry point catches and soft-fails on any throw,
  // so we exercise the private fetchNpm / fetchPypi directly to assert the
  // guard runs before any subprocess spawn. fetchNpm/fetchPypi are async
  // (return Promise<void>) so we await .rejects.toThrow rather than the
  // sync `expect(() => ...).toThrow` shape.
  it.each([
    'git+http://169.254.170.2/computeMetadata/',
    'git+https://attacker.example/evil',
    'http://attacker.example/x.tgz',
    'https://attacker.example/x.tgz',
    'file:///etc/passwd',
    '../../../etc/passwd',
    '/absolute/path',
    'name with space',
    'name\nwith\nnewlines',
  ])('fetchNpm rejects non-registry spec %s', async (badName) => {
    await expect((cache as any).fetchNpm(badName, '1.0.0', '/tmp/never-used'))
      .rejects.toThrow(/rejected non-registry npm spec/);
  });

  it.each([
    'name @ http://attacker.example/x.tgz',
    '../../../etc/passwd',
    '/absolute/path',
    'http://attacker/pkg',
    'name with space',
  ])('fetchPypi rejects non-distribution spec %s', async (badName) => {
    await expect((cache as any).fetchPypi(badName, '1.0.0', '/tmp/never-used'))
      .rejects.toThrow(/rejected non-distribution PyPI spec/);
  });

  it('TarballCache.fetch soft-fails (returns null) on rejected spec', async () => {
    const result = await cache.fetch('npm' as any, 'git+http://attacker/evil', '1.0.0');
    expect(result).toBeNull();
  });
});

describeIfTar('TarballCache.unpackTar — whitespace-in-filename robustness', () => {
  let workRoot: string;
  let cache: TarballCache;

  beforeEach(() => {
    workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'tar-ws-test-'));
    cache = new TarballCache(`tar-ws-${Date.now()}`);
  });

  afterEach(() => {
    try { fs.rmSync(workRoot, { recursive: true, force: true }); } catch { /* noop */ }
    cache.cleanup();
  });

  it('unpacks a tarball whose entry path contains whitespace and resolves zip-slip correctly', () => {
    // Build a temp source tree with a deliberately tricky filename.
    // We chdir into workRoot for tar invocations so we can pass relative
    // paths only — gnu tar treats `C:\` as a remote-host spec on Windows
    // (the colon is ambiguous), and `--force-local` isn't supported by
    // bsdtar. Relative paths sidestep both.
    fs.mkdirSync(path.join(workRoot, 'src', 'pkg with  spaces'), { recursive: true });
    fs.writeFileSync(
      path.join(workRoot, 'src', 'pkg with  spaces', 'README  doc.txt'),
      'hello whitespace world\n',
      'utf8',
    );

    execFileSync(
      'tar',
      ['--create', '--gzip', '--file', 'fixture.tar.gz', '-C', 'src', '.'],
      { stdio: 'pipe', cwd: workRoot },
    );

    const tarballPath = path.join(workRoot, 'fixture.tar.gz');
    const dest = path.join(workRoot, 'unpacked');
    fs.mkdirSync(dest, { recursive: true });

    // Bracket access bypasses TypeScript's `private` (which is compile-only).
    expect(() => (cache as any).unpackTar(tarballPath, dest)).not.toThrow();

    // The whitespace-bearing file should exist verbatim under dest.
    const expected = path.join(dest, 'pkg with  spaces', 'README  doc.txt');
    expect(fs.existsSync(expected)).toBe(true);
    expect(fs.readFileSync(expected, 'utf8')).toBe('hello whitespace world\n');
  });
});
