/**
 * Per-job ephemeral dependency-source cache — the hardened fetch/unpack core
 * shared by the malicious-scan step (`malicious/tarball-cache.ts`, sdist-first
 * for GuardDog) and the Arc 2 dep-import-graph step (wheel-only for import
 * extraction).
 *
 * Downloads package artifacts into `/tmp/<rootDirName>/<eco>/<pkg>-<ver>/`
 * and unpacks them with two hard sandbox boundaries:
 *
 *   - **zip-slip**: every entry path must resolve under the destination
 *     root after `path.resolve()`. Anything escaping the root is rejected
 *     and the whole package is skipped.
 *   - **decompression bomb**: cumulative uncompressed size capped at
 *     500 MB. Compression ratio capped at 100:1 against the archive size.
 *     Either trip aborts the unpack mid-stream.
 *
 * ARTIFACT POLICY — the load-bearing security knob:
 *   - `'sdist-first'` (malicious scan): source layout is the cleanest GuardDog
 *     input; wheel fallback when no sdist works. NOTE pip's sdist metadata
 *     preparation can execute the package's build backend — the malicious
 *     scanner accepts that tradeoff for its small suspected-package set.
 *   - `'wheel-only'` (dep-import-graph): `--only-binary=:all:` — pip NEVER
 *     builds source, so no package code (setup.py / PEP 517 backend) can run
 *     in the credential-bearing scan container. A dist with no wheel FAILS
 *     (returns null) — the caller must treat it as "unknown", never guess.
 *     `--isolated --no-input` additionally ignores any PIP_* env / pip.conf
 *     that could redirect the index.
 *
 * The cache is destroyed at job completion (caller responsibility — see
 * `cleanup()`); the Fly machine itself is recycled scale-to-zero so even
 * if cleanup is skipped the host process is short-lived.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { execFileSync } from 'child_process';
import type { CanonicalEcosystem } from '../malicious/ecosystem';

const MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024; // 500 MB
const MAX_COMPRESSION_RATIO = 100;
const PER_PACKAGE_DOWNLOAD_TIMEOUT_MS = 30_000;

// npm registry name regex (validate-npm-package-name's "valid for old packages"
// shape, minus URL/git/file specs). Rejects anything pacote/npa would parse as
// a non-registry spec — git+http://, http://, file:, ../, etc. — so SBOM-derived
// names from arbitrary user repos cannot turn into SSRF / git-clone / LFR
// primitives at fetch time. Names are case-insensitive at the npm registry
// (modern names lowercase only); we match either case for the regex level and
// rely on the registry to canonicalize.
const NPM_NAME_RE = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;

// PyPI/PEP 508 distribution name. Same defensive shape: rejects URL/file
// direct-reference syntax (`name @ http://...`) before it reaches pip.
const PYPI_NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

export type ArtifactPolicy = 'sdist-first' | 'wheel-only';

export interface DepSourceCacheOptions {
  /** Basename of the cache root under os.tmpdir() (e.g. `malicious-scan-<jobId>`). */
  rootDirName: string;
  /** See the artifact-policy doc above. */
  artifactPolicy: ArtifactPolicy;
  /** Prefix for thrown error messages (they are caught + soft-failed by fetch). */
  label: string;
}

export interface TarballCacheEntry {
  /** Absolute path to the unpacked source directory. */
  dir: string;
  /** True when the tarball came from the cache (no network fetch). */
  cached: boolean;
}

export class DepSourceCache {
  private readonly root: string;
  private readonly seen = new Map<string, string>();
  private readonly artifactPolicy: ArtifactPolicy;
  private readonly label: string;

  constructor(opts: DepSourceCacheOptions) {
    this.root = path.join(os.tmpdir(), opts.rootDirName);
    this.artifactPolicy = opts.artifactPolicy;
    this.label = opts.label;
    fs.mkdirSync(this.root, { recursive: true });
  }

  cleanup(): void {
    try {
      fs.rmSync(this.root, { recursive: true, force: true });
    } catch {
      // best-effort; Fly machine recycle is the real backstop
    }
  }

  /**
   * Remove one fetched package's directory (Arc 2 unpack→extract→delete
   * discipline: disk usage is bounded by fetch concurrency, not job length).
   */
  evict(ecosystem: CanonicalEcosystem, packageName: string, version: string): void {
    const key = `${ecosystem}/${packageName}@${version}`;
    const dir = this.seen.get(key);
    if (!dir) return;
    this.seen.delete(key);
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  }

  /**
   * Fetch and unpack a package artifact. Returns null if the download or
   * unpack fails (caller handles soft-fail — for Arc 2 that means the dist
   * is "unknown", never a guessed answer). On success, returns the absolute
   * path to the package source directory.
   */
  async fetch(
    ecosystem: CanonicalEcosystem,
    packageName: string,
    version: string,
  ): Promise<TarballCacheEntry | null> {
    const key = `${ecosystem}/${packageName}@${version}`;
    const cachedDir = this.seen.get(key);
    if (cachedDir && fs.existsSync(cachedDir)) {
      return { dir: cachedDir, cached: true };
    }

    // The slug lossily collapses any char outside [A-Za-z0-9._-] to `_`,
    // so distinct scoped packages (`@a/b-c` vs `@a-b/c`) can produce the
    // same slug and write into the same dir — the caller would then scan a
    // merged tree. Append a short hash of the full `ecosystem/name@version`
    // key so each package gets a collision-free destination.
    const slug = packageName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const keyHash = crypto.createHash('sha256').update(key).digest('hex').slice(0, 12);
    const dest = path.join(this.root, ecosystem, `${slug}-${version}-${keyHash}`);
    fs.mkdirSync(dest, { recursive: true });

    try {
      switch (ecosystem) {
        case 'npm':
          await this.fetchNpm(packageName, version, dest);
          break;
        case 'pypi':
          await this.fetchPypi(packageName, version, dest);
          break;
        default:
          // Other ecosystems aren't first-class in v1 (Go modules, RubyGems
          // tarball auth, etc. each need their own client). Skip cleanly.
          return null;
      }
      this.seen.set(key, dest);
      return { dir: dest, cached: false };
    } catch {
      try { fs.rmSync(dest, { recursive: true, force: true }); } catch { /* noop */ }
      return null;
    }
  }

  private async fetchNpm(packageName: string, version: string, dest: string): Promise<void> {
    // SECURITY: validate the package name BEFORE handing it to pacote.
    // pacote's npa parser accepts URL, git, and file specs in addition to
    // registry names — and packageName originates from cdxgen-parsed
    // SBOMs of arbitrary user repos, so a malicious dependency named
    // `git+http://169.254.170.2/...` (Fly metadata), `http://attacker/x.tgz`,
    // or `../../../etc/passwd` would otherwise turn into SSRF / git-clone
    // RCE / local-file read at scan time. Registry-name-shape only.
    if (!NPM_NAME_RE.test(packageName)) {
      throw new Error(`${this.label}: rejected non-registry npm spec ${JSON.stringify(packageName)}`);
    }
    // Versions are passed unquoted to pacote — restrict to characters that
    // semver-coerce can handle without hitting the version-spec parser's
    // own URL/git fallback path.
    if (!/^[A-Za-z0-9.+\-_]{1,256}$/.test(version)) {
      throw new Error(`${this.label}: rejected non-version npm version ${JSON.stringify(version)}`);
    }
    // pacote is already a runtime dep of the worker; --no-scripts disables
    // any postinstall execution. We don't run install, only extract.
    const tarballPath = path.join(dest, '..', `${path.basename(dest)}.tgz`);
    execFileSync('node', [
      '-e',
      `const pacote=require('pacote'); pacote.tarball.file(process.argv[1] + '@' + process.argv[2], process.argv[3], { ignoreScripts: true }).then(()=>process.exit(0)).catch(e=>{console.error(e.message);process.exit(1)})`,
      packageName,
      version,
      tarballPath,
    ], { stdio: 'pipe', timeout: PER_PACKAGE_DOWNLOAD_TIMEOUT_MS });

    this.unpackTar(tarballPath, dest);
    try { fs.rmSync(tarballPath, { force: true }); } catch { /* noop */ }
  }

  private async fetchPypi(packageName: string, version: string, dest: string): Promise<void> {
    // SECURITY: same rejection as fetchNpm — pip's PEP 508 parser accepts
    // direct-reference URL specs (`name @ http://...`) under some option
    // combinations. Block at the gate: distribution-name shape only.
    if (!PYPI_NAME_RE.test(packageName)) {
      throw new Error(`${this.label}: rejected non-distribution PyPI spec ${JSON.stringify(packageName)}`);
    }
    if (!/^[A-Za-z0-9.+\-_!]{1,256}$/.test(version)) {
      throw new Error(`${this.label}: rejected non-version PyPI version ${JSON.stringify(version)}`);
    }

    if (this.artifactPolicy === 'wheel-only') {
      // Arc 2 policy: pip must NEVER prepare sdist metadata (that executes the
      // package's build backend). `--only-binary=:all:` restricts resolution to
      // wheels; a dist with no wheel fails here → the caller records the dist
      // as unknown. `--isolated --no-input` ignores PIP_* env + pip.conf so no
      // ambient config can redirect the index or re-enable source builds.
      execFileSync('pip3', [
        'download',
        '--no-deps',
        '--only-binary=:all:',
        '--isolated',
        '--no-input',
        '--dest',
        dest,
        `${packageName}==${version}`,
      ], { stdio: 'pipe', timeout: PER_PACKAGE_DOWNLOAD_TIMEOUT_MS });
      if (fs.readdirSync(dest).length === 0) {
        throw new Error(`${this.label}: no wheel available for ${packageName}==${version}`);
      }
    } else {
      // pip download can produce sdist OR wheel. We try sdist first
      // (--no-binary=:all:) because the source layout is the cleanest input
      // for GuardDog. Many high-traffic packages (numpy, pillow, lxml) ship
      // only wheels for older versions OR have sdists that require native
      // toolchains the worker container doesn't have. When --no-binary fails
      // for any reason, retry with no constraint so pip falls back to the
      // wheel; .whl is just a zip, so unpackZip handles it. GuardDog can scan
      // the wheel layout (the .py sources sit alongside the .dist-info
      // metadata inside the zip).
      let pipFailed = false;
      try {
        execFileSync('pip3', [
          'download',
          '--no-deps',
          '--no-build-isolation',
          '--no-binary=:all:',
          '--dest',
          dest,
          `${packageName}==${version}`,
        ], { stdio: 'pipe', timeout: PER_PACKAGE_DOWNLOAD_TIMEOUT_MS });
      } catch {
        pipFailed = true;
      }

      if (pipFailed || fs.readdirSync(dest).length === 0) {
        // Wheel fallback. We still pin the version so we don't accidentally
        // download a newer .whl. --prefer-binary lets pip pick wheels even if
        // an sdist exists; --no-deps stops it pulling a dependency tree.
        execFileSync('pip3', [
          'download',
          '--no-deps',
          '--prefer-binary',
          '--dest',
          dest,
          `${packageName}==${version}`,
        ], { stdio: 'pipe', timeout: PER_PACKAGE_DOWNLOAD_TIMEOUT_MS });
      }
    }

    const downloaded = fs.readdirSync(dest);
    const archive = downloaded.find((f) =>
      f.endsWith('.tar.gz') || f.endsWith('.zip') || f.endsWith('.whl'),
    );
    if (!archive) return; // pip already left us a tree

    const archivePath = path.join(dest, archive);
    if (archive.endsWith('.zip') || archive.endsWith('.whl')) {
      // Wheels are zip-format with a fixed internal layout (`<pkg>/`
      // siblings plus `<pkg>-<ver>.dist-info/`). unpackZip's zip-slip and
      // bomb guards apply unchanged.
      this.unpackZip(archivePath, dest);
    } else {
      this.unpackTar(archivePath, dest);
    }
    try { fs.rmSync(archivePath, { force: true }); } catch { /* noop */ }
  }

  /**
   * Tar unpacking with zip-slip + decompression-bomb guards. Uses the
   * system tar binary (BSD/GNU compatible) for streaming; we pre-validate
   * with a list pass before the extract pass.
   *
   * Listing parser: `tar --list --verbose --numeric-owner --gzip -f` keeps
   * the owner/group field as `<uid>/<gid>` (no spaces — `numeric-owner`
   * forces it, even in locales where the system passwd resolves to a
   * username with whitespace) and the date/time format stays
   * `YYYY-MM-DD HH:MM`. That gives us a regex anchor we can use to lift
   * the entry path verbatim, including filenames containing whitespace —
   * which the previous `split(/\s+/)` parser collapsed and mis-validated.
   */
  private unpackTar(tarballPath: string, dest: string): void {
    const tarballSize = fs.statSync(tarballPath).size;

    // Pass 1: list entries with sizes for sandbox checks.
    const listOut = execFileSync(
      'tar',
      ['--list', '--verbose', '--numeric-owner', '--gzip', '-f', tarballPath],
      {
        stdio: 'pipe',
        timeout: 30_000,
      },
    ).toString('utf8');

    let total = 0;
    // Append path.sep so the prefix check can't be satisfied by a sibling
    // dir sharing a name prefix (`/tmp/x/pkg-1` vs `/tmp/x/pkg-1-evil`).
    const resolvedRoot = path.resolve(dest) + path.sep;
    for (const { size, entryPath } of parseTarListing(listOut)) {
      total += size;
      if (total > MAX_UNCOMPRESSED_BYTES) {
        throw new Error(`tarball exceeds ${MAX_UNCOMPRESSED_BYTES} bytes uncompressed`);
      }
      if (tarballSize > 0 && total / tarballSize > MAX_COMPRESSION_RATIO) {
        throw new Error('compression ratio exceeds bomb threshold');
      }
      const resolved = path.resolve(dest, entryPath) + path.sep;
      if (!resolved.startsWith(resolvedRoot)) {
        throw new Error(`zip-slip attempt: ${entryPath}`);
      }
    }

    // Pass 2: actual extract — sandbox-checked, no scripts to execute.
    execFileSync(
      'tar',
      ['--extract', '--gzip', '--numeric-owner', '--no-same-owner', '--no-same-permissions', '-f', tarballPath, '-C', dest],
      {
        stdio: 'pipe',
        timeout: 60_000,
      },
    );
  }

  private unpackZip(zipPath: string, dest: string): void {
    // Python's zipfile is the most portable unzip available everywhere
    // pip works. We pre-validate sizes via Python before unpacking.
    execFileSync('python3', [
      '-c',
      `
import sys, zipfile, os, os.path as p
src, dst = sys.argv[1], sys.argv[2]
MAX = ${MAX_UNCOMPRESSED_BYTES}
RATIO = ${MAX_COMPRESSION_RATIO}
zsize = os.path.getsize(src)
total = 0
with zipfile.ZipFile(src) as z:
  for info in z.infolist():
    total += info.file_size
    if total > MAX:
      raise SystemExit('uncompressed size cap exceeded')
    if zsize > 0 and (total / zsize) > RATIO:
      raise SystemExit('decompression bomb ratio')
    target = p.realpath(p.join(dst, info.filename))
    root = p.realpath(dst) + os.sep
    if not (target + os.sep).startswith(root):
      raise SystemExit('zip-slip attempt: ' + info.filename)
  z.extractall(dst)
`,
      zipPath,
      dest,
    ], { stdio: 'pipe', timeout: 60_000 });
  }
}

/**
 * Parse the output of `tar --list --verbose --numeric-owner` into per-entry
 * (size, entryPath) tuples. Exported for unit testing — the regex must
 * survive whitespace inside filenames and symlink-target arrows, since both
 * appeared in real npm/pypi tarballs and broke the v1 split-by-whitespace
 * parser.
 *
 * Format anchor (numeric-owner forces uid/gid into the form `1000/1000`,
 * with no whitespace):
 *
 *     -rw-r--r-- 1000/1000   12345 2024-01-01 00:00 path/to/file
 *     lrwxrwxrwx 0/0             0 2024-01-01 00:00 symlink -> target
 *
 * Lines that don't match (totals headers, blank lines) are skipped.
 */
export function parseTarListing(output: string): Array<{ size: number; entryPath: string }> {
  // Permissions, owner/group, size, date, time, then the rest is the path.
  // The non-greedy `(.+?)\s*$` keeps trailing whitespace from the path
  // value (rare but possible from busybox tar).
  const ENTRY_RE = /^\S+\s+\S+\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+?)\s*$/;
  const out: Array<{ size: number; entryPath: string }> = [];
  for (const line of output.split('\n')) {
    if (!line.trim()) continue;
    const m = line.match(ENTRY_RE);
    if (!m) continue;
    const size = parseInt(m[1], 10) || 0;
    // tar --verbose appends ` -> target` for symlinks; we must zip-slip
    // resolve the *entry*, not the link target, so strip the arrow.
    const entryPath = m[2].split(' -> ')[0];
    out.push({ size, entryPath });
  }
  return out;
}
