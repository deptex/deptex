/**
 * Per-job ephemeral tarball cache for the malicious-scan step.
 *
 * GuardDog needs the unpacked package source to run its Semgrep+YARA rules.
 * We download tarballs into `/tmp/<jobId>/<eco>/<pkg>-<ver>/` and unpack
 * them with two hard sandbox boundaries:
 *
 *   - **zip-slip**: every entry path must resolve under the destination
 *     root after `path.resolve()`. Anything escaping the root is rejected
 *     and the whole package is skipped.
 *   - **decompression bomb**: cumulative uncompressed size capped at
 *     500 MB. Compression ratio capped at 100:1 against the tarball size.
 *     Either trip aborts the unpack mid-stream.
 *
 * The cache is destroyed at job completion (caller responsibility — see
 * `cleanup()`); the Fly machine itself is recycled scale-to-zero so even
 * if cleanup is skipped the host process is short-lived.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFileSync } from 'child_process';
import type { CanonicalEcosystem } from './ecosystem';

const MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024; // 500 MB
const MAX_COMPRESSION_RATIO = 100;
const PER_PACKAGE_DOWNLOAD_TIMEOUT_MS = 30_000;

export interface TarballCacheEntry {
  /** Absolute path to the unpacked source directory. */
  dir: string;
  /** True when the tarball came from the cache (no network fetch). */
  cached: boolean;
}

export class TarballCache {
  private readonly root: string;
  private readonly seen = new Map<string, string>();

  constructor(jobId: string) {
    this.root = path.join(os.tmpdir(), `malicious-scan-${jobId}`);
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
   * Fetch and unpack a tarball. Returns null if the download or unpack
   * fails (caller handles soft-fail). On success, returns the absolute
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

    const slug = packageName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const dest = path.join(this.root, ecosystem, `${slug}-${version}`);
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
    // pip download produces sdist OR wheel. We tell it to prefer sdist
    // (--no-binary=:all:) so we always get a source layout GuardDog can scan.
    execFileSync('pip3', [
      'download',
      '--no-deps',
      '--no-build-isolation',
      '--no-binary=:all:',
      '--dest',
      dest,
      `${packageName}==${version}`,
    ], { stdio: 'pipe', timeout: PER_PACKAGE_DOWNLOAD_TIMEOUT_MS });

    const downloaded = fs.readdirSync(dest);
    const archive = downloaded.find((f) => f.endsWith('.tar.gz') || f.endsWith('.zip'));
    if (!archive) return; // pip already left us a tree

    const archivePath = path.join(dest, archive);
    if (archive.endsWith('.zip')) {
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
   */
  private unpackTar(tarballPath: string, dest: string): void {
    const tarballSize = fs.statSync(tarballPath).size;

    // Pass 1: list entries with sizes for sandbox checks.
    const listOut = execFileSync('tar', ['-tzvf', tarballPath], {
      stdio: 'pipe',
      timeout: 30_000,
    }).toString('utf8');

    let total = 0;
    const resolvedRoot = path.resolve(dest);
    for (const line of listOut.split('\n')) {
      if (!line.trim()) continue;
      const cols = line.split(/\s+/);
      if (cols.length < 6) continue;
      const size = parseInt(cols[2], 10) || 0;
      const entryPath = cols.slice(5).join(' ');
      total += size;
      if (total > MAX_UNCOMPRESSED_BYTES) {
        throw new Error(`tarball exceeds ${MAX_UNCOMPRESSED_BYTES} bytes uncompressed`);
      }
      if (tarballSize > 0 && total / tarballSize > MAX_COMPRESSION_RATIO) {
        throw new Error('compression ratio exceeds bomb threshold');
      }
      const resolved = path.resolve(dest, entryPath);
      if (!resolved.startsWith(resolvedRoot)) {
        throw new Error(`zip-slip attempt: ${entryPath}`);
      }
    }

    // Pass 2: actual extract — sandbox-checked, no scripts to execute.
    execFileSync('tar', ['-xzf', tarballPath, '-C', dest, '--no-same-owner', '--no-same-permissions'], {
      stdio: 'pipe',
      timeout: 60_000,
    });
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
    if not target.startswith(p.realpath(dst)):
      raise SystemExit('zip-slip attempt: ' + info.filename)
  z.extractall(dst)
`,
      zipPath,
      dest,
    ], { stdio: 'pipe', timeout: 60_000 });
  }
}
