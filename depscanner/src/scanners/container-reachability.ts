/**
 * Container reachability classifier (Phase 2, Item F).
 *
 * Decorates container CVE findings with a static reachability verdict:
 *
 *   module       — the finding's OS package owns a shared library that the
 *                  image entrypoint loads (DT_NEEDED chain or dlopen literal).
 *   unreachable  — the package is installed but nothing the entrypoint loads
 *                  comes from it.
 *   null         — not classified (a language package, or the classifier
 *                  could not run for this image).
 *
 * The package → files map is read from the image's OWN dpkg / apk database
 * inside the exported filesystem — the authoritative source, and independent
 * of whether the upstream Trivy scan was a cache hit or a fresh run.
 *
 * Fail-closed everywhere: any uncertainty (extraction failure, unparseable
 * entrypoint, budget exhaustion) marks findings `module`, never `unreachable` —
 * a false "reachable" is a wasted triage, a false "unreachable" is a missed CVE.
 */

import * as fs from 'fs';
import * as path from 'path';
import { runScannerSubprocess, type ScannerSubprocessLogger } from '../with-timeout';
import {
  extractDtNeeded,
  extractDlopenStrings,
  resolveLoadedLibraries,
  detectFileKind,
  resolveWrapperScript,
  defaultReadelfRunner,
  type ReadelfRunner,
} from './elf-analyzer';
import type { ContainerFinding } from './types';

/** Per-image wall-clock budget for the whole classification, charged against
 *  the orchestrator's existing CONTAINER_SCAN_TOTAL_BUDGET_MS. */
export const REACHABILITY_PER_IMAGE_TIMEOUT_MS = Number(
  process.env.REACHABILITY_PER_IMAGE_TIMEOUT_MS ?? 30_000
);

// ============================================================
// Image extraction — injectable
// ============================================================

export interface ImageExtractor {
  /** Export the image's flattened filesystem into destDir. */
  extract: (
    imageRef: string,
    destDir: string,
    opts: { dockerConfigDir?: string; timeoutMs: number }
  ) => Promise<void>;
  /** Return the image's OCI config JSON string (for ENTRYPOINT / CMD / Env). */
  config: (
    imageRef: string,
    opts: { dockerConfigDir?: string; timeoutMs: number }
  ) => Promise<string>;
}

export interface ReachabilityRunners {
  imageExtractor: ImageExtractor;
  readelf: ReadelfRunner;
}

// crane export streams the whole flattened FS; a real slim image is a few
// hundred MB. 3 GiB ceiling rejects a malicious image whose layers decompress
// to something absurd. The ceiling is enforced WHILE crane writes the tar (a
// size watchdog), not just after — a post-write check cannot stop a 50 GiB
// decompression bomb from filling the worker's disk first.
const MAX_IMAGE_TAR_BYTES = 3 * 1024 * 1024 * 1024;
// crane export tars are uncompressed, so the extracted tree is ~tar size;
// 4 GiB leaves headroom over the 3 GiB tar cap. Enforced by a watchdog over
// real on-disk usage (sparse-file holes excluded) during `tar -xf`.
const MAX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024;
/** How often the extraction watchdogs sample on-disk size. */
const EXTRACTION_WATCHDOG_INTERVAL_MS = 1_000;

/** Current size of a file, or 0 if it does not exist yet / is unreadable. */
function safeFileSize(p: string): number {
  try {
    return fs.statSync(p).size;
  } catch {
    return 0;
  }
}

/**
 * Real on-disk size of a directory tree, but the walk stops as soon as the
 * running total exceeds `limit` — so a hostile tree costs O(limit), not
 * O(tree). Uses block count (sparse-file holes excluded), so an extracted
 * sparse file that consumes no real disk does not trip the watchdog.
 */
function directorySizeUpTo(dir: string, limit: number): number {
  let total = 0;
  const stack: string[] = [dir];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) {
        stack.push(full);
      } else if (e.isFile()) {
        try {
          const st = fs.statSync(full);
          total += st.blocks != null ? st.blocks * 512 : st.size;
        } catch {
          /* file vanished mid-walk */
        }
      }
      if (total > limit) return total;
    }
  }
  return total;
}

/**
 * Poll `measure()` on a fixed interval; the first time it exceeds `limit`,
 * invoke `onExceed` once. Returns a stop function the caller MUST invoke in a
 * finally block.
 */
function startSizeWatchdog(
  measure: () => number,
  limit: number,
  onExceed: () => void
): () => void {
  let fired = false;
  const timer = setInterval(() => {
    let size: number;
    try {
      size = measure();
    } catch {
      return;
    }
    if (size > limit && !fired) {
      fired = true;
      onExceed();
    }
  }, EXTRACTION_WATCHDOG_INTERVAL_MS);
  timer.unref?.();
  return () => clearInterval(timer);
}

async function craneExec(
  args: string[],
  dockerConfigDir: string | undefined,
  timeoutMs: number,
  signal?: AbortSignal
): Promise<{ stdout: string; exitCode: number }> {
  const env: Record<string, string | undefined> = {};
  if (dockerConfigDir) env.DOCKER_CONFIG = dockerConfigDir;
  const r = await runScannerSubprocess({
    exe: 'crane',
    args,
    timeoutMs,
    env,
    signal,
    // crane config stdout is small; crane export writes to a file arg.
    stdoutMaxBytes: 32 * 1024 * 1024,
  });
  return { stdout: r.stdout, exitCode: r.exitCode };
}

export const defaultImageExtractor: ImageExtractor = {
  async extract(imageRef, destDir, opts) {
    const tarPath = path.join(destDir, '_image.tar');

    // ---- crane export, watchdogged against a disk-filling image ----
    const exportAbort = new AbortController();
    const stopExportWatchdog = startSizeWatchdog(
      () => safeFileSize(tarPath),
      MAX_IMAGE_TAR_BYTES,
      () => exportAbort.abort()
    );
    let exported: { exitCode: number };
    try {
      exported = await craneExec(
        ['export', '--platform', 'linux/amd64', imageRef, tarPath],
        opts.dockerConfigDir,
        opts.timeoutMs,
        exportAbort.signal
      );
    } finally {
      stopExportWatchdog();
    }
    if (exportAbort.signal.aborted) {
      fs.rmSync(tarPath, { force: true });
      throw new Error(`image export exceeded the ${MAX_IMAGE_TAR_BYTES}-byte ceiling`);
    }
    if (exported.exitCode !== 0) {
      fs.rmSync(tarPath, { force: true });
      throw new Error(`crane export exit ${exported.exitCode}`);
    }
    // Defence in depth: a fast spike between watchdog samples.
    const tarSize = safeFileSize(tarPath);
    if (tarSize > MAX_IMAGE_TAR_BYTES) {
      fs.rmSync(tarPath, { force: true });
      throw new Error(`image tar ${tarSize} bytes exceeds ceiling`);
    }

    // ---- tar extract, watchdogged against sparse/many-file expansion ----
    const fsRoot = path.join(destDir, 'rootfs');
    fs.mkdirSync(fsRoot, { recursive: true });
    const untarAbort = new AbortController();
    const stopUntarWatchdog = startSizeWatchdog(
      () => directorySizeUpTo(fsRoot, MAX_EXTRACTED_BYTES),
      MAX_EXTRACTED_BYTES,
      () => untarAbort.abort()
    );
    let untar: { exitCode: number };
    try {
      untar = await runScannerSubprocess({
        exe: 'tar',
        // -p preserves nothing security-relevant here; we only read the tree.
        args: ['-xf', tarPath, '-C', fsRoot],
        timeoutMs: opts.timeoutMs,
        signal: untarAbort.signal,
      });
    } finally {
      stopUntarWatchdog();
    }
    fs.rmSync(tarPath, { force: true });
    if (untarAbort.signal.aborted) {
      throw new Error(`image extraction exceeded the ${MAX_EXTRACTED_BYTES}-byte ceiling`);
    }
    if (untar.exitCode !== 0) {
      throw new Error(`tar extract exit ${untar.exitCode}`);
    }
  },
  async config(imageRef, opts) {
    const r = await craneExec(['config', imageRef], opts.dockerConfigDir, opts.timeoutMs);
    if (r.exitCode !== 0) throw new Error(`crane config exit ${r.exitCode}`);
    return r.stdout;
  },
};

export const defaultReachabilityRunners: ReachabilityRunners = {
  imageExtractor: defaultImageExtractor,
  readelf: defaultReadelfRunner,
};

// ============================================================
// Package database parsing — dpkg + apk
// ============================================================

// The dpkg/apk databases come from the untrusted extracted image. Reading them
// whole with no bound lets a hostile image OOM the worker (a single huge file,
// or many medium files accumulating in memory). Real dpkg `.list` files are a
// few KB; a real apk `installed` DB is a few MB.
const MAX_PKG_DB_FILE_BYTES = 16 * 1024 * 1024;
const MAX_PKG_DB_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_PKG_DB_FILES = 50_000;

/** Standard PATH directories used to resolve a bare entrypoint command. */
const DEFAULT_PATH_DIRS = [
  '/usr/local/sbin',
  '/usr/local/bin',
  '/usr/sbin',
  '/usr/bin',
  '/sbin',
  '/bin',
];

/**
 * Build a package → set-of-installed-file-basenames index from a Debian dpkg
 * database. Each `/var/lib/dpkg/info/<pkg>.list` lists the absolute paths a
 * package owns; we keep basenames so they compare directly against DT_NEEDED
 * sonames.
 */
function parseDpkgFileIndex(rootDir: string): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  const infoDir = path.join(rootDir, 'var/lib/dpkg/info');
  let entries: string[];
  try {
    entries = fs.readdirSync(infoDir);
  } catch {
    return index;
  }
  let totalBytes = 0;
  let fileCount = 0;
  for (const entry of entries) {
    if (!entry.endsWith('.list')) continue;
    if (++fileCount > MAX_PKG_DB_FILES) break;
    // `<pkg>.list` or `<pkg>:<arch>.list`.
    const pkg = entry.slice(0, -'.list'.length).split(':')[0].toLowerCase();
    if (!pkg) continue;
    const listPath = path.join(infoDir, entry);
    let size: number;
    try {
      size = fs.statSync(listPath).size;
    } catch {
      continue;
    }
    // Skip a single oversize `.list` (a real one is KB) — its package stays
    // unclassified rather than risking a heap blow-up; stop entirely once the
    // whole-DB budget is spent.
    if (size > MAX_PKG_DB_FILE_BYTES) continue;
    if (totalBytes + size > MAX_PKG_DB_TOTAL_BYTES) break;
    totalBytes += size;
    let text: string;
    try {
      text = fs.readFileSync(listPath, 'utf8');
    } catch {
      continue;
    }
    const files = index.get(pkg) ?? new Set<string>();
    for (const line of text.split(/\r?\n/)) {
      const p = line.trim();
      if (!p) continue;
      files.add(path.posix.basename(p).toLowerCase());
    }
    index.set(pkg, files);
  }
  return index;
}

/**
 * Build the same index from an Alpine apk database. `/lib/apk/db/installed` is
 * a single file of blank-line-separated records: `P:` package, `F:` current
 * directory, `R:` a file relative to that directory.
 */
function parseApkFileIndex(rootDir: string): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  const dbPath = path.join(rootDir, 'lib/apk/db/installed');
  let size: number;
  try {
    size = fs.statSync(dbPath).size;
  } catch {
    return index;
  }
  // A hostile multi-GB apk DB — refuse rather than slurp it into memory.
  if (size > MAX_PKG_DB_TOTAL_BYTES) return index;
  let text: string;
  try {
    text = fs.readFileSync(dbPath, 'utf8');
  } catch {
    return index;
  }
  let pkg: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('P:')) {
      pkg = line.slice(2).trim().toLowerCase();
      if (pkg && !index.has(pkg)) index.set(pkg, new Set<string>());
    } else if (line.startsWith('R:') && pkg) {
      const file = line.slice(2).trim();
      if (file) index.get(pkg)?.add(path.posix.basename(file).toLowerCase());
    }
  }
  return index;
}

/** Merge dpkg + apk indexes — an image is one or the other, never both. */
function buildPackageFileIndex(rootDir: string): Map<string, Set<string>> {
  const dpkg = parseDpkgFileIndex(rootDir);
  if (dpkg.size > 0) return dpkg;
  return parseApkFileIndex(rootDir);
}

// ============================================================
// Entrypoint resolution
// ============================================================

interface ImageConfig {
  entrypoint: string[];
  cmd: string[];
  pathDirs: string[];
}

/** Parse `crane config` JSON into the ENTRYPOINT / CMD / PATH we need. */
export function parseImageConfig(configJson: string): ImageConfig {
  let parsed: any;
  try {
    parsed = JSON.parse(configJson);
  } catch {
    return { entrypoint: [], cmd: [], pathDirs: DEFAULT_PATH_DIRS };
  }
  const cfg = parsed?.config ?? {};
  const entrypoint: string[] = Array.isArray(cfg.Entrypoint) ? cfg.Entrypoint : [];
  const cmd: string[] = Array.isArray(cfg.Cmd) ? cfg.Cmd : [];
  let pathDirs = DEFAULT_PATH_DIRS;
  if (Array.isArray(cfg.Env)) {
    const pathEnv = cfg.Env.find((e: unknown) => typeof e === 'string' && e.startsWith('PATH='));
    if (pathEnv) {
      const dirs = pathEnv.slice('PATH='.length).split(':').filter(Boolean);
      if (dirs.length > 0) pathDirs = dirs;
    }
  }
  return { entrypoint, cmd, pathDirs };
}

export type EntrypointResolution =
  | {
      ok: true;
      entrypointPath: string; // on-disk path inside rootDir
      imagePath: string; // image-internal path
      isWrapperScript: boolean;
    }
  | { ok: false; reason: string };

/**
 * Resolve the image's entrypoint binary to an on-disk path inside the extracted
 * filesystem. Handles absolute paths, bare commands resolved against PATH, and
 * shell-wrapper entrypoints (chased to their `exec` target). A `sh -c` style
 * entrypoint is intentionally unresolvable — the real command is dynamic.
 */
export async function resolveEntrypoint(
  rootDir: string,
  config: ImageConfig
): Promise<EntrypointResolution> {
  const argv0 = config.entrypoint[0] ?? config.cmd[0];
  if (!argv0) return { ok: false, reason: 'no_entrypoint_in_config' };

  // `/bin/sh -c "..."` — the real command is a runtime string, not static.
  const base = path.posix.basename(argv0);
  const isShell = base === 'sh' || base === 'bash' || base === 'dash';
  const hasShellC =
    config.entrypoint.includes('-c') || config.cmd.includes('-c');
  if (isShell && hasShellC) {
    return { ok: false, reason: 'shell_c_entrypoint' };
  }

  // Resolve the image-internal path of the entrypoint.
  let imagePath: string | null = null;
  if (argv0.startsWith('/')) {
    imagePath = argv0;
  } else {
    for (const dir of config.pathDirs) {
      const candidate = path.posix.join(dir, argv0);
      if (fs.existsSync(path.join(rootDir, candidate))) {
        imagePath = candidate;
        break;
      }
    }
  }
  if (!imagePath) return { ok: false, reason: 'entrypoint_not_on_path' };

  let diskPath = path.join(rootDir, imagePath);
  if (!fs.existsSync(diskPath)) {
    return { ok: false, reason: 'entrypoint_missing_on_disk' };
  }

  // Chase a shell-wrapper entrypoint to its exec target.
  let isWrapperScript = false;
  const wrapper = await resolveWrapperScript(diskPath);
  if (wrapper.isWrapperScript) {
    isWrapperScript = true;
    if (wrapper.target !== diskPath) {
      const targetDisk = path.join(rootDir, wrapper.target);
      if (fs.existsSync(targetDisk)) {
        diskPath = targetDisk;
        imagePath = wrapper.target;
      } else {
        return { ok: false, reason: 'wrapper_target_missing' };
      }
    } else {
      // It is a script but we could not chase it — fail closed.
      return { ok: false, reason: 'wrapper_unparseable' };
    }
  }

  return { ok: true, entrypointPath: diskPath, imagePath, isWrapperScript };
}

// ============================================================
// Subprocess-path discovery (skeptic-f10)
// ============================================================

// Absolute paths to other executables embedded in a (static) binary's strings.
const SUBPROCESS_PATH_RE = /\/(?:usr\/)?(?:s)?bin\/[a-z0-9_][a-z0-9_.\-]*/g;

/**
 * A statically-linked Go/Rust binary loads nothing itself, but may `exec` other
 * programs in the image. Scan its strings for absolute executable paths, and
 * fold in the DT_NEEDED of any that exist on disk — otherwise a Go app that
 * shells out to `git` would mark every libcurl CVE unreachable.
 */
async function discoverSubprocessLibraries(
  entrypointDiskPath: string,
  rootDir: string,
  runner: ReadelfRunner
): Promise<{ libraries: string[]; uncertain: boolean }> {
  let strings: string[] = [];
  try {
    const buf = await fs.promises.readFile(entrypointDiskPath);
    // Static Go binaries are large; cap the string scan at 32 MiB.
    const text = buf.subarray(0, 32 * 1024 * 1024).toString('latin1');
    const seen = new Set<string>();
    SUBPROCESS_PATH_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = SUBPROCESS_PATH_RE.exec(text)) !== null) seen.add(m[0]);
    strings = [...seen];
  } catch {
    return { libraries: [], uncertain: false };
  }
  const merged = new Set<string>();
  // `uncertain` = an exec'd ELF binary existed but readelf could not analyze
  // it. Its loaded libraries are unknown, so the static-entrypoint verdict
  // cannot safely conclude `unreachable` — the caller fails closed instead.
  let uncertain = false;
  for (const imagePath of strings.slice(0, 50)) {
    const disk = path.join(rootDir, imagePath);
    try {
      if (!fs.existsSync(disk)) continue;
      if ((await detectFileKind(disk)) !== 'elf') continue;
      const dt = await extractDtNeeded(disk, runner);
      if (dt.status !== 'ok') {
        uncertain = true;
        continue;
      }
      for (const so of dt.needed) merged.add(so);
    } catch {
      /* skip unreadable subprocess binary */
    }
  }
  return { libraries: [...merged], uncertain };
}

// ============================================================
// Classification
// ============================================================

export interface DecorateOptions {
  imageRef: string;
  /** A scratch directory the classifier owns; cleaned on return. */
  scratchDir: string;
  dockerConfigDir?: string;
  budgetMs?: number;
  runners?: ReachabilityRunners;
  logger?: ScannerSubprocessLogger;
  /**
   * Item G — second analysis pass over the same extracted rootDir. Called
   * AFTER the dynamic-linker walk completes and BEFORE the scratch dir is
   * cleaned. Failures here must not affect the reachability summary; the
   * decorator catches and logs but never rethrows. Keeping this on the
   * decorate API (rather than a second extract) means one crane export
   * powers both analyses — no doubled image-pull cost.
   */
  onRootDirReady?: (rootDir: string) => Promise<void>;
}

export interface DecorateSummary {
  total: number;
  /** Findings given a non-null, non-fallback verdict. */
  classified: number;
  module: number;
  unreachable: number;
  /** Findings forced to `module` by a fallback (uncertainty). */
  fallback: number;
  fallbackReason: string | null;
}

function emptySummary(total: number): DecorateSummary {
  return { total, classified: 0, module: 0, unreachable: 0, fallback: 0, fallbackReason: null };
}

/** Mark every finding with one verdict — the fail-closed path. */
function markAll(
  findings: ContainerFinding[],
  level: 'module' | 'unreachable',
  details: Record<string, unknown>
): DecorateSummary {
  for (const f of findings) {
    f.reachability_level = level;
    f.reachability_details = details;
  }
  const s = emptySummary(findings.length);
  if (level === 'module') {
    s.module = findings.length;
    s.fallback = details.fallback_reason ? findings.length : 0;
    s.fallbackReason = (details.fallback_reason as string) ?? null;
  } else {
    s.unreachable = findings.length;
    s.classified = findings.length;
  }
  return s;
}

/** Normalize a Trivy OS-package name for dpkg/apk index lookup. */
function normalizePkgName(name: string): string {
  return name.split(':')[0].trim().toLowerCase();
}

/**
 * Classify a set of container findings for ONE image in place — sets
 * `reachability_level` + `reachability_details` on each finding object.
 */
export async function decorateContainerFindingsWithReachability(
  findings: ContainerFinding[],
  opts: DecorateOptions
): Promise<DecorateSummary> {
  if (findings.length === 0) return emptySummary(0);

  const runners = opts.runners ?? defaultReachabilityRunners;
  const budgetMs = opts.budgetMs ?? REACHABILITY_PER_IMAGE_TIMEOUT_MS;
  const started = Date.now();
  const remaining = () => budgetMs - (Date.now() - started);

  const workDir = path.join(opts.scratchDir, 'reach');
  let extractedRootDir: string | null = null;
  try {
    fs.mkdirSync(workDir, { recursive: true });

    // ---- extract image filesystem ----
    if (remaining() <= 0) {
      return markAll(findings, 'module', { fallback_reason: 'reachability_timeout' });
    }
    try {
      await runners.imageExtractor.extract(opts.imageRef, workDir, {
        dockerConfigDir: opts.dockerConfigDir,
        timeoutMs: Math.max(1, remaining()),
      });
    } catch (err) {
      return markAll(findings, 'module', {
        fallback_reason: 'image_extraction_failed',
        error: (err as Error).message,
      });
    }
    const rootDir = path.join(workDir, 'rootfs');
    extractedRootDir = rootDir;

    // ---- resolve entrypoint ----
    let config: ImageConfig;
    try {
      const json = await runners.imageExtractor.config(opts.imageRef, {
        dockerConfigDir: opts.dockerConfigDir,
        timeoutMs: Math.max(1, remaining()),
      });
      config = parseImageConfig(json);
    } catch {
      return markAll(findings, 'module', { fallback_reason: 'image_config_failed' });
    }

    const entrypoint = await resolveEntrypoint(rootDir, config);
    if (!entrypoint.ok) {
      return markAll(findings, 'module', {
        fallback_reason: 'entrypoint_unparseable',
        detail: entrypoint.reason,
      });
    }

    // ---- DT_NEEDED + loaded-library closure ----
    if (remaining() <= 0) {
      return markAll(findings, 'module', { fallback_reason: 'reachability_timeout' });
    }
    const kind = await detectFileKind(entrypoint.entrypointPath);
    if (kind !== 'elf') {
      // The resolved entrypoint is not an ELF binary (a script we could not
      // chase, or an unknown file) — the dynamic-linker graph cannot be
      // analyzed. Fail closed: every finding stays `module`.
      return markAll(findings, 'module', {
        fallback_reason: 'entrypoint_not_elf',
        entrypoint: entrypoint.imagePath,
      });
    }

    const directNeeded = await extractDtNeeded(entrypoint.entrypointPath, runners.readelf);
    if (directNeeded.status !== 'ok') {
      // readelf could not analyze the entrypoint — it is absent (binutils not
      // installed) or the binary is corrupt / stripped / wrong-arch. An empty
      // DT_NEEDED list here is NOT evidence of static linking, so inferring
      // `unreachable` would be a guess. Fail closed to `module`.
      return markAll(findings, 'module', {
        fallback_reason:
          directNeeded.status === 'unavailable' ? 'readelf_unavailable' : 'readelf_failed',
        entrypoint: entrypoint.imagePath,
      });
    }

    let loadedSonames = new Set<string>();
    let staticLinked = false;
    let depthCapped = false;

    if (directNeeded.needed.length === 0) {
      // Genuinely statically linked — readelf confirmed no dynamic section.
      // Still chase subprocess binaries the static entrypoint may exec.
      staticLinked = true;
      const subprocess = await discoverSubprocessLibraries(
        entrypoint.entrypointPath,
        rootDir,
        runners.readelf
      );
      if (subprocess.uncertain) {
        // A binary the entrypoint may exec could not be analyzed — its loaded
        // libraries are unknown, so an `unreachable` verdict would be a guess.
        return markAll(findings, 'module', {
          fallback_reason: 'subprocess_analysis_incomplete',
          entrypoint: entrypoint.imagePath,
        });
      }
      for (const so of subprocess.libraries) loadedSonames.add(so.toLowerCase());
    } else {
      const resolved = await resolveLoadedLibraries({
        entrypointPath: entrypoint.entrypointPath,
        rootDir,
        runner: runners.readelf,
        budgetMs: Math.max(1, remaining()),
      });
      depthCapped = resolved.depth_capped || resolved.width_capped;
      for (const so of resolved.loaded) loadedSonames.add(so.toLowerCase());
      const dlopen = await extractDlopenStrings(entrypoint.entrypointPath, runners.readelf);
      for (const so of dlopen.libraries) loadedSonames.add(so.toLowerCase());
    }

    // Static binary with no exec'd subprocesses → every OS package unreachable.
    if (staticLinked && loadedSonames.size === 0) {
      return markAll(findings, 'unreachable', {
        static_linked: true,
        entrypoint: entrypoint.imagePath,
        wrapper_script: entrypoint.isWrapperScript,
      });
    }

    // ---- package → files index from the image's own dpkg/apk DB ----
    const pkgIndex = buildPackageFileIndex(rootDir);

    // ---- per-finding verdict ----
    const summary = emptySummary(findings.length);
    const sharedEvidence = {
      entrypoint: entrypoint.imagePath,
      wrapper_script: entrypoint.isWrapperScript,
      static_linked: staticLinked,
      depth_capped: depthCapped,
      dt_needed: directNeeded.needed,
      loaded_count: loadedSonames.size,
    };
    for (const f of findings) {
      const pkg = normalizePkgName(f.os_package_name);
      const files = pkgIndex.get(pkg);
      if (!files) {
        // Not in the OS package DB — a language package, or DB parse gap.
        f.reachability_level = null;
        f.reachability_details = { ...sharedEvidence, reason: 'package_not_in_os_db' };
        continue;
      }
      let loaded = false;
      for (const basename of files) {
        if (loadedSonames.has(basename)) {
          loaded = true;
          break;
        }
      }
      f.reachability_level = loaded ? 'module' : 'unreachable';
      f.reachability_details = { ...sharedEvidence, owns_loaded_file: loaded };
      summary.classified += 1;
      if (loaded) summary.module += 1;
      else summary.unreachable += 1;
    }
    return summary;
  } catch (err) {
    // Any unexpected failure → fail closed.
    return markAll(findings, 'module', {
      fallback_reason: 'classifier_error',
      error: (err as Error).message,
    });
  } finally {
    // Item G — second pass over the same extracted rootDir BEFORE cleanup.
    // Failures are swallowed: native bindings are an optional analysis and
    // must never break reachability decoration or the scan as a whole.
    if (extractedRootDir && opts.onRootDirReady) {
      try {
        await opts.onRootDirReady(extractedRootDir);
      } catch {
        /* native-bindings extractor is best-effort */
      }
    }
    try {
      fs.rmSync(workDir, { recursive: true, force: true });
    } catch {
      /* best-effort cleanup */
    }
  }
}
