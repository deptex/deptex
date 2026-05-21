/**
 * ELF dynamic-linker analysis for container reachability (Phase 2, Item F).
 *
 * The container reachability classifier needs to know which shared libraries
 * an image's entrypoint actually loads at runtime — that's the difference
 * between an OS-package CVE that ships in the image (installed) and one that
 * is genuinely on a code path (loaded). This module is the static side of
 * that: parse a binary's `DT_NEEDED` chain and `dlopen` literal strings via
 * `readelf`, then walk the chain recursively against the extracted image
 * filesystem.
 *
 * Every subprocess call is injectable so the test suite runs deterministically
 * on any platform (readelf is Linux-only — the worker has it via binutils, a
 * Windows dev box does not). The default runner shells out to the real binary.
 */

import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { runScannerSubprocess } from '../with-timeout';

// ============================================================
// readelf runner — injectable
// ============================================================

/** Runs `readelf <args>`. Real impl shells out; tests inject canned output. */
export type ReadelfRunner = (
  args: string[]
) => Promise<{ stdout: string; exitCode: number }>;

const READELF_TIMEOUT_MS = 10_000;
/** readelf output on a normal binary is a few KB; 16 MiB defends against a
 *  crafted binary with a pathological section table. */
const READELF_STDOUT_CAP = 16 * 1024 * 1024;

export const defaultReadelfRunner: ReadelfRunner = async (args) => {
  const r = await runScannerSubprocess({
    exe: 'readelf',
    args,
    timeoutMs: READELF_TIMEOUT_MS,
    stdoutMaxBytes: READELF_STDOUT_CAP,
  });
  return { stdout: r.stdout, exitCode: r.exitCode };
};

// ============================================================
// readelf query outcome
// ============================================================

/**
 * Outcome of a readelf query.
 *  - `ok`          readelf ran and its output is trustworthy.
 *  - `unparsable`  readelf ran but failed on this binary (corrupt / stripped /
 *                  wrong-arch ELF) — it exited non-zero.
 *  - `unavailable` readelf could not be executed at all — the binary is absent
 *                  from PATH (e.g. binutils not installed in the image).
 *
 * The reachability classifier MUST treat anything other than `ok` as
 * uncertainty and fail closed to `module`. An empty result is only evidence of
 * static linking when the status is `ok` — never otherwise.
 */
export type ReadelfStatus = 'ok' | 'unparsable' | 'unavailable';

export interface DtNeededResult {
  status: ReadelfStatus;
  /** DT_NEEDED sonames. Meaningful only when `status === 'ok'`. */
  needed: string[];
}

export interface DlopenResult {
  /** `unavailable` only when readelf could not be executed; otherwise `ok`. */
  status: 'ok' | 'unavailable';
  libraries: string[];
}

// ============================================================
// DT_NEEDED — declared shared-library dependencies
// ============================================================

// readelf -d prints one line per dynamic entry; NEEDED entries look like:
//   0x0000000000000001 (NEEDED)  Shared library: [libssl.so.3]
const NEEDED_RE = /\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]/;

/**
 * Extract the `DT_NEEDED` sonames a binary declares — the libraries the
 * dynamic linker loads eagerly at process start.
 *
 * The return is a tri-state, NOT a bare array: a statically-linked binary
 * (status `ok`, empty `needed`) must be distinguishable from a binary readelf
 * could not parse (`unparsable`) or could not run against at all
 * (`unavailable`). Collapsing all three to `[]` lets the classifier mistake a
 * missing/broken readelf for a static binary and wrongly mark live CVEs
 * `unreachable`.
 */
export async function extractDtNeeded(
  binaryPath: string,
  runner: ReadelfRunner = defaultReadelfRunner
): Promise<DtNeededResult> {
  let result: { stdout: string; exitCode: number };
  try {
    result = await runner(['-d', binaryPath]);
  } catch {
    // readelf could not be spawned (ENOENT) — this is NOT a static binary.
    return { status: 'unavailable', needed: [] };
  }
  // Non-zero exit: a corrupt / stripped / wrong-arch ELF readelf cannot read.
  if (result.exitCode !== 0) return { status: 'unparsable', needed: [] };

  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of result.stdout.split(/\r?\n/)) {
    const m = NEEDED_RE.exec(line);
    if (m && !seen.has(m[1])) {
      seen.add(m[1]);
      out.push(m[1]);
    }
  }
  return { status: 'ok', needed: out };
}

// ============================================================
// dlopen literal strings — lazily-loaded libraries
// ============================================================

// A library name embedded in .rodata: libfoo.so, libssl.so.3, libnss_dns.so.2.
// Lowercase-only by convention; the `g` + per-call lastIndex reset keeps this
// module-level regex safe for repeated use.
const SO_LITERAL_RE = /lib[a-z0-9_+.\-]*\.so(?:\.[0-9]+)*/g;

/**
 * Scan a binary's `.rodata` section for literal shared-library names — the
 * best static signal for `dlopen()` calls, which the DT_NEEDED chain misses
 * because they load lazily. Computed-string dlopen (`"lib" + name + ".so"`)
 * is unmatchable by design; that limitation is logged by the caller.
 */
export async function extractDlopenStrings(
  binaryPath: string,
  runner: ReadelfRunner = defaultReadelfRunner
): Promise<DlopenResult> {
  let result: { stdout: string; exitCode: number };
  try {
    result = await runner(['-p', '.rodata', binaryPath]);
  } catch {
    // readelf could not be spawned — the dlopen signal is unknown, not empty.
    return { status: 'unavailable', libraries: [] };
  }
  // readelf exits non-zero / warns when .rodata is absent — that is a genuine
  // "no dlopen literals", not an analysis failure, so the status stays `ok`.
  if (result.exitCode !== 0) return { status: 'ok', libraries: [] };

  const seen = new Set<string>();
  SO_LITERAL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SO_LITERAL_RE.exec(result.stdout)) !== null) {
    seen.add(m[0].toLowerCase());
  }
  return { status: 'ok', libraries: [...seen] };
}

// ============================================================
// File-kind detection + wrapper-script chasing
// ============================================================

export type FileKind = 'elf' | 'script' | 'other';

/** Classify a file by its magic bytes: ELF (`\x7fELF`) vs shebang script. */
export async function detectFileKind(filePath: string): Promise<FileKind> {
  let fd: fs.promises.FileHandle | null = null;
  try {
    fd = await fs.promises.open(filePath, 'r');
    const buf = Buffer.alloc(4);
    const { bytesRead } = await fd.read(buf, 0, 4, 0);
    if (bytesRead >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
      return 'elf';
    }
    if (bytesRead >= 2 && buf[0] === 0x23 && buf[1] === 0x21) {
      return 'script';
    }
    return 'other';
  } catch {
    return 'other';
  } finally {
    await fd?.close();
  }
}

// Lines like `exec /usr/local/bin/node "$@"` or `exec "/app/server" -flag`.
const EXEC_TARGET_RE = /^\s*exec\s+(?:-a\s+\S+\s+)?["']?(\/[^\s"']+)/m;

export interface WrapperResolution {
  /** True when the entrypoint was a shell wrapper that exec's another binary. */
  isWrapperScript: boolean;
  /** Absolute (image-internal) path of the final exec target, or the input
   *  path unchanged when no wrapper indirection was found. */
  target: string;
}

/**
 * If an image's entrypoint is a shell wrapper (`#!/bin/sh` … `exec /real/bin`),
 * chase the `exec` target so reachability analysis runs against the real
 * binary, not the shell. Only the first exec with an absolute-path target is
 * followed; relative targets and shell-builtin exec are left for the caller to
 * treat as unparseable (fail-closed).
 */
export async function resolveWrapperScript(
  filePath: string
): Promise<WrapperResolution> {
  const kind = await detectFileKind(filePath);
  if (kind !== 'script') {
    return { isWrapperScript: false, target: filePath };
  }
  let text: string;
  try {
    // Wrapper scripts are tiny; cap the read so a "script" that is really a
    // multi-MB blob can't be slurped into memory.
    const buf = await fs.promises.readFile(filePath);
    text = buf.subarray(0, 64 * 1024).toString('utf8');
  } catch {
    return { isWrapperScript: true, target: filePath };
  }
  const m = EXEC_TARGET_RE.exec(text);
  if (!m) {
    // It is a script, but we could not find an exec target — caller fails closed.
    return { isWrapperScript: true, target: filePath };
  }
  return { isWrapperScript: true, target: m[1] };
}

// ============================================================
// Recursive DT_NEEDED resolution
// ============================================================

/** Standard glibc/musl dynamic-linker search roots, image-internal. */
const DEFAULT_LIB_SEARCH_PATHS: readonly string[] = [
  '/lib',
  '/lib64',
  '/usr/lib',
  '/usr/lib64',
  '/lib/x86_64-linux-gnu',
  '/usr/lib/x86_64-linux-gnu',
  '/usr/local/lib',
];

export interface ResolveLoadedOptions {
  /** Absolute on-disk path of the entrypoint binary inside the extracted image. */
  entrypointPath: string;
  /** On-disk root of the extracted image filesystem. */
  rootDir: string;
  /** Image-internal lib search paths; defaults to the standard glibc set. */
  libSearchPaths?: string[];
  runner?: ReadelfRunner;
  /** Max recursion depth through the DT_NEEDED chain. */
  maxDepth?: number;
  /** Max unique libraries before the walk stops. */
  maxWidth?: number;
  /** Wall-clock budget for the whole walk. */
  budgetMs?: number;
}

export interface ResolveLoadedResult {
  /** Every soname reached from the entrypoint's DT_NEEDED closure. */
  loaded: string[];
  /** binary label → its direct DT_NEEDED list (entrypoint label is `<entrypoint>`). */
  chain: Record<string, string[]>;
  /** A binary at maxDepth still declared dependencies we did not follow. */
  depth_capped: boolean;
  /** The unique-library ceiling was hit. */
  width_capped: boolean;
  /** The wall-clock budget was exhausted mid-walk. */
  budget_exceeded: boolean;
}

const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_MAX_WIDTH = 200;
const DEFAULT_BUDGET_MS = 30_000;

/** Resolve a soname to an on-disk path under rootDir, basename-only so a
 *  crafted soname with `../` cannot escape the extracted image tree. */
function resolveLibPath(
  soname: string,
  rootDir: string,
  searchPaths: readonly string[]
): string | null {
  const base = path.basename(soname);
  if (!base || base === '.' || base === '..') return null;
  for (const sp of searchPaths) {
    const candidate = path.join(rootDir, sp, base);
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      /* unreadable path — skip */
    }
  }
  return null;
}

/**
 * Walk the entrypoint's `DT_NEEDED` closure breadth-first, resolving each
 * soname against the extracted image filesystem and recursing into the ones
 * that exist on disk. Cycle-safe (visited-path set), and bounded on all three
 * axes — depth, unique-library width, and wall-clock — so a pathological image
 * cannot stall the extraction.
 */
export async function resolveLoadedLibraries(
  opts: ResolveLoadedOptions
): Promise<ResolveLoadedResult> {
  const runner = opts.runner ?? defaultReadelfRunner;
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxWidth = opts.maxWidth ?? DEFAULT_MAX_WIDTH;
  const budgetMs = opts.budgetMs ?? DEFAULT_BUDGET_MS;
  const searchPaths =
    opts.libSearchPaths && opts.libSearchPaths.length > 0
      ? opts.libSearchPaths
      : DEFAULT_LIB_SEARCH_PATHS;
  const started = Date.now();

  const loaded = new Set<string>();
  const chain: Record<string, string[]> = {};
  const visitedPaths = new Set<string>();
  let depth_capped = false;
  let width_capped = false;
  let budget_exceeded = false;

  interface QueueEntry {
    diskPath: string;
    label: string;
    depth: number;
  }
  const queue: QueueEntry[] = [
    { diskPath: opts.entrypointPath, label: '<entrypoint>', depth: 0 },
  ];

  while (queue.length > 0) {
    if (Date.now() - started > budgetMs) {
      budget_exceeded = true;
      break;
    }
    const cur = queue.shift() as QueueEntry;
    if (visitedPaths.has(cur.diskPath)) continue;
    visitedPaths.add(cur.diskPath);

    // A child library readelf cannot parse contributes no further edges; the
    // walk continues from what it can read. The entrypoint's own readability
    // is gated upstream by the classifier (fail-closed) before this runs.
    const needed = (await extractDtNeeded(cur.diskPath, runner)).needed;
    chain[cur.label] = needed;

    if (cur.depth >= maxDepth) {
      if (needed.length > 0) depth_capped = true;
      continue;
    }

    for (const soname of needed) {
      if (loaded.size >= maxWidth) {
        width_capped = true;
        break;
      }
      loaded.add(soname);
      const resolved = resolveLibPath(soname, opts.rootDir, searchPaths);
      if (resolved && !visitedPaths.has(resolved)) {
        queue.push({ diskPath: resolved, label: soname, depth: cur.depth + 1 });
      }
    }
  }

  return {
    loaded: [...loaded],
    chain,
    depth_capped,
    width_capped,
    budget_exceeded,
  };
}

// ============================================================
// Evidence hash
// ============================================================

/**
 * SHA-256 of the entrypoint binary — recorded in reachability evidence so a
 * recommendation can be tied to the exact binary it was computed against.
 */
export async function computeEntrypointSha256(filePath: string): Promise<string> {
  const buf = await fs.promises.readFile(filePath);
  return createHash('sha256').update(buf).digest('hex');
}
