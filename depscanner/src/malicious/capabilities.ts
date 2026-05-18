/**
 * Capability detection entry point — malicious-packages-v2 M1b.
 *
 * Runs after the tarball has been unpacked into a sandboxed per-job
 * directory (see `tarball-cache.ts`). For each ecosystem we map to a set
 * of per-language detector modules and walk every supported source file
 * under the unpacked tree, OR-merging detected capabilities into a
 * single `CapabilitySet`. install_script is detected separately from the
 * package's manifest file.
 *
 * Capabilities are global cache rows in `package_capabilities` — one row
 * per (package, version, ecosystem). Soft-fail: any throw inside the
 * scan is captured as a `scan_error` string on the cache row so the
 * pipeline keeps running and downstream consumers render an empty state.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { CanonicalEcosystem } from './ecosystem';
import {
  CAPABILITY_KEYS,
  emptyCapabilitySet,
  orMerge,
  type CapabilityDetector,
  type CapabilitySet,
} from './capabilities/types';
import { detectInstallScript } from './capabilities/manifest';
import { jsDetector } from './capabilities/js';
import { pyDetector } from './capabilities/py';
import { javaDetector } from './capabilities/java';
import { goDetector } from './capabilities/go';
import { rubyDetector } from './capabilities/ruby';
import { phpDetector } from './capabilities/php';
import { rustDetector } from './capabilities/rust';
import { csharpDetector } from './capabilities/csharp';

export const CAPABILITY_SCANNER_VERSION = 'capability@v2.0.0';

export type { CapabilitySet, CapabilityKey } from './capabilities/types';
export { CAPABILITY_KEYS, emptyCapabilitySet } from './capabilities/types';

/**
 * Per-ecosystem walk budget. We cap the number of files scanned per
 * package so a 50-MB monorepo-style npm package can't blow the per-package
 * latency budget. Files beyond the cap are silently skipped — the
 * capability OR-merge converges quickly because most flags trip on the
 * first matching file.
 */
const MAX_FILES_PER_PACKAGE = 5000;

/**
 * Hard ceiling on per-file source size we'll regex-match. Tarballs
 * sometimes contain pre-bundled blobs larger than 5 MB; skipping these
 * avoids worst-case regex backtracking on minified code.
 */
const MAX_FILE_BYTES = 5 * 1024 * 1024;

const ECOSYSTEM_DETECTORS: Record<CanonicalEcosystem, CapabilityDetector[]> = {
  npm: [jsDetector],
  pypi: [pyDetector],
  maven: [javaDetector],
  golang: [goDetector],
  rubygems: [rubyDetector],
  composer: [phpDetector],
  cargo: [rustDetector],
  nuget: [csharpDetector],
  // Cap-detection not run for these two — feed-only ecosystems for v2.
  'github-actions': [],
  vscode: [],
};

/**
 * Result of a capability scan, including the OR-merged flag set, scanner
 * version, and a non-fatal `scan_error` string when the walk threw mid-way
 * through (e.g. tree-sitter blew up on one weird file).
 */
export interface CapabilityScanResult {
  capabilities: CapabilitySet;
  scanner_version: string;
  scan_error: string | null;
}

/**
 * Top-level capability detector. Returns the OR-merged CapabilitySet across
 * every supported source file under `unpackedDir`, plus the
 * `install_script` flag derived from the package's manifest.
 *
 * `packageName` is currently unused but reserved for future per-package
 * heuristics (e.g. allow-list overrides for known-safe packages with
 * obvious install hooks).
 */
export function detectCapabilities(
  unpackedDir: string,
  ecosystem: CanonicalEcosystem,
  _packageName: string,
): CapabilityScanResult {
  const accum = emptyCapabilitySet();
  const detectors = ECOSYSTEM_DETECTORS[ecosystem] ?? [];

  let scanError: string | null = null;
  try {
    if (detectors.length > 0) {
      walkAndDetect(unpackedDir, detectors, accum);
    }
    accum.install_script = detectInstallScript(unpackedDir, ecosystem);
  } catch (err: any) {
    scanError = String(err?.message ?? err).slice(0, 500);
  }

  return {
    capabilities: accum,
    scanner_version: CAPABILITY_SCANNER_VERSION,
    scan_error: scanError,
  };
}

function walkAndDetect(
  rootDir: string,
  detectors: CapabilityDetector[],
  accum: CapabilitySet,
): void {
  let scannedFiles = 0;
  const stack: string[] = [rootDir];
  while (stack.length > 0) {
    if (scannedFiles >= MAX_FILES_PER_PACKAGE) return;
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue; // refuse to follow symlinks (zip-slip already enforced at unpack)
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const fileName = entry.name.toLowerCase();
      const detector = detectors.find((d) => d.supportsFile(fileName));
      if (!detector) continue;

      let stat: fs.Stats;
      try {
        stat = fs.statSync(full);
      } catch {
        continue;
      }
      if (stat.size > MAX_FILE_BYTES) continue;

      let source: string;
      try {
        source = fs.readFileSync(full, 'utf8');
      } catch {
        continue;
      }
      scannedFiles++;
      const partial = detector.detect(source);
      orMerge(accum, partial);

      // Early-exit: if every capability the language can flip is true,
      // no further file inspection changes the answer.
      if (allFlagsTrue(accum)) return;
    }
  }
}

function allFlagsTrue(c: CapabilitySet): boolean {
  for (const k of CAPABILITY_KEYS) {
    if (!c[k]) return false;
  }
  return true;
}
