/**
 * Native-binding extractors for Item G (composed IaC↔Code reachability).
 *
 * Two sides of the SONAME bridge:
 *
 *   Language side: a Python wheel or Node native module installed somewhere
 *     under rootDir that ships an ELF whose DT_NEEDED list names a SONAME.
 *     We walk `*.dist-info/RECORD` (Python) and `node_modules/<name>/`
 *     (Node) to find those install dirs, then `readelf -d` every `.so`
 *     / `.node` file inside.
 *
 *   OS side: a dpkg-managed package whose payload includes an ELF whose
 *     own DT_SONAME identifies it. We walk `/var/lib/dpkg/info/<pkg>.list`
 *     files to get the package → file list, then `readelf -d` each `.so*`
 *     file and harvest its DT_SONAME.
 *
 * Pairing happens later in composition.ts via exact-string soname match.
 *
 * Both extractors are subprocess-injectable so unit tests run on a Windows
 * dev box; the real readelf only runs inside the depscanner Docker image.
 * They return tri-state structs that distinguish "no bindings on this
 * platform" from "readelf is broken / unavailable" — the same fail-closed
 * discipline the rest of elf-analyzer.ts follows.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  extractDtNeeded,
  extractDtSoname,
  defaultReadelfRunner,
  type ReadelfRunner,
} from './elf-analyzer';

// ---- Tunables --------------------------------------------------------------

/** Wall-clock budget across both extractors. Each side gets half by default. */
const DEFAULT_BINDINGS_BUDGET_MS = 60_000;

/** Cap on total .so/.node files inspected per side. Defends against a
 *  pathologically deep filesystem (huge image, broken vendoring) from
 *  consuming the readelf wall-clock budget on one cryptography wheel. */
const MAX_BINARIES_PER_SIDE = 2_000;

/** Cap on total dpkg .list files parsed. Real-world Debian image is
 *  ~100 packages; 1000 is comfortably above any realistic baseline. */
const MAX_DPKG_LISTS = 1_000;

/** Cap on lines parsed per dpkg list. The dpkg `.list` for `libc6` is ~600
 *  lines; this protects against an adversarial / corrupt list dump. */
const MAX_LINES_PER_DPKG_LIST = 50_000;

// ---- Types ----------------------------------------------------------------

export interface LanguageBinding {
  /** 'pypi' | 'npm' — the SBOM ecosystem the package belongs to. */
  ecosystem: 'pypi' | 'npm';
  /** Package name (case-sensitive on dist-info; lower-cased on node_modules). */
  package_identifier: string;
  /** DT_NEEDED soname read off the ELF. */
  soname: string;
  /** Path on disk (under rootDir) of the binary the soname came from. */
  install_path: string;
  link_method: 'elf_needed';
}

export interface OsBinding {
  /** Source dpkg package name (e.g. `libssl3:amd64` normalized to `libssl3`). */
  package_identifier: string;
  /** DT_SONAME the binary declares for itself. */
  soname: string;
  install_path: string;
  link_method: 'dpkg_soname';
}

export type OsFamily = 'dpkg' | 'apk' | 'rpm' | 'none' | 'unknown';

export interface LanguageBindingsResult {
  status: 'ok' | 'budget_exceeded';
  bindings: LanguageBinding[];
  /** Count of `.so` / `.node` files inspected. */
  binaries_inspected: number;
  /** Count whose readelf invocation returned a non-`ok` status. */
  binaries_unparsable: number;
}

export interface OsBindingsResult {
  status: 'ok' | 'unsupported_os' | 'budget_exceeded';
  os_family: OsFamily;
  bindings: OsBinding[];
  binaries_inspected: number;
  binaries_unparsable: number;
}

export interface ExtractLanguageBindingsOptions {
  /** Absolute path of the extracted-container filesystem root. */
  rootDir: string;
  runner?: ReadelfRunner;
  budgetMs?: number;
  /** Cap on files inspected; primarily a test knob. */
  maxBinaries?: number;
}

export interface ExtractOsBindingsOptions {
  rootDir: string;
  runner?: ReadelfRunner;
  budgetMs?: number;
  maxLists?: number;
  maxBinaries?: number;
}

// ---- Helpers --------------------------------------------------------------

/** Read `/etc/os-release` ID= to classify the package manager backend. */
export function detectOsFamily(rootDir: string): OsFamily {
  const candidates = ['/etc/os-release', '/usr/lib/os-release'];
  for (const rel of candidates) {
    const abs = path.join(rootDir, rel);
    let text: string;
    try {
      text = fs.readFileSync(abs, { encoding: 'utf8' });
    } catch {
      continue;
    }
    // ID line examples: ID=debian / ID=ubuntu / ID=alpine / ID="rhel"
    const m = /^ID=("?)([a-z0-9._-]+)\1$/m.exec(text);
    const id = m?.[2] ?? '';
    if (!id) return 'unknown';
    // ID_LIKE-aware would be nicer but ID is sufficient for v1 dispatch.
    if (['debian', 'ubuntu', 'raspbian', 'kali'].includes(id)) return 'dpkg';
    if (['alpine', 'wolfi', 'chainguard'].includes(id)) return 'apk';
    if (['rhel', 'centos', 'fedora', 'rocky', 'almalinux', 'amzn'].includes(id)) return 'rpm';
    return 'unknown';
  }
  return 'none';
}

/** Resolve a symlink-or-file path to its final on-disk path under rootDir,
 *  refusing any chain that escapes the root. Returns null on escape / cycle
 *  / unreadable. */
function realpathContained(absPath: string, rootDir: string): string | null {
  let real: string;
  try {
    real = fs.realpathSync(absPath);
  } catch {
    return null;
  }
  const normalizedRoot = path.resolve(rootDir);
  const normalizedReal = path.resolve(real);
  if (
    normalizedReal !== normalizedRoot &&
    !normalizedReal.startsWith(normalizedRoot + path.sep)
  ) {
    return null; // symlink escaped rootDir
  }
  return normalizedReal;
}

/** Walk a directory tree under base looking for matches, capping
 *  recursion + file count so a huge image cannot stall the extractor. */
function* walkFiles(
  base: string,
  predicate: (relPath: string) => boolean,
  maxFiles: number,
  maxDepth = 12
): Generator<string> {
  let yielded = 0;
  const stack: Array<{ dir: string; depth: number }> = [{ dir: base, depth: 0 }];
  while (stack.length) {
    const { dir, depth } = stack.pop()!;
    if (depth > maxDepth) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (yielded >= maxFiles) return;
      const full = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) continue; // we follow only regular files
      if (ent.isDirectory()) {
        stack.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (!ent.isFile()) continue;
      if (predicate(full)) {
        yielded++;
        yield full;
      }
    }
  }
}

// ---- Python wheel install discovery ---------------------------------------

interface PythonWheelInstall {
  package_name: string;
  /** Directory containing this wheel's installed files (the parent of
   *  `<pkg>.dist-info` is the site-packages root; this is the package's
   *  on-disk install dir, derived from top_level.txt + dist-info location). */
  install_dir: string;
}

/**
 * Walk under rootDir for `*.dist-info/RECORD` files. Each one identifies an
 * installed Python wheel: the dist-info's parent is the site-packages dir,
 * and `top_level.txt` (when present) names the importable package dir(s).
 * Returns one entry per (package, install_dir) pair.
 */
export function findPythonWheelInstalls(
  rootDir: string,
  maxWheels = 1_000
): PythonWheelInstall[] {
  const out: PythonWheelInstall[] = [];
  const seenDistInfos = new Set<string>();
  for (const recordPath of walkFiles(
    rootDir,
    (p) => p.endsWith(path.sep + 'RECORD') && /\.dist-info[\\/]+RECORD$/.test(p),
    maxWheels * 4
  )) {
    if (out.length >= maxWheels) break;
    const distInfoDir = path.dirname(recordPath);
    if (seenDistInfos.has(distInfoDir)) continue;
    seenDistInfos.add(distInfoDir);

    // Package name: dist-info dir is `<name>-<version>.dist-info`
    const distInfoBase = path.basename(distInfoDir);
    const m = /^([^/\\]+?)-[0-9].*\.dist-info$/.exec(distInfoBase);
    const packageName = m ? m[1] : distInfoBase.replace(/\.dist-info$/, '');

    const sitePackagesDir = path.dirname(distInfoDir);
    let topLevel: string[] = [];
    try {
      const text = fs.readFileSync(path.join(distInfoDir, 'top_level.txt'), 'utf8');
      topLevel = text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    } catch {
      /* top_level.txt is optional; many modern wheels omit it */
    }
    if (topLevel.length === 0) {
      // Heuristic: the package dir is usually named the same as the wheel,
      // with hyphens swapped for underscores per PEP 491.
      topLevel = [packageName.replace(/-/g, '_')];
    }
    for (const tl of topLevel) {
      const candidate = path.join(sitePackagesDir, tl);
      try {
        if (fs.statSync(candidate).isDirectory()) {
          out.push({ package_name: packageName, install_dir: candidate });
        }
      } catch {
        // top_level entry might be a single .py file rather than a package
        // dir — those have no native artifacts so ignore.
      }
    }
  }
  return out;
}

// ---- Node native-module install discovery ---------------------------------

interface NodePackageInstall {
  package_name: string;
  install_dir: string;
}

export function findNodePackageInstalls(
  rootDir: string,
  maxPackages = 5_000
): NodePackageInstall[] {
  const out: NodePackageInstall[] = [];
  const seenDirs = new Set<string>();
  for (const pkgJsonPath of walkFiles(
    rootDir,
    (p) =>
      p.endsWith(path.sep + 'package.json') &&
      p.includes(path.sep + 'node_modules' + path.sep),
    maxPackages * 4
  )) {
    if (out.length >= maxPackages) break;
    const dir = path.dirname(pkgJsonPath);
    if (seenDirs.has(dir)) continue;
    // Only direct node_modules children — not nested package.json files.
    const parent = path.basename(path.dirname(dir));
    if (parent !== 'node_modules' && !parent.startsWith('@')) {
      continue;
    }
    seenDirs.add(dir);
    let name: string;
    try {
      const parsed = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      name = typeof parsed?.name === 'string' && parsed.name.length > 0
        ? parsed.name
        : path.basename(dir);
    } catch {
      name = path.basename(dir);
    }
    out.push({ package_name: name, install_dir: dir });
  }
  return out;
}

// ---- Language-side extractor ----------------------------------------------

/**
 * Walk the rootDir for Python wheel + Node-module install directories;
 * for every native `.so` / `.node` file inside one, read DT_NEEDED via
 * readelf and emit a binding row. The package_identifier is the package
 * name (dist-info or package.json `name`), so composition can match on
 * `(ecosystem, name)` against PDV's dependency.
 */
export async function extractLanguageBindings(
  opts: ExtractLanguageBindingsOptions
): Promise<LanguageBindingsResult> {
  const runner = opts.runner ?? defaultReadelfRunner;
  const budgetMs = opts.budgetMs ?? DEFAULT_BINDINGS_BUDGET_MS / 2;
  const maxBinaries = opts.maxBinaries ?? MAX_BINARIES_PER_SIDE;
  const started = Date.now();
  const out: LanguageBinding[] = [];
  let inspected = 0;
  let unparsable = 0;

  const wheels = findPythonWheelInstalls(opts.rootDir);
  const nodePkgs = findNodePackageInstalls(opts.rootDir);

  const sweep = async (
    installDir: string,
    ecosystem: 'pypi' | 'npm',
    packageName: string,
    pattern: RegExp
  ): Promise<void> => {
    for (const binPath of walkFiles(installDir, (p) => pattern.test(p), maxBinaries)) {
      if (Date.now() - started > budgetMs) return;
      if (inspected >= maxBinaries) return;
      const real = realpathContained(binPath, opts.rootDir);
      if (!real) continue;
      inspected++;
      const dt = await extractDtNeeded(real, runner);
      if (dt.status !== 'ok') {
        unparsable++;
        continue;
      }
      for (const soname of dt.needed) {
        // Use the install_path RELATIVE to rootDir so the same install on a
        // re-extracted image produces the same UNIQUE-index payload.
        const relPath = path.relative(opts.rootDir, real);
        out.push({
          ecosystem,
          package_identifier: packageName,
          soname,
          install_path: relPath,
          link_method: 'elf_needed',
        });
      }
    }
  };

  for (const w of wheels) {
    if (Date.now() - started > budgetMs) {
      return { status: 'budget_exceeded', bindings: out, binaries_inspected: inspected, binaries_unparsable: unparsable };
    }
    await sweep(w.install_dir, 'pypi', w.package_name, /\.so(\.[0-9.]+)?$/);
  }
  for (const n of nodePkgs) {
    if (Date.now() - started > budgetMs) {
      return { status: 'budget_exceeded', bindings: out, binaries_inspected: inspected, binaries_unparsable: unparsable };
    }
    // Node native addons are .node (N-API); some packages also ship .so.
    await sweep(n.install_dir, 'npm', n.package_name, /\.(node|so(\.[0-9.]+)?)$/);
  }

  return { status: 'ok', bindings: out, binaries_inspected: inspected, binaries_unparsable: unparsable };
}

// ---- dpkg side ------------------------------------------------------------

/**
 * Parse `/var/lib/dpkg/info/<pkg>.list` (one absolute container-internal
 * path per line). Returns the regular-file `.so*` paths only — skipping
 * directories and symlinks because we want each soname's *defining* binary.
 */
function readDpkgListFiles(
  rootDir: string,
  listPath: string,
  maxLines: number
): string[] {
  let text: string;
  try {
    text = fs.readFileSync(listPath, 'utf8');
  } catch {
    return [];
  }
  const out: string[] = [];
  let i = 0;
  for (const line of text.split(/\r?\n/)) {
    if (i++ >= maxLines) break;
    const trimmed = line.trim();
    if (!trimmed) continue;
    // dpkg lists store container-internal absolute paths.
    if (!trimmed.startsWith('/')) continue;
    if (!/\.so(\.[0-9.]+)*$/.test(trimmed)) continue;
    // Resolve against rootDir. Skip if not a regular file (symlinks are
    // versioned aliases; the SONAME-defining file is the symlink target).
    const abs = path.join(rootDir, trimmed);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(abs);
    } catch {
      continue;
    }
    if (!stat.isFile()) continue;
    out.push(abs);
  }
  return out;
}

/** Strip dpkg multi-arch suffix: `libssl3:amd64` → `libssl3`. */
function normalizeDpkgPackageName(listBasename: string): string {
  const noExt = listBasename.replace(/\.list$/, '');
  return noExt.split(':')[0];
}

export async function extractOsBindings(
  opts: ExtractOsBindingsOptions
): Promise<OsBindingsResult> {
  const runner = opts.runner ?? defaultReadelfRunner;
  const budgetMs = opts.budgetMs ?? DEFAULT_BINDINGS_BUDGET_MS / 2;
  const maxLists = opts.maxLists ?? MAX_DPKG_LISTS;
  const maxBinaries = opts.maxBinaries ?? MAX_BINARIES_PER_SIDE;
  const started = Date.now();

  const family = detectOsFamily(opts.rootDir);
  if (family !== 'dpkg') {
    return {
      status: 'unsupported_os',
      os_family: family,
      bindings: [],
      binaries_inspected: 0,
      binaries_unparsable: 0,
    };
  }

  const infoDir = path.join(opts.rootDir, '/var/lib/dpkg/info');
  let listFiles: string[];
  try {
    listFiles = fs
      .readdirSync(infoDir)
      .filter((n) => n.endsWith('.list'))
      .slice(0, maxLists);
  } catch {
    // /var/lib/dpkg/info missing on a non-dpkg image we mis-classified.
    return {
      status: 'unsupported_os',
      os_family: family,
      bindings: [],
      binaries_inspected: 0,
      binaries_unparsable: 0,
    };
  }

  const out: OsBinding[] = [];
  let inspected = 0;
  let unparsable = 0;
  const seen = new Set<string>();

  for (const listName of listFiles) {
    if (Date.now() - started > budgetMs) {
      return { status: 'budget_exceeded', os_family: family, bindings: out, binaries_inspected: inspected, binaries_unparsable: unparsable };
    }
    if (inspected >= maxBinaries) {
      return { status: 'ok', os_family: family, bindings: out, binaries_inspected: inspected, binaries_unparsable: unparsable };
    }
    const packageName = normalizeDpkgPackageName(listName);
    const binaries = readDpkgListFiles(
      opts.rootDir,
      path.join(infoDir, listName),
      MAX_LINES_PER_DPKG_LIST
    );

    for (const binPath of binaries) {
      if (Date.now() - started > budgetMs) {
        return { status: 'budget_exceeded', os_family: family, bindings: out, binaries_inspected: inspected, binaries_unparsable: unparsable };
      }
      if (inspected >= maxBinaries) break;
      const real = realpathContained(binPath, opts.rootDir);
      if (!real) continue;
      // Dedup: a multi-arch package may list the same file twice.
      const key = `${packageName}|${real}`;
      if (seen.has(key)) continue;
      seen.add(key);
      inspected++;

      const s = await extractDtSoname(real, runner);
      if (s.status !== 'ok') {
        unparsable++;
        continue;
      }
      if (!s.soname) continue; // ok-but-no-SONAME → not a library identity
      const relPath = path.relative(opts.rootDir, real);
      out.push({
        package_identifier: packageName,
        soname: s.soname,
        install_path: relPath,
        link_method: 'dpkg_soname',
      });
    }
  }

  return { status: 'ok', os_family: family, bindings: out, binaries_inspected: inspected, binaries_unparsable: unparsable };
}

// ---- Test seam ------------------------------------------------------------

export const _internal = {
  findPythonWheelInstalls,
  findNodePackageInstalls,
  detectOsFamily,
  normalizeDpkgPackageName,
};
