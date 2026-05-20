/**
 * Python transitive dependency resolver.
 *
 * cdxgen for `pypi` emits a direct-deps-only SBOM by default (it parses
 * setup.py / pyproject.toml / requirements.txt without resolving the
 * full transitive closure). The reachability classifier needs every
 * transitive present to flag `unreachable`, so this resolver runs pip's
 * own resolver in --dry-run mode to enumerate the full set without
 * actually installing anything.
 *
 * Primary path: `pip install --dry-run --report=- -r requirements.txt`
 *   pip resolves dependencies and emits a JSON report to stdout. Zero
 *   side effects (no actual install). Works on any pip 22.2+; depscanner
 *   ships pip via debian/python3-pip which is recent enough.
 *
 * Fallback path: `pipdeptree --json` against a throwaway venv that we
 *   actually install into. Slower but handles poetry-locked projects
 *   and projects with build backends pip's resolver chokes on. pipdeptree
 *   2.23.0 is pinned in the Dockerfile.
 *
 * No `uv` path — that would require adding `uv` to the Dockerfile for
 * a marginal speed win; the existing pip is sufficient.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import type { ParsedSbomDep, ParsedSbomRelationship } from '../sbom';
import type { TransitiveResolverResult } from './go';

const execFileP = promisify(execFile);

const REQUIREMENTS_FILES = [
  'requirements.txt',
  'requirements/base.txt',
  'requirements/main.txt',
  'requirements/prod.txt',
];
const PYPROJECT = 'pyproject.toml';

/**
 * Resolve transitive pypi packages for the given repo. Returns null when
 * no python manifest can be detected (soft-fail). Throws when a manifest
 * exists but neither pip nor pipdeptree can produce a result.
 */
export async function resolvePypiTransitives(
  repoRoot: string,
): Promise<TransitiveResolverResult | null> {
  // Find a manifest. Requirements files take priority — pip's dry-run
  // resolver is happiest with them. pyproject.toml is the modern source
  // but the resolver path is more brittle on poetry-locked projects, so
  // we fall through to the pipdeptree path when pip can't handle it.
  let manifest: { kind: 'requirements'; path: string } | { kind: 'pyproject'; path: string } | null = null;
  for (const rel of REQUIREMENTS_FILES) {
    const full = path.join(repoRoot, rel);
    if (fs.existsSync(full)) {
      manifest = { kind: 'requirements', path: full };
      break;
    }
  }
  if (!manifest) {
    const pyproj = path.join(repoRoot, PYPROJECT);
    if (fs.existsSync(pyproj)) {
      manifest = { kind: 'pyproject', path: pyproj };
    }
  }
  if (!manifest) return null;

  try {
    return await resolveViaPipDryRun(manifest.path, manifest.kind);
  } catch (primaryErr) {
    // Fall back to the pipdeptree venv path. If THAT also fails, throw
    // a structured error carrying both failures so operators can triage.
    try {
      return await resolveViaPipdeptreeVenv(manifest.path);
    } catch (fallbackErr) {
      const primaryMsg = primaryErr instanceof Error ? primaryErr.message : String(primaryErr);
      const fallbackMsg = fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr);
      const err = new Error(
        `pypi resolver failed: primary (pip --dry-run): ${primaryMsg}; fallback (pipdeptree venv): ${fallbackMsg}`,
      );
      (err as Error & { code?: string }).code = 'pypi_resolver_both_paths_failed';
      throw err;
    }
  }
}

/**
 * Primary path: pip's own resolver in dry-run mode. Emits a JSON
 * install plan to stdout via `--report=-`. Available since pip 22.2.
 */
async function resolveViaPipDryRun(
  manifestPath: string,
  kind: 'requirements' | 'pyproject',
): Promise<TransitiveResolverResult> {
  const args =
    kind === 'requirements'
      ? ['install', '--dry-run', '--quiet', '--report', '-', '-r', manifestPath]
      // PEP 660 / 517 — install the project itself in editable mode so
      // pyproject.toml's [project.dependencies] resolves transitively.
      : ['install', '--dry-run', '--quiet', '--report', '-', '-e', path.dirname(manifestPath)];

  const { stdout } = await execFileP('pip', args, {
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      // Don't pollute the worker's site-packages — dry-run shouldn't,
      // but force --user off for paranoia.
      PIP_USER: '0',
    },
  });

  return parsePipDryRunReport(stdout, 'pip-dry-run-report');
}

/**
 * Fallback: install into a tmpdir venv, run pipdeptree to walk the tree.
 * Used when pip's --dry-run resolver fails (poetry-locked projects, build
 * backends pip can't drive, weird platform markers).
 */
async function resolveViaPipdeptreeVenv(
  manifestPath: string,
): Promise<TransitiveResolverResult> {
  const venv = fs.mkdtempSync(path.join(os.tmpdir(), 'pypi-resolver-'));
  try {
    await execFileP('python3', ['-m', 'venv', venv]);
    const pip = path.join(venv, 'bin', 'pip');
    const pipdeptree = path.join(venv, 'bin', 'pipdeptree');
    // Install pipdeptree into the venv (avoid relying on the global one
    // pointing at the worker's python).
    await execFileP(pip, ['install', '--quiet', 'pipdeptree']);
    if (manifestPath.endsWith('pyproject.toml')) {
      await execFileP(pip, ['install', '--quiet', '-e', path.dirname(manifestPath)]);
    } else {
      await execFileP(pip, ['install', '--quiet', '-r', manifestPath]);
    }
    const { stdout } = await execFileP(pipdeptree, ['--json'], { maxBuffer: 64 * 1024 * 1024 });
    return parsePipdeptreeJson(stdout, 'pipdeptree-venv');
  } finally {
    fs.rmSync(venv, { recursive: true, force: true });
  }
}

/**
 * pip's --report=- JSON shape (PEP 668):
 *   { "version": "1", "pip_version": "...", "install": [
 *       { "metadata": { "name": "...", "version": "..." }, ... }
 *     ] }
 * Each `install` entry is one resolved package. The first usually is the
 * project itself (when installing via -e); skip entries flagged
 * `is_direct: true` since cdxgen already lists those.
 */
export function parsePipDryRunReport(
  stdout: string,
  source: TransitiveResolverResult['source'] | 'pip-dry-run-report',
): TransitiveResolverResult {
  // pip's --quiet on Python 3.10+ may still emit warnings; isolate the
  // JSON block by scanning for the outermost { ... }.
  const report = extractFirstJsonObject(stdout);
  if (!report) {
    throw new Error('pip --dry-run --report produced no JSON');
  }
  const parsed = JSON.parse(report) as PipReport;
  const installs = Array.isArray(parsed.install) ? parsed.install : [];
  const deps: ParsedSbomDep[] = [];
  for (const entry of installs) {
    const meta = entry.metadata ?? {};
    const name = meta.name;
    const version = meta.version;
    if (!name || !version) continue;
    deps.push({
      name,
      version,
      namespace: null,
      license: null,
      is_direct: false,
      source: 'transitive',
      devScoped: false,
      bomRef: `pypi-resolver:${name}@${version}`,
    });
  }
  return {
    deps,
    relationships: [],
    rawModuleCount: installs.length,
    source: source as TransitiveResolverResult['source'],
  };
}

/**
 * pipdeptree --json emits a flat list of:
 *   { "package": { "key": "...", "package_name": "...",
 *                  "installed_version": "..." }, "dependencies": [...] }
 */
export function parsePipdeptreeJson(
  stdout: string,
  source: 'pipdeptree-venv',
): TransitiveResolverResult {
  const parsed = JSON.parse(stdout) as PipdeptreeRecord[];
  const deps: ParsedSbomDep[] = [];
  const relationships: ParsedSbomRelationship[] = [];
  for (const rec of parsed) {
    const pkg = rec.package;
    if (!pkg?.package_name || !pkg.installed_version) continue;
    const parentRef = `pypi-resolver:${pkg.package_name}@${pkg.installed_version}`;
    deps.push({
      name: pkg.package_name,
      version: pkg.installed_version,
      namespace: null,
      license: null,
      is_direct: false,
      source: 'transitive',
      devScoped: false,
      bomRef: parentRef,
    });
    for (const child of rec.dependencies ?? []) {
      if (!child.package_name || !child.installed_version) continue;
      relationships.push({
        parentBomRef: parentRef,
        childBomRef: `pypi-resolver:${child.package_name}@${child.installed_version}`,
      });
    }
  }
  return {
    deps,
    relationships,
    rawModuleCount: parsed.length,
    source: source as unknown as TransitiveResolverResult['source'],
  };
}

/** Scan a string for the first balanced `{...}` JSON object. */
function extractFirstJsonObject(s: string): string | null {
  let depth = 0;
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0 && start >= 0) {
        return s.slice(start, i + 1);
      }
    }
  }
  return null;
}

interface PipReport {
  version?: string;
  install?: Array<{
    metadata?: { name?: string; version?: string };
    is_direct?: boolean;
  }>;
}

interface PipdeptreeRecord {
  package?: {
    key?: string;
    package_name?: string;
    installed_version?: string;
  };
  dependencies?: Array<{
    key?: string;
    package_name?: string;
    installed_version?: string;
  }>;
}
