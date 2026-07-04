/**
 * STEP: Dependency-source import graphs (Arc 2).
 *
 * Builds the per-scan `TransitiveImportIndex` the reachability precondition
 * models consult to answer "is module/submodule X imported by any package on
 * the production dependency path?" — the transitive extension of their
 * first-party-only absence proofs.
 *
 * Two legs, both TRIGGER-GUARDED (never fetch/run without a gate in play):
 *
 *   - golang: `go list -deps ./...` per module — the toolchain's exact compile
 *     set. Zero new network on the happy path (`go mod download` already ran in
 *     the resolve step); hardened env (GOTOOLCHAIN=local so a repo demanding a
 *     newer toolchain FAILS instead of downloading/executing one; GOWORK=off
 *     for deterministic per-module semantics; CGO_ENABLED=0). Multi-module
 *     repos are enumerated and UNIONED — `./...` does not cross go.mod
 *     boundaries, so a single-module run over a multi-module repo would be
 *     complete-but-wrong (the review's nested-module finding). Any per-module
 *     failure → the whole index is 'unavailable' (Go has no 'partial': a
 *     missing module's compile set could hide the import).
 *
 *   - pypi: per-dist WHEEL-ONLY import/token extraction over the prod dists
 *     (`DepSourceCache` with artifactPolicy 'wheel-only' — pip never executes
 *     a build backend; a dist with no wheel = failed = unknown). Extraction
 *     stores only the QUESTION-RELEVANT subset of each dist's imports (the
 *     registry's module prefixes) + liberal question-token substring hits —
 *     v1 is veto-only, so only those memberships are ever asked. Results are
 *     cached cross-org in `package_import_summaries` keyed
 *     (ecosystem, package_name, version) with extractor_version as a
 *     replace-in-place COLUMN (the package_capabilities pattern — no stale-row
 *     accumulation). Wall-capped + dist-capped; any shortfall → 'partial'
 *     (positive answers stay valid; absence claims are refused by the models).
 *
 * FAIL-SAFE: every failure path returns 'unavailable' or degrades to
 * 'partial' — the classifier then behaves exactly as it does today. This step
 * must run BEFORE reachability classification and is NOT part of the
 * DEPTEX_SKIP_OPTIONAL_SCANS block (corpus scans need it).
 */

import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import pLimit from 'p-limit';
import { runStage } from '../pipeline-stage-runner';
import type { PipelineContext } from '../pipeline-types';
import type { Storage } from '../storage';
import { DepSourceCache } from '../lib/dep-sources';
import {
  emptyTransitiveImportIndex,
  pep503Normalize,
  type PackageImportSummary,
  type TransitiveImportIndex,
} from '../transitive-imports';
import { goSubpackageGateModules } from '../reachability-go-preconditions';
import {
  djangoTransitiveQuestionRegistry,
  extractPythonImports,
} from '../reachability-django-preconditions';
import * as crypto from 'crypto';

const GO_LIST_TIMEOUT_MS = 180_000;
const GO_MODULE_ENUM_MAX_DEPTH = 6;
const GO_MODULE_ENUM_MAX_MODULES = 50;
const PYPI_FETCH_CONCURRENCY = 4;
const PYPI_MAX_FILES_PER_DIST = 3_000;
const PYPI_MAX_FILE_BYTES = 2 * 1024 * 1024;
const PYPI_MAX_DIST_BYTES = 64 * 1024 * 1024;
const SKIP_DIR_NAMES = new Set(['vendor', 'testdata', 'node_modules', '.git']);

function envInt(name: string, fallback: number): number {
  const v = parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

// ---------------------------------------------------------------------------
// Go leg
// ---------------------------------------------------------------------------

/** Parse `go list -deps ./...` stdout: one import path per non-empty line. */
export function parseGoListOutput(stdout: string): string[] {
  return stdout
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/**
 * Enumerate go.mod module directories under the workspace — `./...` does not
 * cross module boundaries, so every nested module must be listed separately.
 * vendor/ and testdata/ are never module roots we ship; dot-dirs skipped.
 */
export function enumerateGoModules(workspaceRoot: string): string[] {
  const out: string[] = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > GO_MODULE_ENUM_MAX_DEPTH || out.length >= GO_MODULE_ENUM_MAX_MODULES) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    if (entries.some((e) => e.isFile() && e.name === 'go.mod')) out.push(dir);
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (SKIP_DIR_NAMES.has(e.name) || e.name.startsWith('.')) continue;
      walk(path.join(dir, e.name), depth + 1);
    }
  };
  walk(workspaceRoot, 0);
  return out;
}

async function buildGoIndex(ctx: PipelineContext): Promise<TransitiveImportIndex | null> {
  const { supabase, projectId, runId, log, workspaceRoot } = ctx;

  // Trigger guard: only run the toolchain when a gated module is actually a
  // dependency of this project (idna/protojson-class gates).
  const gateModules = goSubpackageGateModules();
  const { data: deps } = await supabase
    .from('project_dependencies')
    .select('name')
    .eq('project_id', projectId)
    .eq('last_seen_extraction_run_id', runId);
  const hasGatedDep = (deps ?? []).some((d: { name?: string | null }) =>
    gateModules.has((d.name ?? '').toLowerCase()),
  );
  if (!hasGatedDep) return null;

  const modules = enumerateGoModules(workspaceRoot);
  if (modules.length === 0) return null;
  if (modules.length >= GO_MODULE_ENUM_MAX_MODULES) {
    // Enumeration cap hit — we cannot promise the union is complete. Refuse.
    await log.warn('dep_import_graph', `go module enumeration capped at ${GO_MODULE_ENUM_MAX_MODULES} — transitive proofs disabled`);
    return emptyTransitiveImportIndex('golang');
  }

  const idx = emptyTransitiveImportIndex('golang');
  for (const moduleDir of modules) {
    const rel = path.relative(workspaceRoot, moduleDir) || '.';
    try {
      // -buildvcs=false: VCS stamping shells out to git and fails on
      // ownership-mismatched mounts (exit 128, "error obtaining VCS status");
      // the compile set doesn't depend on VCS info.
      const stdout = execFileSync('go', ['list', '-deps', '-buildvcs=false', './...'], {
        cwd: moduleDir,
        encoding: 'utf8',
        timeout: GO_LIST_TIMEOUT_MS,
        maxBuffer: 64 * 1024 * 1024,
        env: {
          ...process.env,
          // A repo demanding a newer toolchain FAILS (→ unavailable → refuse)
          // instead of downloading + executing a repo-chosen toolchain binary.
          GOTOOLCHAIN: 'local',
          // Deterministic per-module semantics even when a go.work exists.
          GOWORK: 'off',
          CGO_ENABLED: '0',
        },
      });
      idx.perPackage.set(rel, {
        modules: new Set(parseGoListOutput(stdout)),
        tokenHits: new Set<string>(),
      });
      idx.extractedPackages.add(rel);
    } catch (err: unknown) {
      // ANY module failing means the union could hide an import — Go has no
      // 'partial' (a positive from a succeeded module would still be valid,
      // but we discard everything for simplicity: unavailable = today's
      // behavior, the fail-safe default).
      const msg = err instanceof Error ? err.message : String(err);
      await log.warn('dep_import_graph', `go list failed in ${rel} — transitive proofs disabled: ${msg.slice(0, 300)}`);
      const unavailable = emptyTransitiveImportIndex('golang');
      unavailable.failedPackages.push(rel);
      return unavailable;
    }
  }
  idx.status = 'complete';
  const total = [...idx.perPackage.values()].reduce((n, s) => n + s.modules.size, 0);
  await log.info('dep_import_graph', `go compile set: ${modules.length} module(s), ${total} package path(s)`);
  return idx;
}

// ---------------------------------------------------------------------------
// pypi leg
// ---------------------------------------------------------------------------

export interface PypiQuestionRegistry {
  modules: string[];
  tokens: string[];
  owners: string[];
}

/**
 * The extractor version — cache rows carry it as a replace-in-place column,
 * so editing any row's `question` (registry hash) or the extraction logic
 * (bump the prefix) invalidates cached summaries automatically.
 */
export function pypiExtractorVersion(registry: PypiQuestionRegistry): string {
  const h = crypto
    .createHash('sha256')
    .update(JSON.stringify({ m: registry.modules, t: registry.tokens }))
    .digest('hex')
    .slice(0, 12);
  return `arc2-v1:${h}`;
}

/**
 * Keep only the QUESTION-RELEVANT subset of a dist's imports: an import that
 * is a question module or a descendant of one. v1 only ever asks those
 * memberships (veto-only), and the subset keeps cache rows small.
 */
export function questionRelevantImports(imports: string[], questionModules: string[]): string[] {
  const out = new Set<string>();
  for (const imp of imports) {
    for (const qm of questionModules) {
      if (imp === qm || imp.startsWith(qm + '.')) {
        out.add(imp);
        break;
      }
    }
  }
  return [...out];
}

/**
 * Walk an unpacked dist and extract question-relevant imports + token hits.
 * Returns null when the dist is not meaningfully scannable (zero .py files —
 * e.g. a compiled/empty wheel) or the walk tripped a cap: the caller must
 * record the dist as FAILED (unknown), never as scanned-clean.
 */
export function extractDistSummary(
  distDir: string,
  registry: PypiQuestionRegistry,
): { modules: string[]; tokenHits: string[] } | null {
  const pyFiles: string[] = [];
  const textFiles: string[] = [];
  let totalBytes = 0;
  let capped = false;

  const walk = (dir: string): void => {
    if (capped) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      capped = true;
      return;
    }
    for (const e of entries) {
      if (capped) return;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (e.isFile()) {
        if (pyFiles.length + textFiles.length >= PYPI_MAX_FILES_PER_DIST) {
          capped = true;
          return;
        }
        if (e.name.endsWith('.py')) pyFiles.push(full);
        // Liberal token surface beyond .py: plugin registries + metadata where
        // dotted module strings hide (entry_points.txt, setup.cfg, pyproject).
        else if (/\.(txt|cfg|toml|json)$/i.test(e.name)) textFiles.push(full);
      }
    }
  };
  walk(distDir);
  if (capped) return null;
  if (pyFiles.length === 0) return null; // compiled/empty wheel — unknown, not clean

  const imports = new Set<string>();
  const tokenHits = new Set<string>();
  for (const file of [...pyFiles, ...textFiles]) {
    let statSize = 0;
    try {
      statSize = fs.statSync(file).size;
    } catch {
      return null;
    }
    if (statSize > PYPI_MAX_FILE_BYTES) return null; // oversize → unknown
    totalBytes += statSize;
    if (totalBytes > PYPI_MAX_DIST_BYTES) return null;
    let content: string;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      return null;
    }
    const lower = content.toLowerCase();
    for (const t of registry.tokens) {
      if (lower.includes(t)) tokenHits.add(t);
    }
    if (file.endsWith('.py')) {
      for (const imp of questionRelevantImports(extractPythonImports(content), registry.modules)) {
        imports.add(imp);
      }
    }
  }
  return { modules: [...imports], tokenHits: [...tokenHits] };
}

interface CacheRow {
  package_name: string;
  version: string;
  ecosystem: string;
  extractor_version: string;
  imported_modules: string[] | null;
  question_hits: string[] | null;
}

async function buildPypiIndex(ctx: PipelineContext): Promise<TransitiveImportIndex | null> {
  const { supabase, projectId, runId, log, workspaceRoot } = ctx;
  void workspaceRoot;

  const registry = djangoTransitiveQuestionRegistry();
  if (registry.owners.length === 0) return null;
  const ownerSet = new Set(registry.owners);
  const extractorVersion = pypiExtractorVersion(registry);

  // Load the run's deps once — used for both the trigger and the enumeration.
  const { data: depRows } = await supabase
    .from('project_dependencies')
    .select('id, name, version, environment')
    .eq('project_id', projectId)
    .eq('last_seen_extraction_run_id', runId);
  const deps = (depRows ?? []) as Array<{
    id: string;
    name: string | null;
    version: string | null;
    environment: string | null;
  }>;
  if (deps.length === 0) return null;

  // Trigger guard: a PDV must exist on an OWNER dep (a row the oracle can
  // actually veto). No open question → zero fetches, zero wall-time.
  const { data: pdvRows } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('project_dependency_id')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);
  const pdvDepIds = new Set(
    ((pdvRows ?? []) as Array<{ project_dependency_id: string | null }>)
      .map((r) => r.project_dependency_id)
      .filter((x): x is string => !!x),
  );
  const triggered = deps.some(
    (d) => pdvDepIds.has(d.id) && d.name && ownerSet.has(pep503Normalize(d.name)),
  );
  if (!triggered) return null;

  // Enumerate targets: prod dists (explicit-dev excluded; unknown env counts
  // as prod — inclusion errs toward refusal, the safe direction).
  const maxDists = envInt('DEPTEX_DEP_IMPORT_MAX_DISTS', 500);
  const wallMs = envInt('DEPTEX_DEP_IMPORT_WALL_MS', 240_000);
  const seen = new Set<string>();
  const targets: Array<{ name: string; version: string }> = [];
  for (const d of deps) {
    if (d.environment === 'dev') continue;
    if (!d.name || !d.version) continue;
    const name = pep503Normalize(d.name);
    const key = `${name}@${d.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({ name, version: d.version });
  }
  let capHit = false;
  if (targets.length > maxDists) {
    targets.length = maxDists;
    capHit = true;
  }
  if (targets.length === 0) return null;

  const idx = emptyTransitiveImportIndex('pypi');

  // Cache read — one batched .in() per 200 names; any error (e.g. 42P01 on a
  // not-yet-migrated DB / older PGLite schema) disables the cache for the run.
  const cached = new Map<string, PackageImportSummary>();
  let cacheUsable = true;
  try {
    const names = [...new Set(targets.map((t) => t.name))];
    for (let i = 0; i < names.length; i += 200) {
      const { data, error } = await supabase
        .from('package_import_summaries')
        .select('package_name, version, ecosystem, extractor_version, imported_modules, question_hits')
        .eq('ecosystem', 'pypi')
        .in('package_name', names.slice(i, i + 200));
      if (error) throw new Error(error.message);
      for (const row of (data ?? []) as CacheRow[]) {
        if (row.extractor_version !== extractorVersion) continue;
        cached.set(`${row.package_name}@${row.version}`, {
          modules: new Set(row.imported_modules ?? []),
          tokenHits: new Set(row.question_hits ?? []),
        });
      }
    }
  } catch (err: unknown) {
    cacheUsable = false;
    const msg = err instanceof Error ? err.message : String(err);
    await log.warn('dep_import_graph', `package_import_summaries cache unavailable (${msg.slice(0, 160)}) — fetching uncached`);
  }

  const cache = new DepSourceCache({
    rootDirName: `dep-import-${ctx.job.jobId ?? runId}`,
    artifactPolicy: 'wheel-only',
    label: 'dep-import-graph',
  });
  const limit = pLimit(PYPI_FETCH_CONCURRENCY);
  const startedAt = Date.now();
  const newRows: Array<CacheRow & { files_scanned: number }> = [];

  try {
    await Promise.all(
      targets.map((t) =>
        limit(async () => {
          const key = `${t.name}@${t.version}`;
          const hit = cached.get(key);
          if (hit) {
            idx.perPackage.set(t.name, mergeSummaries(idx.perPackage.get(t.name), hit));
            idx.extractedPackages.add(t.name);
            return;
          }
          if (Date.now() - startedAt > wallMs) {
            capHit = true;
            idx.failedPackages.push(t.name);
            return;
          }
          const entry = await cache.fetch('pypi', t.name, t.version);
          if (!entry) {
            idx.failedPackages.push(t.name);
            return;
          }
          try {
            const summary = extractDistSummary(entry.dir, registry);
            if (!summary) {
              idx.failedPackages.push(t.name);
              return;
            }
            idx.perPackage.set(
              t.name,
              mergeSummaries(idx.perPackage.get(t.name), {
                modules: new Set(summary.modules),
                tokenHits: new Set(summary.tokenHits),
              }),
            );
            idx.extractedPackages.add(t.name);
            if (cacheUsable) {
              newRows.push({
                package_name: t.name,
                version: t.version,
                ecosystem: 'pypi',
                extractor_version: extractorVersion,
                imported_modules: summary.modules,
                question_hits: summary.tokenHits,
                files_scanned: 0,
              });
            }
          } finally {
            // unpack → extract → delete: disk bounded by concurrency, not job length.
            cache.evict('pypi', t.name, t.version);
          }
        }),
      ),
    );
  } finally {
    cache.cleanup();
  }

  // Cache write — replace-in-place on (ecosystem, package_name, version);
  // failed/truncated dists are never written (no partial rows served cross-org).
  if (cacheUsable && newRows.length > 0) {
    try {
      for (let i = 0; i < newRows.length; i += 100) {
        const { error } = await supabase
          .from('package_import_summaries')
          .upsert(newRows.slice(i, i + 100), { onConflict: 'ecosystem,package_name,version' });
        if (error) throw new Error(error.message);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      await log.warn('dep_import_graph', `package_import_summaries cache write failed (${msg.slice(0, 160)})`);
    }
  }

  idx.status =
    idx.failedPackages.length === 0 && !capHit
      ? 'complete'
      : idx.extractedPackages.size > 0
        ? 'partial'
        : 'unavailable';
  await log.info(
    'dep_import_graph',
    `pypi import summaries: ${idx.extractedPackages.size}/${targets.length} dist(s) (${cached.size} cached, ${idx.failedPackages.length} failed${capHit ? ', capped' : ''}) — ${idx.status}`,
  );
  return idx;
}

function mergeSummaries(
  a: PackageImportSummary | undefined,
  b: PackageImportSummary,
): PackageImportSummary {
  if (!a) return b;
  return {
    modules: new Set([...a.modules, ...b.modules]),
    tokenHits: new Set([...a.tokenHits, ...b.tokenHits]),
  };
}

// ---------------------------------------------------------------------------
// Step entry
// ---------------------------------------------------------------------------

export async function doDepImportGraph(ctx: PipelineContext): Promise<TransitiveImportIndex | null> {
  const { supabase, job, projectId, log, jobEcosystem } = ctx;
  if (process.env.DEPTEX_DEP_IMPORT_DISABLE === '1') return null;
  if (jobEcosystem !== 'golang' && jobEcosystem !== 'pypi') return null;

  const result = await runStage<TransitiveImportIndex | null>({
    name: 'dep_import_graph',
    timeoutMs: 6 * 60_000,
    fn: () => (jobEcosystem === 'golang' ? buildGoIndex(ctx) : buildPypiIndex(ctx)),
    supabase: supabase as Storage,
    jobId: job.jobId,
    projectId,
    log,
    // Fail-safe observability: a thrown step = no index = today's behavior.
    severity: 'warn',
  });
  return result ?? null;
}
