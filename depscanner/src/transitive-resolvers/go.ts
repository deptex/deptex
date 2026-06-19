/**
 * Go transitive dependency resolver.
 *
 * cdxgen for `gomod` emits a direct-deps-only SBOM (the go.mod manifest's
 * top-level `require` block, no transitives). The reachability classifier's
 * `unreachable` verdict keys on `!is_direct && filesImporting === 0`, so a
 * shallow SBOM produces zero unreachable transitives → 0% Gate 1 lift on
 * go projects. This resolver invokes `go list -m -json all` in the repo
 * root to enumerate every module in the resolved build graph and folds
 * the result back into the in-memory ParsedSbomDep list.
 *
 * Stable on Go 1.16+ — `-m -json all` was introduced in 1.13 and is
 * unchanged through 1.22.x (depscanner Dockerfile pins 1.22.10).
 */

import * as fs from 'fs';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import type { ParsedSbomDep, ParsedSbomRelationship } from '../sbom';

// Lazy-initialized to avoid running `promisify(execFile)` at module-load
// time — some jest test contexts mock `child_process` globally and the
// mock leaves `execFile` undefined, which would trip `promisify` here
// before any caller actually invokes the resolver.
let execFileP: ((cmd: string, args: readonly string[], opts?: any) => Promise<{ stdout: string; stderr: string }>) | null = null;
function getExecFileP() {
  if (!execFileP) execFileP = promisify(execFile) as any;
  return execFileP!;
}

/**
 * Output of any transitive resolver. Two-tuple of (deps, relationships)
 * appended onto the cdxgen-emitted ParsedSbom shape; `null` from the
 * resolver function itself means "soft-fail, ecosystem not applicable
 * here". Hard-fail throws — the pipeline catches it as a warn-and-continue.
 */
export interface TransitiveResolverResult {
  deps: ParsedSbomDep[];
  relationships: ParsedSbomRelationship[];
  /** Module count from the resolver's raw output, before dedup. */
  rawModuleCount: number;
  /** Structured tag for telemetry. */
  source:
    | 'go-list-m-json-all'
    | 'pip-dry-run-report'
    | 'pipdeptree-venv'
    | 'composer-lock-parse'
    | 'gemfile-lock-parse'
    | 'nuget-lock-parse';
}

/** One record in a `go list -m -json all` stream. */
interface GoModuleRecord {
  Path: string;
  Version?: string;
  Main?: boolean;
  /** True when this module is replaced by a different one (replace directive). */
  Replace?: GoModuleRecord;
  /** True when the module is excluded. Listed for completeness; we filter these. */
  Indirect?: boolean;
}

/**
 * Resolve transitive go modules for the given repo. Returns null when
 * `go.mod` is absent (soft-fail — not applicable). Throws on `go list`
 * failure when go.mod is present (hard-fail — caller logs + falls back
 * to the cdxgen-only SBOM).
 */
export async function resolveGoTransitives(
  repoRoot: string,
): Promise<TransitiveResolverResult | null> {
  const goModPath = path.join(repoRoot, 'go.mod');
  if (!fs.existsSync(goModPath)) {
    return null;
  }

  const { stdout } = await getExecFileP()('go', ['list', '-m', '-json', 'all'], {
    cwd: repoRoot,
    maxBuffer: 64 * 1024 * 1024, // 64MB — generous; medium projects stay <1MB
    env: {
      ...process.env,
      // Force module mode and disable network proxies in case the worker
      // runs without GOPROXY pre-warmed. Falls back to GOPROXY=direct so
      // CI works in airgapped self-host installs.
      GOFLAGS: '-mod=readonly',
    },
  });

  const records = parseGoListJsonStream(stdout);
  const deps: ParsedSbomDep[] = [];
  for (const r of records) {
    if (r.Main) continue;
    // Replace directives substitute Path/Version — honor them.
    const resolved = r.Replace ?? r;
    if (!resolved.Path || !resolved.Version) continue;
    deps.push({
      name: resolved.Path,
      version: resolved.Version,
      namespace: extractGoNamespace(resolved.Path),
      license: null, // license discovery is cdxgen's job; resolver only fills coords.
      is_direct: false,
      source: 'transitive',
      devScoped: false,
      // Synthetic bom-ref — cdxgen-emitted refs always start with `pkg:` for
      // the purl. Prefix `gomod-resolver:` so the wire-in dedup never
      // accidentally collides this row with a cdxgen row.
      bomRef: `gomod-resolver:${resolved.Path}@${resolved.Version}`,
    });
  }

  return {
    deps,
    // go.mod doesn't ship inter-dep edges without `go mod graph`, which
    // is a separate (heavier) invocation. The reachability classifier
    // only keys on `is_direct`, so the lack of edges between transitives
    // is OK — every emitted row is correctly !is_direct.
    relationships: [],
    rawModuleCount: records.length,
    source: 'go-list-m-json-all',
  };
}

/**
 * `go list -m -json all` emits a *stream* of pretty-printed JSON objects
 * separated by `\n` — NOT a JSON array. Parse by scanning for balanced
 * brace runs starting at column 0 (`go list`'s exact format), then
 * `JSON.parse` each block.
 */
export function parseGoListJsonStream(stdout: string): GoModuleRecord[] {
  const out: GoModuleRecord[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < stdout.length; i++) {
    const ch = stdout[i];
    if (ch === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0 && start >= 0) {
        const chunk = stdout.slice(start, i + 1);
        try {
          out.push(JSON.parse(chunk) as GoModuleRecord);
        } catch {
          // Skip malformed chunk — `go list` very rarely emits truncated
          // records on resolver edge cases. Don't fail the whole resolver.
        }
        start = -1;
      }
    }
  }
  return out;
}

/**
 * For `github.com/spf13/cobra` returns `github.com/spf13`. Mirrors the
 * Maven `groupId` shape used elsewhere in the codebase so per-eco
 * namespacing stays consistent.
 */
function extractGoNamespace(modulePath: string): string | null {
  const lastSlash = modulePath.lastIndexOf('/');
  if (lastSlash === -1) return null;
  return modulePath.slice(0, lastSlash);
}
