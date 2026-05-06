/**
 * Per-finding reachability resolver for malicious-package findings.
 *
 * Self-contained: takes the extractUsage() output (imports + usages) and
 * classifies each malicious package into one of four levels:
 *
 *   - `unimported`       — no file imports the dep at all.
 *   - `imported_unused`  — at least one file imports the dep but no usage
 *                          slice references it (dead import).
 *   - `module`           — a symbol from the dep is referenced as a member
 *                          (e.g. `pkg.foo` read but never called).
 *   - `function`         — a symbol from the dep is invoked
 *                          (call / constructor / new / JSX tag).
 *
 * No whole-program propagation, no taint engine. The "callgraph" here is
 * just the existing per-file usage slices — sufficient for the malicious
 * use-case because we only care whether the package is reached at all,
 * not which sink it flows to.
 */
import type {
  ExtractedFile,
  ImportBinding,
  KnownDep,
  SupportedEcosystem,
  UsageSlice,
} from '../tree-sitter-extractor';
import { resolveImportToDep } from '../tree-sitter-extractor';

export type ReachabilityLevel =
  | 'unimported'
  | 'imported_unused'
  | 'module'
  | 'function';

export interface ReachabilityDetails {
  entry_points?: string[];
  call_chain?: string[];
  sink_file?: string;
  sink_line?: number;
}

export interface ReachabilityResult {
  level: ReachabilityLevel;
  details: ReachabilityDetails;
}

/**
 * Pre-indexed view of an `extractUsage` run keyed by dep name.
 * Build once per project, query once per finding — O(1) lookup.
 */
export interface ReachabilityIndex {
  importsByDep: Map<string, Array<{ file: string; binding: ImportBinding }>>;
  usagesByDep: Map<string, UsageSlice[]>;
}

const EMPTY_INDEX: ReachabilityIndex = {
  importsByDep: new Map(),
  usagesByDep: new Map(),
};

export function emptyReachabilityIndex(): ReachabilityIndex {
  return { importsByDep: new Map(), usagesByDep: new Map() };
}

/**
 * Build the per-dep lookup index from an `extractUsage()` file list.
 * Handles import resolution (so callers don't need to re-run the dep
 * resolver) and groups usages by their already-resolved `depName`.
 */
export function buildReachabilityIndex(
  files: readonly ExtractedFile[],
  ecosystem: SupportedEcosystem,
  deps: readonly KnownDep[],
): ReachabilityIndex {
  const importsByDep = new Map<string, Array<{ file: string; binding: ImportBinding }>>();
  const usagesByDep = new Map<string, UsageSlice[]>();

  for (const f of files) {
    for (const binding of f.imports) {
      const dep = resolveImportToDep(binding.source, ecosystem, deps);
      if (!dep) continue;
      let arr = importsByDep.get(dep);
      if (!arr) {
        arr = [];
        importsByDep.set(dep, arr);
      }
      arr.push({ file: f.filePath, binding });
    }
    for (const usage of f.usages) {
      if (!usage.depName) continue;
      let arr = usagesByDep.get(usage.depName);
      if (!arr) {
        arr = [];
        usagesByDep.set(usage.depName, arr);
      }
      arr.push(usage);
    }
  }

  return { importsByDep, usagesByDep };
}

/**
 * `member` = read access without invocation → `module` level.
 * Everything else (call / constructor / new / tag) = invocation → `function`.
 */
function isInvocation(usage: UsageSlice): boolean {
  return usage.targetType !== 'member';
}

/**
 * Classify a single (package, ecosystem) tuple into a reachability level.
 *
 * `index` is the pre-built per-project lookup. For unit tests, callers
 * can pass `emptyReachabilityIndex()` to assert the unimported branch
 * without spinning up extractUsage.
 */
export function computeReachability(
  index: ReachabilityIndex | undefined,
  packageName: string,
  // ecosystem reserved for future per-ecosystem name normalisation
  // (e.g. Maven groupId:artifactId vs npm flat name); resolver currently
  // matches on the canonical dep-name string the SBOM produced.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _ecosystem: string,
): ReachabilityResult {
  const idx = index ?? EMPTY_INDEX;

  const imports = idx.importsByDep.get(packageName) ?? [];
  if (imports.length === 0) {
    return { level: 'unimported', details: {} };
  }

  const usages = idx.usagesByDep.get(packageName) ?? [];
  if (usages.length === 0) {
    // Imported but never referenced — dead import.
    const first = imports[0];
    return {
      level: 'imported_unused',
      details: {
        sink_file: first.file,
        sink_line: first.binding.line,
      },
    };
  }

  const invocations = usages.filter(isInvocation);
  if (invocations.length === 0) {
    // Only member-reads (e.g. `pkg.VERSION`); nothing called.
    const sink = usages[0];
    return {
      level: 'module',
      details: {
        sink_file: sink.filePath,
        sink_line: sink.lineNumber,
      },
    };
  }

  // function-level: invoked at least once.
  const sink = invocations[0];
  const callChain = invocations
    .slice(0, 5) // cap details payload — first 5 call sites is enough for the tooltip
    .map((u) => `${u.filePath}:${u.lineNumber}${u.containingMethod ? ` (${u.containingMethod})` : ''}`);
  const entryPoints = Array.from(
    new Set(
      invocations
        .map((u) => u.containingMethod)
        .filter((m): m is string => Boolean(m)),
    ),
  ).slice(0, 5);

  return {
    level: 'function',
    details: {
      entry_points: entryPoints.length > 0 ? entryPoints : undefined,
      call_chain: callChain,
      sink_file: sink.filePath,
      sink_line: sink.lineNumber,
    },
  };
}
