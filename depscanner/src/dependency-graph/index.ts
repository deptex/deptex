/**
 * Dependency-graph recovery.
 *
 * cdxgen sometimes returns a CycloneDX SBOM whose `dependencies` graph is
 * unwired — no root node, no edges. When that happens `parseSbom()` can't tell
 * direct dependencies from transitive ones, and the historical fallback marked
 * every component `is_direct: true`, which structurally disabled the
 * `unreachable` reachability tier (it requires `!is_direct`). That is the root
 * cause of whole ecosystems scoring 0% noise reduction.
 *
 * This module rebuilds the direct set from ground truth — the ecosystem's
 * manifest, or for Maven/PyPI the resolved dependency tree — so `is_direct`
 * stays trustworthy regardless of cdxgen's graph quality.
 */

import type { ParsedSbomDep } from '../sbom';
import {
  parseNpmDirectSet,
  parseComposerDirectSet,
  parseGolangDirectSet,
  parseCargoDirectSet,
  parseGemDirectSet,
  parseMavenDirectSet,
  parsePypiDirectSet,
  normalizePypiName,
} from './parsers';

export type RecoveryMethod = 'lockfile' | 'manifest' | 'mvn_tree' | 'pipdeptree';

export interface GraphRecoveryResult {
  /** Match keys (see `depMatchKey`) for every dependency the project declares
   *  directly. A dep absent from this set is transitive. */
  directKeys: Set<string>;
  /** Which strategy produced the set, for the `graph_recovery` telemetry tag. */
  method: RecoveryMethod;
}

/**
 * Canonical key for reconciling a recovered direct set against parsed SBOM
 * components. Maven artifacts collide on bare `artifactId` across groups, so
 * Maven keys carry the `groupId`. PyPI names fold `_`/`.`/`-` and case. Every
 * other ecosystem keys on the lowercased name alone.
 */
export function depMatchKey(name: string, namespace: string | null, ecosystem: string): string {
  if (ecosystem === 'maven') {
    const artifact = name.trim().toLowerCase();
    return namespace ? `${namespace.trim().toLowerCase()}:${artifact}` : artifact;
  }
  if (ecosystem === 'pypi') {
    return normalizePypiName(name);
  }
  return name.trim().toLowerCase();
}

/** Which recovery method each ecosystem uses, for telemetry labelling. */
function methodFor(ecosystem: string): RecoveryMethod {
  if (ecosystem === 'maven') return 'mvn_tree';
  if (ecosystem === 'pypi') return 'pipdeptree';
  // npm/cargo/composer/golang/gem all recover from their committed manifest.
  return 'manifest';
}

/**
 * Recover the direct dependency set for an ecosystem. Returns `null` when the
 * manifest/tree is absent or unreadable — the caller treats that as "recovery
 * unavailable" and must NOT mark anything `unreachable`.
 */
export function recoverDirectSet(
  ecosystem: string,
  workspaceRoot: string,
): GraphRecoveryResult | null {
  let directKeys: Set<string> | null;
  switch (ecosystem) {
    case 'npm':      directKeys = parseNpmDirectSet(workspaceRoot); break;
    case 'composer': directKeys = parseComposerDirectSet(workspaceRoot); break;
    case 'golang':   directKeys = parseGolangDirectSet(workspaceRoot); break;
    case 'cargo':    directKeys = parseCargoDirectSet(workspaceRoot); break;
    case 'gem':      directKeys = parseGemDirectSet(workspaceRoot); break;
    case 'maven':    directKeys = parseMavenDirectSet(workspaceRoot); break;
    case 'pypi':     directKeys = parsePypiDirectSet(workspaceRoot); break;
    default:         directKeys = null;
  }
  if (!directKeys || directKeys.size === 0) return null;
  return { directKeys, method: methodFor(ecosystem) };
}

/**
 * Overwrite `is_direct` / `source` on parsed SBOM deps from a recovered direct
 * set. Mutates `deps` in place; returns how many entries flipped, for logging.
 * Run BEFORE `patchDevDependencies()` so the dev refinement sees a correct
 * direct set.
 */
export function applyRecoveredDirectSet(
  deps: ParsedSbomDep[],
  recovery: GraphRecoveryResult,
  ecosystem: string,
): number {
  let changed = 0;
  for (const dep of deps) {
    const isDirect = recovery.directKeys.has(depMatchKey(dep.name, dep.namespace, ecosystem));
    if (isDirect !== dep.is_direct) {
      changed++;
      dep.is_direct = isDirect;
      // `patchDevDependencies()` may later move a direct dep to 'devDependencies'.
      dep.source = isDirect ? 'dependencies' : 'transitive';
    }
  }
  return changed;
}
