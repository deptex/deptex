/**
 * NuGet (.NET) dependency resolver.
 *
 * cdxgen resolves .NET `PackageReference` projects via the dotnet SDK
 * (`dotnet restore` → `project.assets.json`). The depscanner image ships no
 * .NET SDK, so cdxgen returns zero components even when the repo commits a
 * `packages.lock.json` — leaving the whole SCA pass with no dependencies to
 * scan.
 *
 * We parse `packages.lock.json` directly. The format is deterministic and
 * carries the full resolved tree with Direct/Transitive markers, so it is a
 * strictly better source than cdxgen's (empty) SBOM and needs no SDK.
 *
 * packages.lock.json format (excerpt):
 *
 *   {
 *     "version": 1,
 *     "dependencies": {
 *       "net6.0": {
 *         "Newtonsoft.Json": {
 *           "type": "Direct",
 *           "resolved": "12.0.3",
 *           "dependencies": { "Some.Transitive": "1.2.3" }
 *         },
 *         "Some.Transitive": { "type": "Transitive", "resolved": "1.2.3" }
 *       }
 *     }
 *   }
 *
 * Every entry under a target-framework block is a resolved package; `type`
 * distinguishes the directly-referenced set from transitives, and each entry's
 * nested `dependencies` map gives the edges.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ParsedSbomDep, ParsedSbomRelationship } from '../sbom';
import type { TransitiveResolverResult } from './go';

interface LockEntry {
  type?: string;
  resolved?: string;
  dependencies?: Record<string, string>;
}

/**
 * Resolve .NET packages by parsing packages.lock.json. Returns null when the
 * lock file is absent (a project without a committed lock can only be resolved
 * by cdxgen + the SDK, which we don't ship).
 */
export async function resolveNugetLock(
  repoRoot: string,
): Promise<TransitiveResolverResult | null> {
  const lockPath = path.join(repoRoot, 'packages.lock.json');
  if (!fs.existsSync(lockPath)) return null;

  let parsed: { dependencies?: Record<string, Record<string, LockEntry>> };
  try {
    parsed = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  } catch {
    return null;
  }
  const frameworks = parsed.dependencies;
  if (!frameworks || typeof frameworks !== 'object') return null;

  // Dedup across target-framework blocks: a package resolved to the same
  // version under both net6.0 and net8.0 is one dependency. First write wins
  // on `is_direct` (Direct beats Transitive — a package directly referenced in
  // any TFM is a direct dependency of the project).
  const byKey = new Map<string, ParsedSbomDep>();
  const bomRef = (name: string, version: string) => `nuget-lock-resolver:${name}@${version}`;

  for (const pkgs of Object.values(frameworks)) {
    if (!pkgs || typeof pkgs !== 'object') continue;
    for (const [name, entry] of Object.entries(pkgs)) {
      const version = entry?.resolved;
      if (!name || !version) continue;
      const isDirect = entry?.type === 'Direct';
      const key = `${name}@${version}`;
      const existing = byKey.get(key);
      if (existing) {
        if (isDirect && !existing.is_direct) {
          existing.is_direct = true;
          existing.source = 'dependencies';
        }
        continue;
      }
      byKey.set(key, {
        name,
        version,
        namespace: null,
        license: null,
        is_direct: isDirect,
        source: isDirect ? 'dependencies' : 'transitive',
        devScoped: false,
        bomRef: bomRef(name, version),
      });
    }
  }

  const deps = Array.from(byKey.values());

  // Build edges from each entry's nested `dependencies` map. The child is
  // referenced by name only (no version) in the lock, so resolve the version
  // from the resolved set in the same TFM block.
  const relationships: ParsedSbomRelationship[] = [];
  const seenEdge = new Set<string>();
  for (const pkgs of Object.values(frameworks)) {
    if (!pkgs || typeof pkgs !== 'object') continue;
    const versionOf = new Map<string, string>();
    for (const [name, entry] of Object.entries(pkgs)) {
      if (entry?.resolved) versionOf.set(name, entry.resolved);
    }
    for (const [name, entry] of Object.entries(pkgs)) {
      const parentVersion = entry?.resolved;
      if (!parentVersion || !entry?.dependencies) continue;
      for (const childName of Object.keys(entry.dependencies)) {
        const childVersion = versionOf.get(childName);
        if (!childVersion) continue;
        const edgeKey = `${name}@${parentVersion}->${childName}@${childVersion}`;
        if (seenEdge.has(edgeKey)) continue;
        seenEdge.add(edgeKey);
        relationships.push({
          parentBomRef: bomRef(name, parentVersion),
          childBomRef: bomRef(childName, childVersion),
        });
      }
    }
  }

  return {
    deps,
    relationships,
    rawModuleCount: deps.length,
    source: 'nuget-lock-parse',
  };
}
