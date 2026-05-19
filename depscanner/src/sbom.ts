/**
 * Parse CycloneDX SBOM and extract dependencies for project_dependencies, dependency_version_edges, etc.
 */

import * as fs from 'fs';
import * as path from 'path';

export interface SbomComponent {
  'bom-ref'?: string;
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  group?: string;
  licenses?: unknown;
}

export interface SbomDependency {
  ref: string;
  dependsOn?: string[];
}

export interface CycloneDxSbom {
  bomFormat?: string;
  specVersion?: string;
  metadata?: { component?: SbomComponent };
  components?: SbomComponent[];
  dependencies?: SbomDependency[];
}

export interface ParsedSbomDep {
  name: string;
  version: string;
  namespace: string | null;
  license: string | null;
  is_direct: boolean;
  source: 'dependencies' | 'devDependencies' | 'transitive';
  /**
   * True when this dependency is dev/test/build scope — set by
   * `patchDevDependencies` for direct dev deps (from the manifest) and for
   * transitive deps reachable only via dev roots. Distinct from `source`:
   * a transitively-dev-only dep keeps `source: 'transitive'` (the literal
   * SBOM origin) but carries `devScoped: true`. Persisted indirectly via the
   * `environment` column, never written back into `source`.
   */
  devScoped: boolean;
  bomRef: string;
}

export interface ParsedSbomRelationship {
  parentBomRef: string;
  childBomRef: string;
}

/**
 * Parse any Package URL into type, name, and version.
 * Handles all ecosystem PURL types (pkg:npm/, pkg:pypi/, pkg:maven/, etc.)
 */
function parsePurl(purl: string): { type: string; name: string; version: string | null } | null {
  const match = purl.match(/^pkg:([^/]+)\/(.+?)(?:@([^?#]+))?(?:\?|#|$)/);
  if (!match) return null;
  return {
    type: match[1],
    name: decodeURIComponent(match[2]),
    version: match[3] ? decodeURIComponent(match[3]) : null,
  };
}

function nameFromPurl(purl: string): string {
  return parsePurl(purl)?.name ?? purl.split('/').pop() ?? purl.split('@')[0] ?? '';
}

function versionFromPurl(purl: string): string | null {
  return parsePurl(purl)?.version ?? null;
}

/**
 * Parse the namespace (Maven groupId, NuGet parent namespace, etc.) from a
 * purl. For `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` returns
 * `org.apache.logging.log4j`. Returns null for single-segment ecosystems
 * (npm without scope, pypi, go, cargo, rubygems, nuget without nesting).
 */
function namespaceFromPurl(purl: string): string | null {
  const parsed = parsePurl(purl);
  if (!parsed) return null;
  const slashIdx = parsed.name.lastIndexOf('/');
  if (slashIdx === -1) return null;
  return parsed.name.slice(0, slashIdx);
}

/**
 * Map bom-ref to name@version for building edges.
 */
export function getBomRefToNameVersion(sbom: CycloneDxSbom): Map<string, { name: string; version: string }> {
  const map = new Map<string, { name: string; version: string }>();
  const components = sbom.components || [];
  for (const c of components) {
    const ref = c['bom-ref'];
    if (!ref) continue;
    let name = c.name;
    let version = c.version ?? null;
    if (c.purl) {
      if (!name) name = nameFromPurl(c.purl);
      if (!version) version = versionFromPurl(c.purl);
    }
    if (name && version) {
      map.set(ref, { name, version });
    }
  }
  return map;
}

/**
 * Parse CycloneDX SBOM into dependency rows and relationships.
 */
export function parseSbom(sbom: CycloneDxSbom): {
  dependencies: ParsedSbomDep[];
  relationships: ParsedSbomRelationship[];
  /** Number of components present in the SBOM before name/version filtering. */
  rawComponentCount: number;
  /** Components dropped because name or version couldn't be resolved (e.g. cdxgen
   *  emitted a name without a version when the package manager failed to
   *  resolve it). Surfacing this lets the pipeline distinguish "manifest empty"
   *  from "manifest had stuff we couldn't parse." */
  droppedVersionlessCount: number;
  /** False when cdxgen returned an unwired CycloneDX `dependencies` graph (no
   *  root node / no edges). When false, the direct/transitive split on every
   *  dep is untrustworthy — the caller must run lockfile/tree graph recovery
   *  (`dependency-graph/`) before relying on `is_direct`, and the reachability
   *  classifier must floor at `module` (never `unreachable`) if recovery also
   *  fails. */
  directSetTrusted: boolean;
} {
  const components = sbom.components || [];
  const depGraph = sbom.dependencies || [];
  const rawComponentCount = components.length;
  let droppedVersionlessCount = 0;

  const bomRefToComponent = new Map<string, SbomComponent>();
  for (const c of components) {
    const ref = c['bom-ref'];
    if (ref) bomRefToComponent.set(ref, c);
  }

  const rootRef = sbom.metadata?.component?.['bom-ref'];
  const directRefs = new Set<string>();
  if (rootRef) {
    const rootDep = depGraph.find((d) => d.ref === rootRef);
    if (rootDep?.dependsOn) {
      for (const ref of rootDep.dependsOn) {
        directRefs.add(ref);
      }
    }
  }

  const allDeps = new Set<string>();
  function collectTransitive(ref: string) {
    if (allDeps.has(ref)) return;
    allDeps.add(ref);
    const d = depGraph.find((x) => x.ref === ref);
    if (d?.dependsOn) {
      for (const child of d.dependsOn) {
        collectTransitive(child);
      }
    }
  }
  for (const ref of directRefs) {
    collectTransitive(ref);
  }

  // Fallback: cdxgen's CycloneDX `dependencies` graph came back unwired (no
  // root node, or the root has no edges — common on pypi/maven SBOMs). Include
  // every component so no valid package is dropped, but DO NOT mark them direct
  // — the old behaviour (everything `is_direct: true`) structurally disabled
  // the `unreachable` reachability tier. `directSetTrusted = false` tells the
  // pipeline to run lockfile/tree graph recovery to rebuild the direct set.
  let directSetTrusted = true;
  if (allDeps.size === 0 && components.length > 0) {
    directSetTrusted = false;
    for (const c of components) {
      const ref = c['bom-ref'];
      if (ref) allDeps.add(ref);
    }
  }

  const relationships: ParsedSbomRelationship[] = [];
  for (const d of depGraph) {
    if (d.dependsOn) {
      for (const child of d.dependsOn) {
        relationships.push({ parentBomRef: d.ref, childBomRef: child });
      }
    }
  }

  const nameVersionToSource = new Map<string, 'dependencies' | 'devDependencies'>();

  const dependencies: ParsedSbomDep[] = [];

  for (const ref of allDeps) {
    const comp = bomRefToComponent.get(ref);
    if (!comp) continue;

    let name = comp.name;
    let version = comp.version ?? null;
    if (comp.purl) {
      if (!name) name = nameFromPurl(comp.purl);
      if (!version) version = versionFromPurl(comp.purl);
    }
    if (!name || !version) {
      droppedVersionlessCount++;
      continue;
    }

    const license = extractLicense(comp.licenses);

    const isDirect = directRefs.has(ref);
    const source: 'dependencies' | 'devDependencies' | 'transitive' = isDirect ? 'dependencies' : 'transitive';

    // Prefer explicit comp.group (cdxgen always sets it for Maven), fall back
    // to parsing the purl when the SBOM generator omits it.
    const namespace = comp.group ?? (comp.purl ? namespaceFromPurl(comp.purl) : null);

    dependencies.push({
      name,
      version,
      namespace,
      license,
      is_direct: isDirect,
      source,
      devScoped: false,
      bomRef: ref,
    });
  }

  return { dependencies, relationships, rawComponentCount, droppedVersionlessCount, directSetTrusted };
}

function extractLicense(licenses: unknown): string | null {
  if (!licenses) return null;
  if (typeof licenses === 'string') return licenses;
  if (Array.isArray(licenses) && licenses.length > 0) {
    const first = licenses[0] as { license?: { id?: string; name?: string } };
    if (first?.license?.id) return first.license.id;
    if (first?.license?.name) return first.license.name;
  }
  if (typeof licenses === 'object' && licenses !== null && 'license' in licenses) {
    const l = (licenses as { license?: { id?: string; name?: string } }).license;
    return l?.id ?? l?.name ?? null;
  }
  return null;
}

/**
 * Cross-reference parsed SBOM deps with actual manifest files to correctly identify devDependencies.
 * CycloneDX SBOMs from cdxgen don't reliably distinguish dev from prod deps.
 */
export function patchDevDependencies(deps: ParsedSbomDep[], repoRoot: string, ecosystem: string): void {
  const devNames = collectDevDependencyNames(repoRoot, ecosystem);
  if (devNames.size === 0) return;

  for (const dep of deps) {
    if (!dep.is_direct) continue;
    // Maven dev names are keyed `groupId:artifactId`; `dep.name` is the bare
    // artifactId, so probe the namespaced form too. Other ecosystems key on
    // the bare name.
    const namespaced = dep.namespace ? `${dep.namespace}:${dep.name}` : null;
    if (devNames.has(dep.name) || (namespaced && devNames.has(namespaced))) {
      dep.source = 'devDependencies';
      dep.devScoped = true;
    }
  }
}

function collectDevDependencyNames(repoRoot: string, ecosystem: string): Set<string> {
  const devNames = new Set<string>();

  if (ecosystem === 'npm') {
    collectNpmDevDeps(repoRoot, devNames);
  } else if (ecosystem === 'pypi') {
    collectPypiDevDeps(repoRoot, devNames);
  } else if (ecosystem === 'maven') {
    collectMavenDevDeps(repoRoot, devNames);
  } else if (ecosystem === 'cargo') {
    collectCargoDevDeps(repoRoot, devNames);
  }

  return devNames;
}

function collectCargoDevDeps(repoRoot: string, devNames: Set<string>): void {
  const cargoPath = path.join(repoRoot, 'Cargo.toml');
  try {
    const content = fs.readFileSync(cargoPath, 'utf8');
    // Crate names under [dev-dependencies] / [build-dependencies] and their
    // target-specific variants, e.g. [target.'cfg(unix)'.dev-dependencies].
    // Tracked line-by-line: each `[section]` header opens/closes a section.
    let inDevSection = false;
    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      const header = line.match(/^\[([^\]]+)\]$/);
      if (header) {
        inDevSection = /(?:^|\.)(?:dev|build)-dependencies$/.test(header[1].trim());
        continue;
      }
      if (!inDevSection || !line || line.startsWith('#')) continue;
      // `name = "1.0"`, `name = { version = "1" }`, or `name.workspace = true`
      const m = line.match(/^([A-Za-z0-9_-]+)\s*[.=]/);
      if (m) devNames.add(m[1]);
    }
  } catch { /* no Cargo.toml or parse error */ }
}

function collectNpmDevDeps(repoRoot: string, devNames: Set<string>): void {
  const pkgPath = path.join(repoRoot, 'package.json');
  try {
    const raw = fs.readFileSync(pkgPath, 'utf8');
    const pkg = JSON.parse(raw) as { devDependencies?: Record<string, string> };
    if (pkg.devDependencies) {
      for (const name of Object.keys(pkg.devDependencies)) devNames.add(name);
    }
  } catch { /* no package.json or parse error */ }
}

function collectPypiDevDeps(repoRoot: string, devNames: Set<string>): void {
  // pyproject.toml: [tool.poetry.dev-dependencies] or [project.optional-dependencies]
  const pyprojectPath = path.join(repoRoot, 'pyproject.toml');
  try {
    const content = fs.readFileSync(pyprojectPath, 'utf8');
    // Simple heuristic: lines under [tool.poetry.dev-dependencies] until next section
    const devSection = content.match(
      /\[tool\.poetry\.dev-dependencies\]([\s\S]*?)(?=\n\[|\n$)/
    );
    if (devSection) {
      const lines = devSection[1].split('\n');
      for (const line of lines) {
        const match = line.match(/^(\S+)\s*=/);
        if (match && match[1] !== 'python') devNames.add(match[1]);
      }
    }
  } catch { /* ignore */ }

  // requirements-dev.txt
  const reqDevPath = path.join(repoRoot, 'requirements-dev.txt');
  try {
    const content = fs.readFileSync(reqDevPath, 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
      const name = trimmed.split(/[=<>!~[\s]/)[0];
      if (name) devNames.add(name.toLowerCase());
    }
  } catch { /* ignore */ }
}

function collectMavenDevDeps(repoRoot: string, devNames: Set<string>): void {
  const pomPath = path.join(repoRoot, 'pom.xml');
  try {
    const content = fs.readFileSync(pomPath, 'utf8');
    // Match dependencies with <scope>test</scope> or <scope>provided</scope>
    const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>[\s\S]*?<scope>(test|provided)<\/scope>[\s\S]*?<\/dependency>/g;
    let match;
    while ((match = depRegex.exec(content)) !== null) {
      devNames.add(`${match[1]}:${match[2]}`);
    }
  } catch { /* ignore */ }
}
