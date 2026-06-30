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
  /**
   * npm-only fallback signal: true when the npm lockfile (`package-lock.json`)
   * marks this package `"dev": true`. cdxgen's edge-graph dev propagation
   * (`devScoped` pass 2) is fragile and frequently leaves a transitive-of-dev
   * package un-scoped — but npm's lockfile records the resolved dev flag on
   * every package directly. `deps-sync` consults this only when `environment`
   * would otherwise resolve to `null`, so it never downgrades an already-'dev'
   * dep. Set by `patchDevDependencies` for the npm ecosystem; left undefined
   * for every other ecosystem (their lockfiles are read by their own
   * resolvers, not here).
   */
  lockfileDev?: boolean;
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
 * Strip a non-canonical leading `v` from an SBOM version string.
 *
 * Go module versions are canonically v-prefixed (`v1.5.0`,
 * `gopkg.in/yaml.v2@v2.2.2`) and OSV / dep-scan match on that exact form, so Go
 * is left untouched. For every other ecosystem a leading `v` before a digit is
 * non-canonical (e.g. Packagist tags like `v5.2.16`); left in place it splits
 * one package into two `project_dependencies` rows — `v5.2.16` from the SBOM
 * and `5.2.16` from the transitive resolver (which already strips it) — which
 * doubles every CVE attached to the package. Only strips when a digit follows
 * the `v` so versions that genuinely start with a letter are never mangled.
 * Leaves versions with no purl untouched (unknown ecosystem — don't guess).
 */
export function normalizeSbomVersion(version: string, purl: string | undefined): string {
  if (!purl) return version;
  if (parsePurl(purl)?.type?.toLowerCase() === 'golang') return version;
  return version.replace(/^[vV](?=\d)/, '');
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
    if (version) version = normalizeSbomVersion(version, c.purl);
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
    if (version) version = normalizeSbomVersion(version, comp.purl);
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

/**
 * Whether an npm package.json declares at least one dependency (any of the four
 * dependency blocks). Used by the SBOM step to decide whether an empty SBOM is a
 * hard failure: npm is the one ecosystem where a single unresolvable/unpublished
 * dependency aborts the whole `npm install` and — with no committed lockfile for
 * cdxgen to read statically — zeroes the SBOM. If the manifest declared deps we
 * couldn't resolve, that's a failed scan; if it declared none, it's a
 * legitimately zero-dependency project and not an error.
 */
export function npmManifestDeclaresDependencies(workspaceRoot: string): boolean {
  try {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(workspaceRoot, 'package.json'), 'utf8'),
    ) as Record<string, unknown>;
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const block = pkg[field];
      if (block && typeof block === 'object' && Object.keys(block as object).length > 0) return true;
    }
    return false;
  } catch {
    return false;
  }
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
export function patchDevDependencies(
  deps: ParsedSbomDep[],
  repoRoot: string,
  ecosystem: string,
  relationships: ParsedSbomRelationship[] = [],
  directSetTrusted = true,
): void {
  const devNames = collectDevDependencyNames(repoRoot, ecosystem);
  if (devNames.size === 0) return;

  // Pass 1 — direct dev marking from the manifest (always trustworthy).
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

  // npm lockfile-dev fallback capture (npm only). cdxgen's edge-graph dev
  // propagation below (pass 2) is fragile — on real frontends it routinely
  // leaves build/test-only transitives (rollup, esbuild, @babel/core, ajv,
  // js-yaml, brace-expansion, …) un-scoped. npm's own lockfile records the
  // resolved `"dev": true` flag on every package, so stamp `lockfileDev` from
  // it and let `deps-sync` use it as the `environment === null` fallback.
  // Only marks dev-only packages true; never clears a flag, so it can't
  // un-scope anything pass 1/2 already caught.
  if (ecosystem === 'npm') {
    const lockfileDevKeys = collectNpmLockfileDevSet(repoRoot);
    if (lockfileDevKeys.size > 0) {
      for (const dep of deps) {
        // Key on both `name@version` (exact resolved package) and bare `name`
        // (npm v3 nests by path, so a transitive may not match the version we
        // see — bare-name still pins dev-only packages correctly because npm
        // only records `dev: true` when the package is dev-only everywhere).
        if (lockfileDevKeys.has(`${dep.name}@${dep.version}`) || lockfileDevKeys.has(dep.name)) {
          dep.lockfileDev = true;
        }
      }
    }
  }

  // Pass 2 — transitive dev-only propagation. A transitive dependency that is
  // reachable in the cdxgen dependency graph only via devDependency roots —
  // never via a production root — is itself dev-only. Skipped when the graph
  // is untrusted (the direct-set fallback marked every dep transitive, so the
  // closure would be meaningless); direct-dev marking from pass 1 still holds.
  //
  // Maven is excluded: cdxgen's maven `dependencies` graph is too shallow to
  // compute prod-reachability — a test-scope starter (testcontainers, the
  // *-test starters) pulls a large subtree that overlaps production
  // (jackson, logback, micrometer), and the production-side edges several
  // hops down are not wired, so the closure mis-marks genuine prod
  // transitives dev-only. Maven dev-scope therefore comes from pass-1 direct
  // `<scope>test</scope>` / `provided` deps alone.
  if (!directSetTrusted || relationships.length === 0 || ecosystem === 'maven') return;

  const adjacency = new Map<string, string[]>();
  for (const rel of relationships) {
    const kids = adjacency.get(rel.parentBomRef);
    if (kids) kids.push(rel.childBomRef);
    else adjacency.set(rel.parentBomRef, [rel.childBomRef]);
  }
  const closureFrom = (rootRefs: string[]): Set<string> => {
    const seen = new Set<string>(rootRefs);
    const queue = [...rootRefs];
    while (queue.length > 0) {
      const ref = queue.pop()!;
      for (const child of adjacency.get(ref) ?? []) {
        if (!seen.has(child)) {
          seen.add(child);
          queue.push(child);
        }
      }
    }
    return seen;
  };
  const prodReachable = closureFrom(
    deps.filter((d) => d.source === 'dependencies').map((d) => d.bomRef),
  );
  const devReachable = closureFrom(
    deps.filter((d) => d.source === 'devDependencies').map((d) => d.bomRef),
  );
  for (const dep of deps) {
    // Only un-marked transitive deps are candidates; a dep reachable from any
    // production root stays production-scope even if a dev root also reaches it.
    if (dep.source !== 'transitive') continue;
    if (devReachable.has(dep.bomRef) && !prodReachable.has(dep.bomRef)) {
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

/**
 * Build the set of npm packages the lockfile marks dev-only, for the
 * `lockfileDev` fallback. cdxgen's transitive dev propagation is fragile; the
 * lockfile is authoritative. Returns keys in both `name@version` and bare
 * `name` form so callers can match either.
 *
 * Handles both lockfile shapes:
 *   - npm v2/v3 (`lockfileVersion` 2/3): `packages` keyed by install path
 *     (`""` is the root, `"node_modules/<name>"` / nested), each carrying a
 *     resolved `dev: true` flag. We derive the package name from the last
 *     `node_modules/` path segment and read `version` off the entry.
 *   - npm v1 (`lockfileVersion` 1): `dependencies` keyed by bare name, each
 *     with `dev: true` + `version` (recurse into nested `dependencies`).
 *
 * npm sets `dev: true` only when a package is reachable *exclusively* through
 * devDependencies — exactly the scope we want — so a bare-name match is safe.
 */
function collectNpmLockfileDevSet(repoRoot: string): Set<string> {
  const devKeys = new Set<string>();
  const lockPath = path.join(repoRoot, 'package-lock.json');
  let lock: {
    packages?: Record<string, { dev?: boolean; version?: string }>;
    dependencies?: Record<string, NpmV1LockEntry>;
  };
  try {
    lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  } catch {
    // No lockfile (or unparseable) — nothing to fall back on. The transitive
    // dev propagation in patchDevDependencies still runs.
    return devKeys;
  }

  // npm v2/v3: `packages` map keyed by install path.
  if (lock.packages && typeof lock.packages === 'object') {
    for (const [pkgPath, entry] of Object.entries(lock.packages)) {
      if (!entry || entry.dev !== true) continue;
      // Path is `node_modules/<name>` (possibly nested,
      // `node_modules/a/node_modules/b`); the package name is everything after
      // the last `node_modules/` segment. The root entry (`""`) has no name.
      const idx = pkgPath.lastIndexOf('node_modules/');
      if (idx === -1) continue;
      const name = pkgPath.slice(idx + 'node_modules/'.length);
      if (!name) continue;
      devKeys.add(name);
      if (entry.version) devKeys.add(`${name}@${entry.version}`);
    }
  }

  // npm v1: nested `dependencies` map keyed by bare name.
  if (lock.dependencies && typeof lock.dependencies === 'object') {
    const walk = (deps: Record<string, NpmV1LockEntry>) => {
      for (const [name, entry] of Object.entries(deps)) {
        if (!entry) continue;
        if (entry.dev === true) {
          devKeys.add(name);
          if (entry.version) devKeys.add(`${name}@${entry.version}`);
        }
        if (entry.dependencies) walk(entry.dependencies);
      }
    };
    walk(lock.dependencies);
  }

  return devKeys;
}

interface NpmV1LockEntry {
  dev?: boolean;
  version?: string;
  dependencies?: Record<string, NpmV1LockEntry>;
}

function collectPypiDevDeps(repoRoot: string, devNames: Set<string>): void {
  const pyprojectPath = path.join(repoRoot, 'pyproject.toml');
  try {
    collectPyprojectDevNames(fs.readFileSync(pyprojectPath, 'utf8'), devNames);
  } catch { /* no pyproject.toml or read error */ }

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

/**
 * Collect dev/test/build-tool dependency names from a `pyproject.toml`, covering
 * the modern Python tool matrix (not just Poetry-classic). cdxgen can't tell
 * dev scope from these sections, so the manifest is the source of truth.
 *
 * Two value shapes exist and both are handled:
 *   - TOML table keyed BY package name (Poetry):
 *       [tool.poetry.dev-dependencies] / [tool.poetry.group.<g>.dependencies]
 *       → `pytest = "^7"` — the KEY is the package name.
 *   - Array of PEP 508 requirement strings:
 *       [dependency-groups]            (PEP 735 — `dev = ["pytest>=7", ...]`)
 *       [tool.pdm.dev-dependencies]    (PDM — `test = ["pytest"]`)
 *       [tool.uv] dev-dependencies     (uv legacy — `dev-dependencies = [...]`)
 *       [tool.hatch.envs.<env>]        (Hatch — `dependencies = [...]` /
 *                                        `extra-dependencies = [...]`)
 *       → the package name is the leading token of each quoted requirement.
 *
 * `[project.optional-dependencies]` is intentionally NOT treated as dev: its
 * groups are user-facing extras that may be production features, and flooring
 * one to `unreachable` would be a false negative.
 */
export function collectPyprojectDevNames(content: string, devNames: Set<string>): void {
  type Mode = 'none' | 'keyTable' | 'reqArrayMap' | 'reqArrayKeys';
  let mode: Mode = 'none';
  let allowedKeys = new Set<string>();
  // Multi-line array tracking — an array value can span many lines.
  let inArray = false;
  let arrayIsDev = false;

  const addReqNames = (chunk: string) => {
    // Strip inline tables (PEP 735 `{ include-group = "x" }`) so their keys/
    // values aren't mistaken for package names; PEP 508 entries are plain strings.
    const cleaned = chunk.replace(/\{[^}]*\}/g, '');
    const re = /["']([^"']+)["']/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(cleaned)) !== null) {
      const name = m[1].match(/^([A-Za-z0-9._-]+)/)?.[1];
      if (name) devNames.add(name.toLowerCase());
    }
  };

  // Does `text` contain the array's closing `]`? Strip quoted strings + inline
  // tables first so a `]` inside a PEP 508 extras spec (`"coverage[toml]"`) is
  // not mistaken for the array terminator — that bug dropped the next entry.
  const closesArray = (text: string): boolean =>
    text.replace(/["'][^"']*["']/g, '').replace(/\{[^}]*\}/g, '').includes(']');

  const classify = (header: string): { mode: Mode; allowedKeys?: Set<string> } => {
    // Normalise quoted path segments: [tool.poetry.group."dev".dependencies].
    const h = header.trim().replace(/"/g, '');
    if (h === 'tool.poetry.dev-dependencies') return { mode: 'keyTable' };
    if (/^tool\.poetry\.group\.[^.]+\.dependencies$/.test(h)) return { mode: 'keyTable' };
    if (h === 'dependency-groups') return { mode: 'reqArrayMap' };
    if (h === 'tool.pdm.dev-dependencies') return { mode: 'reqArrayMap' };
    if (h === 'tool.uv') return { mode: 'reqArrayKeys', allowedKeys: new Set(['dev-dependencies']) };
    if (/^tool\.hatch\.envs\.[^.]+$/.test(h)) {
      return { mode: 'reqArrayKeys', allowedKeys: new Set(['dependencies', 'extra-dependencies']) };
    }
    return { mode: 'none' };
  };

  for (const rawLine of content.split('\n')) {
    const line = rawLine.replace(/\s+#.*$/, '').trim(); // strip trailing comments
    if (!line) continue;

    if (inArray) {
      if (arrayIsDev) addReqNames(line);
      if (closesArray(line)) inArray = false;
      continue;
    }

    const header = line.match(/^\[([^\]]+)\]$/);
    if (header) {
      const c = classify(header[1]);
      mode = c.mode;
      allowedKeys = c.allowedKeys ?? new Set();
      continue;
    }

    if (mode === 'none') continue;
    if (line.startsWith('#')) continue;

    if (mode === 'keyTable') {
      const m = line.match(/^["']?([A-Za-z0-9._-]+)["']?\s*[.=]/);
      if (m && m[1] !== 'python') devNames.add(m[1].toLowerCase());
      continue;
    }

    // Array shapes: `key = [ ... ]` (possibly multi-line).
    const kv = line.match(/^["']?([A-Za-z0-9._-]+)["']?\s*=\s*(.*)$/);
    if (!kv) continue;
    const key = kv[1];
    const rest = kv[2];
    if (!rest.startsWith('[')) continue; // not an array value (e.g. uv `package = true`)
    const isDevArray = mode === 'reqArrayMap' || allowedKeys.has(key);
    if (isDevArray) addReqNames(rest);
    if (!closesArray(rest)) {
      inArray = true;
      arrayIsDev = isDevArray;
    }
  }
}

function collectMavenDevDeps(repoRoot: string, devNames: Set<string>): void {
  const pomPath = path.join(repoRoot, 'pom.xml');
  try {
    const content = fs.readFileSync(pomPath, 'utf8');
    // Isolate each <dependency> block, THEN check its scope. An earlier
    // single-regex form let `[\s\S]*?` between <artifactId> and <scope> run
    // past </dependency>, so a compile-scope dependency sitting just before
    // the first test-scope one absorbed that test scope — on spring-petclinic
    // that mis-flagged the very first dependency (spring-boot-starter-
    // actuator) as test-scope, which then propagated dev-scope across its
    // whole transitive subtree (jackson, micrometer, logback…) and produced
    // a Gate-3 false negative. Matching the block first keeps the scope
    // check bounded to the dependency it belongs to.
    const blockRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
    let block;
    while ((block = blockRegex.exec(content)) !== null) {
      const body = block[1];
      if (!/<scope>\s*(test|provided)\s*<\/scope>/.test(body)) continue;
      const groupId = body.match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
      const artifactId = body.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
      if (groupId && artifactId) devNames.add(`${groupId}:${artifactId}`);
    }
  } catch { /* ignore */ }
}
