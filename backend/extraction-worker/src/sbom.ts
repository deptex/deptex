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
  license: string | null;
  is_direct: boolean;
  source: 'dependencies' | 'devDependencies' | 'transitive';
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
} {
  const components = sbom.components || [];
  const depGraph = sbom.dependencies || [];

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
    if (!name || !version) continue;

    const license = extractLicense(comp.licenses);

    const isDirect = directRefs.has(ref);
    const source: 'dependencies' | 'devDependencies' | 'transitive' = isDirect ? 'dependencies' : 'transitive';

    dependencies.push({
      name,
      version,
      license,
      is_direct: isDirect,
      source,
      bomRef: ref,
    });
  }

  return { dependencies, relationships };
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
    if (dep.is_direct && devNames.has(dep.name)) {
      dep.source = 'devDependencies';
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
  }

  return devNames;
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
