/**
 * Parse CycloneDX SBOM and extract dependencies for project_dependencies, dependency_version_edges, etc.
 */

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
