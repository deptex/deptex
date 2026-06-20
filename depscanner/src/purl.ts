/**
 * PURL (Package URL) parser and dependency resolver.
 * Bridges dep-scan's PURL references to our database dependency IDs.
 */

import type { Storage } from './storage';

export interface ParsedPurl {
  ecosystem: string;
  name: string;
  version: string;
  namespace?: string;
  qualifiers?: Record<string, string>;
}

const PURL_TYPE_TO_ECOSYSTEM: Record<string, string> = {
  npm: 'npm',
  pypi: 'pypi',
  maven: 'maven',
  golang: 'golang',
  cargo: 'cargo',
  gem: 'gem',
  composer: 'composer',
  pub: 'pub',
  hex: 'hex',
  swift: 'swift',
  nuget: 'nuget',
};

const ECOSYSTEM_TO_PURL_TYPE: Record<string, string> = Object.fromEntries(
  Object.entries(PURL_TYPE_TO_ECOSYSTEM).map(([t, e]) => [e, t]),
);

/**
 * The `dependencies.ecosystem` column records the OSV/registry ecosystem name,
 * which for several ecosystems differs from the PURL type spelling: a rubygem
 * is stored as `rubygems` (purl type `gem`), a Go module as `gomod` (purl type
 * `golang`), a .NET package as `dotnet` (purl type `nuget`). Without this
 * normalization `buildPurl('rubygems', …)` returns null, so a CVE-tagged taint
 * flow on that dep never resolves to a dependency_id and the classifier can
 * never promote it past `module`. Keys are lowercase.
 */
const ECOSYSTEM_ALIASES: Record<string, string> = {
  rubygems: 'gem',
  rubygem: 'gem',
  gomod: 'golang',
  go: 'golang',
  pip: 'pypi',
  python: 'pypi',
  crates: 'cargo',
  'crates.io': 'cargo',
  packagist: 'composer',
  dotnet: 'nuget',
};

/** Normalize an OSV/registry ecosystem name to its canonical PURL ecosystem. */
export function normalizeEcosystem(ecosystem: string): string {
  const key = ecosystem.toLowerCase();
  return ECOSYSTEM_ALIASES[key] ?? key;
}

/**
 * Build a purl string from our canonical (ecosystem, name, version) shape.
 * Mirrors dep-scan's output format so rows we synthesize here collide on the
 * project_reachable_flows UNIQUE when they should.
 *
 * Maven names are stored as `groupId:artifactId` in our dependencies table;
 * purls put them as `groupId/artifactId`. Other ecosystems pass through.
 */
export function buildPurl(
  ecosystem: string,
  name: string,
  version: string | null,
): string | null {
  const type = ECOSYSTEM_TO_PURL_TYPE[normalizeEcosystem(ecosystem)];
  if (!type || !name) return null;
  let body = name;
  if (type === 'maven' && name.includes(':')) {
    body = name.replace(':', '/');
  }
  const v = version ? `@${version}` : '';
  return `pkg:${type}/${body}${v}`;
}

export function parsePurl(purl: string): ParsedPurl | null {
  if (!purl || typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;

  try {
    const withoutScheme = purl.slice(4);
    const [typeAndPath] = withoutScheme.split('?');
    const hashIdx = typeAndPath.indexOf('#');
    const pathPart = hashIdx >= 0 ? typeAndPath.slice(0, hashIdx) : typeAndPath;

    const slashIdx = pathPart.indexOf('/');
    if (slashIdx < 0) return null;

    const purlType = pathPart.slice(0, slashIdx);
    const ecosystem = PURL_TYPE_TO_ECOSYSTEM[purlType];
    if (!ecosystem) return null;

    let remainder = decodeURIComponent(pathPart.slice(slashIdx + 1));
    const atIdx = remainder.lastIndexOf('@');
    if (atIdx < 0) return null;

    const version = remainder.slice(atIdx + 1);
    const nameWithNamespace = remainder.slice(0, atIdx);

    let name: string;
    let namespace: string | undefined;

    if (purlType === 'maven') {
      const parts = nameWithNamespace.split('/');
      if (parts.length === 2) {
        namespace = parts[0];
        name = `${parts[0]}:${parts[1]}`;
      } else {
        name = nameWithNamespace;
      }
    } else if (purlType === 'npm' && nameWithNamespace.includes('/')) {
      const parts = nameWithNamespace.split('/');
      namespace = parts[0];
      name = `${parts[0]}/${parts.slice(1).join('/')}`;
    } else {
      name = nameWithNamespace;
    }

    return { ecosystem, name, version, namespace };
  } catch {
    return null;
  }
}

export async function resolvePurlToDependencyId(
  supabase: Storage,
  parsed: ParsedPurl,
): Promise<string | null> {
  const { data } = await supabase
    .from('dependencies')
    .select('id')
    .eq('name', parsed.name)
    .limit(1)
    .single();
  return data?.id ?? null;
}
