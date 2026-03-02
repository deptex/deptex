/**
 * PURL (Package URL) parser and dependency resolver.
 * Bridges dep-scan's PURL references to our database dependency IDs.
 */

import { SupabaseClient } from '@supabase/supabase-js';

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
  supabase: SupabaseClient,
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
