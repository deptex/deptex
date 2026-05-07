/**
 * Feed lookup against `known_malicious_packages`.
 *
 * Cheap, network-free (just a DB query) — runs first so we don't pay for a
 * tarball download on packages already known-malicious. A hit becomes a
 * `scanner='feed'` finding with severity `critical`.
 */
import type { Storage } from '../storage';
import { canonicalizeEcosystem, canonicalizePackageName } from './ecosystem';

export interface FeedHit {
  source: 'osv' | 'ghsa';
  source_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  description: string | null;
}

export async function lookupFeed(
  supabase: Storage,
  packageName: string,
  ecosystem: string,
  version: string | null,
): Promise<FeedHit[]> {
  const canonical = canonicalizeEcosystem(ecosystem);
  if (!canonical) return [];

  // Canonicalize package_name on the read path so a GHSA advisory for
  // `Django` (mixed case, written canonically as `django` per PEP 503)
  // matches an installed `django` from cdxgen. MUST stay in sync with
  // feed-sync's write-side canonicalization in advisoryToEntries.
  const canonicalName = canonicalizePackageName(packageName, canonical);

  const { data, error } = await supabase
    .from('known_malicious_packages')
    .select('source, source_id, severity, description, version, withdrawn_at')
    .eq('package_name', canonicalName)
    .eq('ecosystem', canonical);

  if (error || !data) return [];

  const hits: FeedHit[] = [];
  for (const row of data as Array<{
    source: 'osv' | 'ghsa';
    source_id: string;
    severity: string | null;
    description: string | null;
    version: string | null;
    withdrawn_at: string | null;
  }>) {
    if (row.withdrawn_at) continue;
    // version=null in feed → covers all versions of this package
    if (row.version && version && row.version !== version) continue;
    hits.push({
      source: row.source,
      source_id: row.source_id,
      severity: (row.severity as FeedHit['severity']) ?? 'critical',
      description: row.description,
    });
  }
  return hits;
}
