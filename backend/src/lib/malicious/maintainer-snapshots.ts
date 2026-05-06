/**
 * Maintainer-snapshot writer / reader for the malicious-packages-v2 M1c
 * detection path.
 *
 * Each call to `writeMaintainerSnapshot` upserts a fresh row keyed on
 * (package_name, version, ecosystem, observed_at). The natural key uses
 * `NULLS NOT DISTINCT` so re-runs in the same observation moment collapse
 * to one row instead of accumulating duplicates.
 *
 * `getLatestSnapshotBefore(cutoff)` returns the most recent snapshot with
 * `observed_at < cutoff`. The 30d-diff baseline call passes `now() - 30 days`
 * — when no row predates the cutoff, the registry-pull lib treats the
 * package as cold-start and returns `false` for every change signal.
 *
 * Cache is global; rows never contain org-derived data. Pruner trims to
 * 90-day retention via `malicious-retention.ts`.
 */
import { type SupabaseClient } from '@supabase/supabase-js';
import { canonicalizeEcosystem, type CanonicalEcosystem } from './ecosystem';

export interface MaintainerSnapshotInput {
  packageName: string;
  version: string;
  ecosystem: string;
  maintainerHandles: string[];
  primaryMaintainerEmail: string | null;
  signingConfigHash: string | null;
  postinstallHash: string | null;
  registryMetadataRaw: unknown;
  observedAt?: string;
}

export interface MaintainerSnapshotRow {
  id: string;
  package_name: string;
  version: string;
  ecosystem: CanonicalEcosystem;
  observed_at: string;
  maintainer_handles: string[];
  primary_maintainer_email: string | null;
  signing_config_hash: string | null;
  postinstall_hash: string | null;
  registry_metadata_raw: unknown;
}

/**
 * Upsert the current (package, version, ecosystem) state. Returns the row
 * id on success, or null when the ecosystem is unrecognised.
 */
export async function writeMaintainerSnapshot(
  supabase: SupabaseClient,
  input: MaintainerSnapshotInput,
): Promise<string | null> {
  const eco = canonicalizeEcosystem(input.ecosystem);
  if (!eco) return null;

  const observedAt = input.observedAt ?? new Date().toISOString();

  const payload = {
    package_name: input.packageName,
    version: input.version,
    ecosystem: eco,
    observed_at: observedAt,
    maintainer_handles: input.maintainerHandles ?? [],
    primary_maintainer_email: input.primaryMaintainerEmail ?? null,
    signing_config_hash: input.signingConfigHash ?? null,
    postinstall_hash: input.postinstallHash ?? null,
    registry_metadata_raw: input.registryMetadataRaw ?? null,
  };

  const { data, error } = await supabase
    .from('package_maintainer_snapshots')
    .upsert(payload, {
      onConflict: 'package_name,version,ecosystem,observed_at',
    })
    .select('id')
    .maybeSingle();

  if (error) {
    console.error('[maintainer-snapshots] upsert failed:', error.message);
    return null;
  }
  return (data?.id as string) ?? null;
}

/**
 * Latest snapshot strictly older than `cutoff`. Used as the 30d-ago diff
 * baseline. Returns null when no row predates the cutoff (cold start).
 */
export async function getLatestSnapshotBefore(
  supabase: SupabaseClient,
  packageName: string,
  version: string,
  ecosystem: string,
  cutoff: string | Date,
): Promise<MaintainerSnapshotRow | null> {
  const eco = canonicalizeEcosystem(ecosystem);
  if (!eco) return null;
  const cutoffIso = typeof cutoff === 'string' ? cutoff : cutoff.toISOString();

  const { data, error } = await supabase
    .from('package_maintainer_snapshots')
    .select('*')
    .eq('package_name', packageName)
    .eq('version', version)
    .eq('ecosystem', eco)
    .lt('observed_at', cutoffIso)
    .order('observed_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error || !data) return null;
  return data as MaintainerSnapshotRow;
}

/**
 * Most recent snapshot regardless of age. Used for cache-hit short-circuits
 * when the registry-pull lib decides whether a fresh registry call is needed.
 */
export async function getLatestSnapshot(
  supabase: SupabaseClient,
  packageName: string,
  version: string,
  ecosystem: string,
): Promise<MaintainerSnapshotRow | null> {
  const eco = canonicalizeEcosystem(ecosystem);
  if (!eco) return null;

  const { data, error } = await supabase
    .from('package_maintainer_snapshots')
    .select('*')
    .eq('package_name', packageName)
    .eq('version', version)
    .eq('ecosystem', eco)
    .order('observed_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error || !data) return null;
  return data as MaintainerSnapshotRow;
}
