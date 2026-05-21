// Phase 35 (v1.1) — backend-side helpers for the dast-openapi-specs bucket.
//
// Authorization model: bucket is private; no storage-level RLS. Backend
// mints signed URLs after route-layer permission checks (loadTargetOrDeny
// + checkOrgManageIntegrationsPermission). Worker writes are service-role
// only; this module reads/presigns and handles delete-cascade.
//
// Worker-side counterpart: depscanner/src/dast/spec-storage.ts emits the
// synthesized YAML on each scan completion. The bucket name + storage path
// convention are duplicated here intentionally (separate-package boundary
// per the sync-script pattern; see scripts/sync-dast-openapi.ts).

import { supabase } from './supabase';

export const DAST_OPENAPI_SPECS_BUCKET = 'dast-openapi-specs';

/** Synthesized spec storage path. Mirror of worker convention. */
export function synthesizedSpecPath(orgId: string, targetId: string): string {
  return `${orgId}/${targetId}/synthesized-latest.yaml`;
}

/** Per-target prefix used for delete-cascade sweeps. */
export function specPathPrefix(orgId: string, targetId: string): string {
  return `${orgId}/${targetId}/`;
}

const SIGNED_URL_TTL_SECONDS = 600;

export interface PresignedDownload {
  kind: 'synthesized';
  url: string;
  expires_at: string;
}

/**
 * Returns a signed download URL for the target's latest synthesized spec,
 * or null when no scan has emitted one yet. Caller already validated route
 * permissions; this is the storage I/O step only.
 */
export async function presignSynthesizedSpecDownload(
  orgId: string,
  targetId: string,
): Promise<PresignedDownload | null> {
  const storagePath = synthesizedSpecPath(orgId, targetId);
  const { data, error } = await supabase.storage
    .from(DAST_OPENAPI_SPECS_BUCKET)
    .createSignedUrl(storagePath, SIGNED_URL_TTL_SECONDS);
  if (error || !data?.signedUrl) {
    // Supabase returns an error when the object is missing — collapse to
    // null so the route layer can map it to a 404 cleanly.
    return null;
  }
  const expiresMs = Date.now() + SIGNED_URL_TTL_SECONDS * 1000;
  return {
    kind: 'synthesized',
    url: data.signedUrl,
    expires_at: new Date(expiresMs).toISOString(),
  };
}

/**
 * Delete every object under `{org}/{target}/` (synthesized + future
 * uploaded). Called from the DELETE /dast/targets/:targetId route after
 * the DB cascade has succeeded; best-effort, swallowed-error pattern so a
 * storage hiccup never blocks target deletion.
 */
export async function deleteAllSpecsForTarget(
  orgId: string,
  targetId: string,
): Promise<{ deleted: number; errors: number }> {
  const prefix = specPathPrefix(orgId, targetId);
  const list = await supabase.storage
    .from(DAST_OPENAPI_SPECS_BUCKET)
    .list(prefix.replace(/\/$/, ''), { limit: 100 });
  if (list.error || !list.data || list.data.length === 0) {
    return { deleted: 0, errors: list.error ? 1 : 0 };
  }
  const paths = list.data.map((entry) => `${prefix}${entry.name}`);
  const del = await supabase.storage
    .from(DAST_OPENAPI_SPECS_BUCKET)
    .remove(paths);
  if (del.error) {
    return { deleted: 0, errors: 1 };
  }
  return { deleted: del.data?.length ?? 0, errors: 0 };
}
