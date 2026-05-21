// Phase 35 (v1.1) — worker-side helpers for the dast-openapi-specs Storage
// bucket. The worker writes the synthesized YAML so the backend's
// presignSynthesizedSpecDownload can later serve it. Authorization is
// route-side; bucket is private with NO storage-level RLS (service-role
// only access — see backend/src/lib/dast-spec-storage.ts).

import type { Storage } from '../storage';

export const DAST_OPENAPI_SPECS_BUCKET = 'dast-openapi-specs';

/**
 * Storage path: `{orgId}/{targetId}/synthesized-latest.yaml`.
 *
 * Locked Decision 11 (v1.1): overwrite-on-each-scan. No per-run-id suffix;
 * no retention cron. Steady state: 1 object per active synthesized-mode
 * target.
 */
export function synthesizedSpecPath(orgId: string, targetId: string): string {
  return `${orgId}/${targetId}/synthesized-latest.yaml`;
}

export type SpecWriteResult =
  | { ok: true; storagePath: string }
  | { ok: false; reason: string };

/**
 * Upload the synthesized OpenAPI YAML to the bucket. upsert=true so a re-scan
 * overwrites prior synthesis. Non-fatal at the caller level — see Task 4's
 * storage-first ordering: if this returns ok=false, the caller leaves the
 * target row's `last_synthesized_at` NULL and sets `last_synthesis_ok=false`
 * to preserve the download invariant.
 */
export async function writeSynthesizedSpec(
  supabase: Storage,
  orgId: string,
  targetId: string,
  yaml: string,
): Promise<SpecWriteResult> {
  const path = synthesizedSpecPath(orgId, targetId);
  try {
    const result = await supabase.storage
      .from(DAST_OPENAPI_SPECS_BUCKET)
      .upload(path, yaml, {
        contentType: 'application/yaml',
        upsert: true,
      });
    if (result.error) {
      const reason = (result.error as { message?: string }).message ?? 'unknown storage error';
      return { ok: false, reason };
    }
    return { ok: true, storagePath: path };
  } catch (e) {
    return {
      ok: false,
      reason: e instanceof Error ? e.message : 'unknown exception during storage upload',
    };
  }
}
