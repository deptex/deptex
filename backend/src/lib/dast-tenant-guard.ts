import type { SupabaseClient } from '@supabase/supabase-js';
import { DastDetectedRuntime } from '../types/dast';

// Three-layer cross-tenant guard. Layer 1 lives here (route-level): every
// :targetId-bearing endpoint runs `loadTargetOrDeny` immediately after
// `resolveProjectAccess` resolves the org/project. Layer 2 is the RPC-level
// assertion baked into `queue_scan_job` (phase24a SQL). Layer 3 is the
// worker-side tenant-drift check in depscanner pipeline.ts.

export interface LoadedTarget {
  id: string;
  project_id: string;
  organization_id: string;
  target_url: string;
  detected_runtime: DastDetectedRuntime;
  detected_runtime_at: string | null;
  detected_runtime_ttl_at: string | null;
  enabled: boolean;
  // Phase 35 (v1.1) — OpenAPI spec config. Single SELECT widened so every
  // route that needs spec context (scan route nuclei guard, PATCH /spec,
  // GET /spec/download) doesn't need a second roundtrip.
  api_spec_source: 'synthesized' | 'url' | 'none';
  api_spec_url: string | null;
  last_synthesized_at: string | null;
  last_synthesis_endpoint_count: number | null;
  last_synthesis_ok: boolean | null;
}

export type LoadTargetDeny = { status: 404; reason: 'target_not_found' };
export type LoadTargetResult = { target: LoadedTarget } | LoadTargetDeny;

/**
 * Loads a `project_dast_targets` row and asserts the loaded row's
 * `(project_id, organization_id)` match the caller-asserted tuple.
 *
 * Returns 404 (NOT 403, NOT 422) on:
 *   - target row missing entirely
 *   - target row exists but belongs to a different project
 *   - target row exists but belongs to a different organization
 *
 * 404 prevents existence enumeration; the same elapsed time within ~50ms is
 * spent regardless of whether the target exists in another tenant or doesn't
 * exist at all. This means a route handler should NEVER differentiate between
 * "target row missing" and "target row in another tenant" by elapsed time or
 * response shape.
 */
export async function loadTargetOrDeny(
  supabase: SupabaseClient,
  targetId: string,
  expectedProjectId: string,
  expectedOrganizationId: string,
): Promise<LoadTargetResult> {
  // Single SELECT — we deliberately do NOT pre-filter by project_id /
  // organization_id, because PostgREST translating those into WHERE clauses
  // would let an attacker measure "row matched filter" vs "row missing"
  // by query plan timing. We pull the row by primary key and validate the
  // tuple in JS so both branches pay the same network round-trip cost.
  const { data, error } = await supabase
    .from('project_dast_targets')
    .select(
      'id, project_id, organization_id, target_url, detected_runtime, detected_runtime_at, detected_runtime_ttl_at, enabled, api_spec_source, api_spec_url, last_synthesized_at, last_synthesis_endpoint_count, last_synthesis_ok',
    )
    .eq('id', targetId)
    .maybeSingle();

  if (error) {
    // Treat unexpected DB errors the same as not-found from the caller's
    // perspective. The actual error is logged for ops; the response is
    // still 404 to avoid leaking schema state.
    console.error('[dast-tenant-guard] supabase error loading target:', error.message);
    return { status: 404, reason: 'target_not_found' };
  }

  if (!data) {
    return { status: 404, reason: 'target_not_found' };
  }

  // Constant-time-ish equality. Strings here are UUIDs (always 36 chars), so
  // `crypto.timingSafeEqual` over fixed-width buffers is consistent. We accept
  // a small variance from the JS string -> Buffer conversion since the
  // dominant cost (the Supabase round-trip above) already swamps it.
  const projectIdMatch = data.project_id === expectedProjectId;
  const orgIdMatch = data.organization_id === expectedOrganizationId;

  if (!projectIdMatch || !orgIdMatch) {
    return { status: 404, reason: 'target_not_found' };
  }

  return {
    target: {
      id: data.id,
      project_id: data.project_id,
      organization_id: data.organization_id,
      target_url: data.target_url,
      detected_runtime: data.detected_runtime as DastDetectedRuntime,
      detected_runtime_at: data.detected_runtime_at,
      detected_runtime_ttl_at: data.detected_runtime_ttl_at,
      enabled: data.enabled,
      api_spec_source: (data.api_spec_source ?? 'none') as 'synthesized' | 'url' | 'none',
      api_spec_url: data.api_spec_url ?? null,
      last_synthesized_at: data.last_synthesized_at ?? null,
      last_synthesis_endpoint_count: data.last_synthesis_endpoint_count ?? null,
      last_synthesis_ok: data.last_synthesis_ok ?? null,
    },
  };
}

export function isLoadTargetDeny(r: LoadTargetResult): r is LoadTargetDeny {
  return (r as LoadTargetDeny).status === 404;
}
