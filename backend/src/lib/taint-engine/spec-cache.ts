/**
 * Org-scoped persistence layer for AI-inferred + user-edited framework specs.
 *
 * The hand-written specs (express, fastify, ...) ship with the
 * extraction-worker. This cache covers everything the engine encounters
 * that isn't hand-written — typically tRPC, Koa, custom internal
 * frameworks. Cache key = (org, framework_name, framework_version).
 *
 * Source-of-truth interactions:
 *   - inferAndStore() → on a cache miss or admin "Refresh" click; runs
 *     spec inference, writes the result with source_type='ai_inferred'.
 *   - storeUserEdit() → on PATCH spec body; preserves the prior
 *     inferred metadata but flips source_type to 'user_edited' so admins
 *     can see the spec is no longer pristine AI output.
 *   - listForOrg() / getById() / softDelete() — admin UI surface.
 *
 * Cost cap is enforced inside inferAndStore() so callers don't need to
 * remember to gate. Throws CostCapExceededError when the cap is blown.
 */

import { supabase } from '../supabase';
import { inferFrameworkSpec, type FrameworkSpec, type InferenceInput } from './spec-inference';
import { assertWithinCostCap } from './cost-cap';

export type SourceType = 'hand_written' | 'ai_inferred' | 'user_edited';

export interface FrameworkModel {
  id: string;
  organization_id: string;
  framework_name: string;
  framework_version: string;
  source_type: SourceType;
  spec: FrameworkSpec;
  inferred_at: string | null;
  inferred_by_model: string | null;
  inferred_cost_usd: number | null;
  edited_by_user_id: string | null;
  edited_at: string | null;
  last_validated_at: string | null;
  validation_score: number | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

/** List all active models for an org. spec body excluded for table views. */
export async function listForOrg(organizationId: string): Promise<Omit<FrameworkModel, 'spec'>[]> {
  const { data, error } = await supabase
    .from('taint_engine_framework_models')
    .select(
      'id, organization_id, framework_name, framework_version, source_type, inferred_at, inferred_by_model, inferred_cost_usd, edited_by_user_id, edited_at, last_validated_at, validation_score, is_active, created_at, updated_at',
    )
    .eq('organization_id', organizationId)
    .eq('is_active', true);
  if (error) throw error;
  return (data ?? []) as Omit<FrameworkModel, 'spec'>[];
}

export async function getById(
  organizationId: string,
  modelId: string,
): Promise<FrameworkModel | null> {
  const { data, error } = await supabase
    .from('taint_engine_framework_models')
    .select('*')
    .eq('organization_id', organizationId)
    .eq('id', modelId)
    .maybeSingle();
  if (error) throw error;
  return (data as FrameworkModel | null) ?? null;
}

export async function getByFrameworkVersion(
  organizationId: string,
  frameworkName: string,
  frameworkVersion: string,
): Promise<FrameworkModel | null> {
  const { data, error } = await supabase
    .from('taint_engine_framework_models')
    .select('*')
    .eq('organization_id', organizationId)
    .eq('framework_name', frameworkName)
    .eq('framework_version', frameworkVersion)
    .eq('is_active', true)
    .maybeSingle();
  if (error) throw error;
  return (data as FrameworkModel | null) ?? null;
}

/**
 * Run AI inference, then upsert the result. Caller must hold the
 * organization (route handler enforces RBAC). Throws on cost-cap
 * exceeded, provider failure, parse failure, or schema mismatch.
 */
export async function inferAndStore(input: InferenceInput): Promise<FrameworkModel> {
  // Pre-call cap check. Spec inference is cheap (<$0.01 typical) so
  // we don't pass a projected estimate; the cap is the gate, not a
  // per-call budget.
  await assertWithinCostCap(input.organizationId);

  const out = await inferFrameworkSpec(input);

  const row = {
    organization_id: input.organizationId,
    framework_name: input.frameworkName,
    framework_version: input.frameworkVersion,
    source_type: 'ai_inferred' as SourceType,
    spec: out.spec,
    inferred_at: new Date().toISOString(),
    inferred_by_model: out.model,
    inferred_cost_usd: out.costUsd,
    is_active: true,
    updated_at: new Date().toISOString(),
  };

  const { data, error } = await supabase
    .from('taint_engine_framework_models')
    .upsert(row, { onConflict: 'organization_id,framework_name,framework_version' })
    .select('*')
    .single();
  if (error) throw error;
  return data as FrameworkModel;
}

/**
 * Apply admin-edited spec content. Flips source_type to 'user_edited',
 * stamps edited_by_user_id + edited_at. Preserves the original
 * inferred_* metadata (so the audit trail of "AI suggested → admin
 * tweaked" stays intact).
 */
export async function storeUserEdit(args: {
  organizationId: string;
  modelId: string;
  userId: string;
  spec: FrameworkSpec;
}): Promise<FrameworkModel | null> {
  // Pre-fetch so a cross-org probe (org A admin patches a modelId belonging
  // to org B) returns 404 instead of a PGRST116 500 — the WHERE clause
  // already prevents the write, but the divergent error code was a usable
  // existence oracle.
  const existing = await getById(args.organizationId, args.modelId);
  if (!existing) return null;

  const { data, error } = await supabase
    .from('taint_engine_framework_models')
    .update({
      spec: args.spec,
      source_type: 'user_edited',
      edited_by_user_id: args.userId,
      edited_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq('organization_id', args.organizationId)
    .eq('id', args.modelId)
    .select('*')
    .single();
  if (error) throw error;
  return data as FrameworkModel;
}

export async function softDelete(organizationId: string, modelId: string): Promise<boolean> {
  // Pre-fetch so a cross-org probe doesn't get a false-positive 200 OK.
  const existing = await getById(organizationId, modelId);
  if (!existing) return false;

  const { error } = await supabase
    .from('taint_engine_framework_models')
    .update({ is_active: false, updated_at: new Date().toISOString() })
    .eq('organization_id', organizationId)
    .eq('id', modelId);
  if (error) throw error;
  return true;
}
