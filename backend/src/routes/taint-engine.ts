// @ts-nocheck
/**
 * Taint engine admin routes (Phase 6 / M6).
 *
 * Two surfaces:
 *
 *   /api/orgs/:orgId/taint-engine/settings
 *     GET  — read taint_engine_settings row (cost cap, killswitch state, etc.)
 *     PATCH — update cost cap / AI layer toggle / untyped-JS toggle / vuln_classes_enabled
 *   /api/orgs/:orgId/taint-engine/killswitch/release
 *     POST — clear the auto-engaged killswitch (admin recovery)
 *   /api/orgs/:orgId/taint-engine/runs
 *     GET — paginated taint_engine_runs telemetry for debugging
 *
 *   /api/orgs/:orgId/taint-engine/framework-models
 *     GET — list (no spec body)
 *     POST — add new framework + run AI inference
 *   /api/orgs/:orgId/taint-engine/framework-models/:modelId
 *     GET — full row including spec body
 *     PATCH — update spec body (admin edit; flips source_type to 'user_edited')
 *     DELETE — soft delete (is_active = false)
 *   /api/orgs/:orgId/taint-engine/framework-models/:modelId/refresh
 *     POST — re-run AI inference for this framework
 *
 * RBAC:
 *   view_ai_spending → all GET routes
 *   manage_aegis     → all mutations + killswitch release
 *
 * Cost cap is enforced inside spec-cache.inferAndStore (throws
 * CostCapExceededError → 402 Payment Required to the client).
 */

import express from 'express';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import {
  inferAndStore,
  storeUserEdit,
  softDelete,
  listForOrg,
  getById,
} from '../lib/taint-engine/spec-cache';
import { CostCapExceededError, getCostCapState } from '../lib/taint-engine/cost-cap';

const router = express.Router({ mergeParams: true });

router.use(authenticateUser);

// ---------------------------------------------------------------------------
// RBAC helper — duplicated from organizations.ts so this file stays
// self-contained. Reads organization_members.role then organization_roles.
// ---------------------------------------------------------------------------

async function hasOrgPermission(orgId: string, userId: string, perm: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;
  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();
  return role?.permissions?.[perm] === true;
}

function requirePerm(perm: string) {
  return async (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
    const orgId = req.params.orgId;
    const userId = req.user!.id;
    if (!(await hasOrgPermission(orgId, userId, perm))) {
      return res.status(403).json({ error: `Missing permission: ${perm}` });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

const VULN_CLASSES = new Set([
  'sql_injection', 'ssrf', 'xss', 'path_traversal', 'command_injection',
  'prototype_pollution', 'deserialization', 'redos', 'file_upload',
  'open_redirect', 'log_injection',
]);

const DEFAULT_VULN_CLASSES = [
  'sql_injection', 'ssrf', 'xss', 'path_traversal', 'command_injection',
  'prototype_pollution', 'deserialization', 'redos', 'file_upload',
  'open_redirect', 'log_injection',
];

router.get('/:orgId/settings', requirePerm('view_ai_spending'), async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.orgId;
    const { data, error } = await supabase
      .from('taint_engine_settings')
      .select('*')
      .eq('organization_id', orgId)
      .maybeSingle();
    if (error) throw error;
    if (data) return res.json(data);
    // Synthesize default row when no settings exist yet (per phase26 DEFAULTs).
    return res.json({
      organization_id: orgId,
      enabled: true,
      ai_layer_enabled: true,
      monthly_ai_cost_cap_usd: 50.0,
      untyped_js_enabled: true,
      vuln_classes_enabled: DEFAULT_VULN_CLASSES,
      killswitch_active: false,
      killswitch_reason: null,
      killswitch_activated_at: null,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to fetch settings' });
  }
});

router.patch('/:orgId/settings', requirePerm('manage_aegis'), async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.orgId;
    const updates: Record<string, unknown> = {};

    if ('enabled' in req.body) {
      if (typeof req.body.enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be boolean' });
      updates.enabled = req.body.enabled;
    }
    if ('ai_layer_enabled' in req.body) {
      if (typeof req.body.ai_layer_enabled !== 'boolean') return res.status(400).json({ error: 'ai_layer_enabled must be boolean' });
      updates.ai_layer_enabled = req.body.ai_layer_enabled;
    }
    if ('untyped_js_enabled' in req.body) {
      if (typeof req.body.untyped_js_enabled !== 'boolean') return res.status(400).json({ error: 'untyped_js_enabled must be boolean' });
      updates.untyped_js_enabled = req.body.untyped_js_enabled;
    }
    if ('monthly_ai_cost_cap_usd' in req.body) {
      const v = req.body.monthly_ai_cost_cap_usd;
      if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
        return res.status(400).json({ error: 'monthly_ai_cost_cap_usd must be a non-negative number' });
      }
      // Clamp to a reasonable range; the production-default is 50.
      updates.monthly_ai_cost_cap_usd = Math.min(1000, Math.max(0, v));
    }
    if ('vuln_classes_enabled' in req.body) {
      const arr = req.body.vuln_classes_enabled;
      if (!Array.isArray(arr) || arr.some((v) => typeof v !== 'string' || !VULN_CLASSES.has(v))) {
        return res.status(400).json({ error: `vuln_classes_enabled must be an array of: ${Array.from(VULN_CLASSES).join(', ')}` });
      }
      updates.vuln_classes_enabled = arr;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    updates.updated_at = new Date().toISOString();

    const { data, error } = await supabase
      .from('taint_engine_settings')
      .upsert({ organization_id: orgId, ...updates }, { onConflict: 'organization_id' })
      .select('*')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to update settings' });
  }
});

router.post('/:orgId/killswitch/release', requirePerm('manage_aegis'), async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.orgId;
    const { data, error } = await supabase
      .from('taint_engine_settings')
      .upsert(
        {
          organization_id: orgId,
          killswitch_active: false,
          killswitch_reason: null,
          killswitch_activated_at: null,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'organization_id' },
      )
      .select('*')
      .single();
    if (error) throw error;
    res.json({ killswitch_active: data.killswitch_active });
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to release killswitch' });
  }
});

router.get('/:orgId/cost', requirePerm('view_ai_spending'), async (req: AuthRequest, res) => {
  try {
    const state = await getCostCapState(req.params.orgId);
    res.json(state);
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to fetch cost state' });
  }
});

router.get('/:orgId/runs', requirePerm('view_ai_spending'), async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.orgId;
    const limit = Math.min(200, Math.max(1, parseInt(String(req.query.limit ?? '50'), 10) || 50));
    const { data, error } = await supabase
      .from('taint_engine_runs')
      .select('*')
      .eq('organization_id', orgId)
      .limit(limit);
    if (error) throw error;
    // PostgREST doesn't reliably honor .order via this storage abstraction
    // surface — sort client-side by created_at desc so newest is first.
    const sorted = (data ?? []).sort((a: any, b: any) =>
      String(b.created_at).localeCompare(String(a.created_at)),
    );
    res.json(sorted);
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to fetch runs' });
  }
});

// ---------------------------------------------------------------------------
// Framework models
// ---------------------------------------------------------------------------

router.get('/:orgId/framework-models', requirePerm('view_ai_spending'), async (req: AuthRequest, res) => {
  try {
    const rows = await listForOrg(req.params.orgId);
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to list framework models' });
  }
});

router.get('/:orgId/framework-models/:modelId', requirePerm('view_ai_spending'), async (req: AuthRequest, res) => {
  try {
    const row = await getById(req.params.orgId, req.params.modelId);
    if (!row) return res.status(404).json({ error: 'framework model not found' });
    res.json(row);
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to fetch model' });
  }
});

router.post('/:orgId/framework-models', requirePerm('manage_aegis'), async (req: AuthRequest, res) => {
  try {
    const { framework_name, framework_version, code_samples } = req.body;
    if (typeof framework_name !== 'string' || framework_name.length === 0) {
      return res.status(400).json({ error: 'framework_name is required' });
    }
    const version = typeof framework_version === 'string' && framework_version.length > 0 ? framework_version : '*';
    if (!Array.isArray(code_samples) || code_samples.length === 0) {
      return res.status(400).json({ error: 'code_samples (array of {path, content}) is required' });
    }
    for (const s of code_samples) {
      if (typeof s?.path !== 'string' || typeof s?.content !== 'string') {
        return res.status(400).json({ error: 'every code_sample must be {path: string, content: string}' });
      }
    }

    const row = await inferAndStore({
      organizationId: req.params.orgId,
      userId: req.user!.id,
      frameworkName: framework_name,
      frameworkVersion: version,
      codeSamples: code_samples,
    });
    res.status(201).json(row);
  } catch (err: any) {
    if (err instanceof CostCapExceededError) {
      return res.status(402).json({ error: err.message, state: err.state });
    }
    res.status(502).json({ error: err.message ?? 'Inference failed' });
  }
});

router.post('/:orgId/framework-models/:modelId/refresh', requirePerm('manage_aegis'), async (req: AuthRequest, res) => {
  try {
    const existing = await getById(req.params.orgId, req.params.modelId);
    if (!existing) return res.status(404).json({ error: 'framework model not found' });
    const { code_samples } = req.body;
    if (!Array.isArray(code_samples) || code_samples.length === 0) {
      return res.status(400).json({ error: 'code_samples (array of {path, content}) is required' });
    }
    const row = await inferAndStore({
      organizationId: req.params.orgId,
      userId: req.user!.id,
      frameworkName: existing.framework_name,
      frameworkVersion: existing.framework_version,
      codeSamples: code_samples,
    });
    res.json(row);
  } catch (err: any) {
    if (err instanceof CostCapExceededError) {
      return res.status(402).json({ error: err.message, state: err.state });
    }
    res.status(502).json({ error: err.message ?? 'Inference failed' });
  }
});

router.patch('/:orgId/framework-models/:modelId', requirePerm('manage_aegis'), async (req: AuthRequest, res) => {
  try {
    const { spec } = req.body;
    if (!spec || typeof spec !== 'object') {
      return res.status(400).json({ error: 'spec is required' });
    }
    // Light shape validation; the engine validates fully when loading.
    if (!Array.isArray(spec.sources) || !Array.isArray(spec.sinks) || !Array.isArray(spec.sanitizers)) {
      return res.status(400).json({ error: 'spec must have sources/sinks/sanitizers arrays' });
    }
    const row = await storeUserEdit({
      organizationId: req.params.orgId,
      modelId: req.params.modelId,
      userId: req.user!.id,
      spec,
    });
    res.json(row);
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to update spec' });
  }
});

router.delete('/:orgId/framework-models/:modelId', requirePerm('manage_aegis'), async (req: AuthRequest, res) => {
  try {
    await softDelete(req.params.orgId, req.params.modelId);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Failed to delete' });
  }
});

export default router;
