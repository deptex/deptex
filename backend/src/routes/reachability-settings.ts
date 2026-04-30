// @ts-nocheck
/**
 * Phase 25: Per-org reachability rule generation policy endpoints.
 *
 * GET/PATCH /api/organizations/:id/reachability-settings — trigger policy +
 * AI model preference + monthly budget. Mounted under /api/organizations in
 * src/index.ts alongside the other org-scoped routers.
 */

import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { createActivity } from '../lib/activities';

const router = express.Router();

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const VALID_PROVIDERS = ['anthropic', 'openai', 'google'] as const;
const VALID_BUDGET_BEHAVIORS = ['skip', 'fall_back_to_haiku'] as const;

const DEFAULTS = {
  auto_generate_enabled: false,
  trigger_severities: ['critical', 'high'],
  trigger_kev: true,
  trigger_asset_tier_max_rank: 2,
  trigger_newly_discovered: true,
  trigger_reevaluate_existing: false,
  ai_provider: 'anthropic',
  ai_model: 'claude-sonnet-4-6',
  monthly_budget_usd: 10.0,
  on_budget_exhaustion: 'skip',
  max_wait_seconds: 300,
};

async function hasPermission(userId: string, orgId: string, permission: string): Promise<boolean> {
  const { data: member } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!member) return false;
  if (member.role === 'owner') return true;

  const { data: roles } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', member.role)
    .single();

  return roles?.permissions?.[permission] === true;
}

// GET /api/organizations/:id/reachability-settings
router.get('/:id/reachability-settings', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasPermission(userId, orgId, 'view_ai_spending'))) {
      return res.status(403).json({ error: 'You do not have permission to view reachability settings' });
    }

    const { data, error } = await supabase
      .from('organization_reachability_settings')
      .select('*')
      .eq('organization_id', orgId)
      .maybeSingle();
    if (error) throw error;

    // No row yet = org has never opened the settings panel. Return defaults
    // so the UI renders a populated form rather than blank.
    res.json(data ?? { organization_id: orgId, ...DEFAULTS });
  } catch (error: any) {
    console.error('Error fetching reachability settings:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch reachability settings' });
  }
});

// PATCH /api/organizations/:id/reachability-settings
router.patch('/:id/reachability-settings', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasPermission(userId, orgId, 'manage_organization_settings'))) {
      return res.status(403).json({ error: 'You do not have permission to manage reachability settings' });
    }

    const updates: Record<string, unknown> = {};
    const body = req.body ?? {};

    if ('auto_generate_enabled' in body) {
      if (typeof body.auto_generate_enabled !== 'boolean') {
        return res.status(400).json({ error: 'auto_generate_enabled must be a boolean' });
      }
      updates.auto_generate_enabled = body.auto_generate_enabled;
    }

    if ('trigger_severities' in body) {
      if (!Array.isArray(body.trigger_severities) || body.trigger_severities.some((s: any) => !VALID_SEVERITIES.includes(s))) {
        return res.status(400).json({ error: `trigger_severities must be an array of ${VALID_SEVERITIES.join('/')}` });
      }
      updates.trigger_severities = body.trigger_severities;
    }

    for (const flag of ['trigger_kev', 'trigger_newly_discovered', 'trigger_reevaluate_existing'] as const) {
      if (flag in body) {
        if (typeof body[flag] !== 'boolean') {
          return res.status(400).json({ error: `${flag} must be a boolean` });
        }
        updates[flag] = body[flag];
      }
    }

    if ('trigger_asset_tier_max_rank' in body) {
      const v = body.trigger_asset_tier_max_rank;
      if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > 5) {
        return res.status(400).json({ error: 'trigger_asset_tier_max_rank must be an integer 1-5' });
      }
      updates.trigger_asset_tier_max_rank = v;
    }

    if ('ai_provider' in body) {
      if (!VALID_PROVIDERS.includes(body.ai_provider)) {
        return res.status(400).json({ error: `ai_provider must be one of ${VALID_PROVIDERS.join('/')}` });
      }
      updates.ai_provider = body.ai_provider;
    }

    if ('ai_model' in body) {
      if (typeof body.ai_model !== 'string' || body.ai_model.length === 0 || body.ai_model.length > 100) {
        return res.status(400).json({ error: 'ai_model must be a non-empty string ≤100 chars' });
      }
      updates.ai_model = body.ai_model;
    }

    if ('monthly_budget_usd' in body) {
      const v = body.monthly_budget_usd;
      if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 1000) {
        return res.status(400).json({ error: 'monthly_budget_usd must be a number 0-1000' });
      }
      updates.monthly_budget_usd = Math.round(v * 100) / 100;
    }

    if ('on_budget_exhaustion' in body) {
      if (!VALID_BUDGET_BEHAVIORS.includes(body.on_budget_exhaustion)) {
        return res.status(400).json({ error: `on_budget_exhaustion must be one of ${VALID_BUDGET_BEHAVIORS.join('/')}` });
      }
      updates.on_budget_exhaustion = body.on_budget_exhaustion;
    }

    if ('max_wait_seconds' in body) {
      const v = body.max_wait_seconds;
      if (typeof v !== 'number' || !Number.isInteger(v) || v < 30 || v > 1800) {
        return res.status(400).json({ error: 'max_wait_seconds must be an integer 30-1800' });
      }
      updates.max_wait_seconds = v;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    updates.updated_at = new Date().toISOString();
    updates.updated_by = userId;

    // Capture prior state for audit log before upsert.
    const { data: priorRow } = await supabase
      .from('organization_reachability_settings')
      .select('*')
      .eq('organization_id', orgId)
      .maybeSingle();

    const upsertPayload = {
      organization_id: orgId,
      ...DEFAULTS,
      ...(priorRow ?? {}),
      ...updates,
    };

    const { data, error } = await supabase
      .from('organization_reachability_settings')
      .upsert(upsertPayload, { onConflict: 'organization_id' })
      .select('*')
      .single();
    if (error) throw error;

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'changed_reachability_settings',
      description: 'updated reachability rule generation settings',
      metadata: {
        old_value: priorRow ?? null,
        new_value: data,
        changed_fields: Object.keys(updates).filter((k) => k !== 'updated_at' && k !== 'updated_by'),
      },
    });

    res.json(data);
  } catch (error: any) {
    console.error('Error updating reachability settings:', error);
    res.status(500).json({ error: error.message || 'Failed to update reachability settings' });
  }
});

export default router;
