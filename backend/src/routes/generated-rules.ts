// @ts-nocheck
/**
 * Phase 25: Per-org generated rule CRUD + regenerate.
 *
 * GET    /api/organizations/:id/generated-rules            — paginated list
 * GET    /api/organizations/:id/generated-rules/:ruleId    — full row incl. yaml + fixtures
 * PATCH  /api/organizations/:id/generated-rules/:ruleId    — toggle enabled / set manual_override
 * DELETE /api/organizations/:id/generated-rules/:ruleId    — hard delete (cascades cleanly)
 * POST   /api/organizations/:id/generated-rules/:ruleId/regenerate — push current → previous_versions, queue regen with new model
 *
 * Regenerate semantics: we don't dispatch generation work synchronously here.
 * Generation runs inside the extraction-worker (where Semgrep + git +
 * AI SDK are installed). Hitting regenerate marks the rule pending and the
 * next scan will pick it up via the in-process generation step. M3 wires
 * QStash → extraction-worker for immediate dispatch when latency matters.
 */

import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { createActivity } from '../lib/activities';

const router = express.Router();

const VALID_PROVIDERS = ['anthropic', 'openai', 'google'] as const;
const VALID_STATUSES = ['pending', 'validated', 'failed_validation', 'manual_override'] as const;

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

async function requireMembership(userId: string, orgId: string): Promise<boolean> {
  const { data } = await supabase
    .from('organization_members')
    .select('id')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  return !!data;
}

// GET /api/organizations/:id/generated-rules
router.get('/:id/generated-rules', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await requireMembership(userId, orgId))) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    const canViewSpend = await hasPermission(userId, orgId, 'view_ai_spending');

    const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
    const perPage = Math.min(100, Math.max(1, parseInt(req.query.per_page as string, 10) || 50));
    const offset = (page - 1) * perPage;

    const status = req.query.status as string | undefined;
    const enabledQuery = req.query.enabled as string | undefined;
    const search = (req.query.search as string | undefined)?.trim();

    let query = supabase
      .from('organization_generated_rules')
      .select(
        // List view excludes rule_yaml + fixtures (large). Detail endpoint
        // returns full row.
        'id, organization_id, cve_id, package_purl, ecosystem, affected_version_range, ' +
          'reachability_level, entry_point_class, generated_with_provider, generated_with_model, ' +
          'generation_cost_usd, validation_status, enabled, generated_at, last_used_at, use_count',
        { count: 'exact' }
      )
      .eq('organization_id', orgId)
      .order('generated_at', { ascending: false })
      .range(offset, offset + perPage - 1);

    if (status && VALID_STATUSES.includes(status as any)) {
      query = query.eq('validation_status', status);
    }
    if (enabledQuery === 'true') query = query.eq('enabled', true);
    if (enabledQuery === 'false') query = query.eq('enabled', false);
    if (search) {
      query = query.or(`cve_id.ilike.%${search}%,package_purl.ilike.%${search}%`);
    }

    const { data, error, count } = await query;
    if (error) throw error;

    // Per-rule generation_cost_usd is AI-spend data — gate on view_ai_spending
    // for consistency with the sibling reachability-settings GET. Members
    // without that permission still see the rule list (they need to see what
    // CVEs are covered) but cost fields are nulled out.
    const rules = (data ?? []).map((row: any) => canViewSpend ? row : { ...row, generation_cost_usd: null });

    res.json({
      rules,
      pagination: {
        page,
        per_page: perPage,
        total: count ?? 0,
        total_pages: count ? Math.ceil(count / perPage) : 0,
      },
    });
  } catch (error: any) {
    console.error('Error listing generated rules:', error);
    res.status(500).json({ error: error.message || 'Failed to list generated rules' });
  }
});

// GET /api/organizations/:id/generated-rules/:ruleId
router.get('/:id/generated-rules/:ruleId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    const ruleId = req.params.ruleId;
    if (!(await requireMembership(userId, orgId))) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    const canViewSpend = await hasPermission(userId, orgId, 'view_ai_spending');

    const { data, error } = await supabase
      .from('organization_generated_rules')
      .select('*')
      .eq('organization_id', orgId)
      .eq('id', ruleId)
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Rule not found' });

    if (!canViewSpend) {
      data.generation_cost_usd = null;
      if (Array.isArray(data.previous_versions)) {
        data.previous_versions = data.previous_versions.map((v: any) => ({ ...v, generation_cost_usd: null }));
      }
    }

    res.json(data);
  } catch (error: any) {
    console.error('Error fetching generated rule:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch generated rule' });
  }
});

// PATCH /api/organizations/:id/generated-rules/:ruleId
router.patch('/:id/generated-rules/:ruleId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    const ruleId = req.params.ruleId;
    if (!(await hasPermission(userId, orgId, 'manage_organization_settings'))) {
      return res.status(403).json({ error: 'You do not have permission to manage generated rules' });
    }

    const updates: Record<string, unknown> = {};
    const body = req.body ?? {};

    if ('enabled' in body) {
      if (typeof body.enabled !== 'boolean') {
        return res.status(400).json({ error: 'enabled must be a boolean' });
      }
      updates.enabled = body.enabled;
    }

    if ('validation_status' in body) {
      if (body.validation_status !== 'manual_override') {
        return res.status(400).json({ error: 'validation_status can only be set to manual_override via PATCH' });
      }
      updates.validation_status = 'manual_override';
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    const { data: priorRule } = await supabase
      .from('organization_generated_rules')
      .select('id, cve_id, package_purl, enabled, validation_status')
      .eq('organization_id', orgId)
      .eq('id', ruleId)
      .maybeSingle();

    if (!priorRule) return res.status(404).json({ error: 'Rule not found' });

    const { data, error } = await supabase
      .from('organization_generated_rules')
      .update(updates)
      .eq('organization_id', orgId)
      .eq('id', ruleId)
      .select('*')
      .single();
    if (error) throw error;

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'updated_generated_rule',
      description: `${updates.enabled === false ? 'disabled' : updates.enabled === true ? 'enabled' : 'updated'} generated rule for ${priorRule.cve_id} (${priorRule.package_purl})`,
      metadata: {
        rule_id: ruleId,
        cve_id: priorRule.cve_id,
        package_purl: priorRule.package_purl,
        old_value: { enabled: priorRule.enabled, validation_status: priorRule.validation_status },
        new_value: { enabled: data.enabled, validation_status: data.validation_status },
      },
    });

    res.json(data);
  } catch (error: any) {
    console.error('Error updating generated rule:', error);
    res.status(500).json({ error: error.message || 'Failed to update generated rule' });
  }
});

// DELETE /api/organizations/:id/generated-rules/:ruleId
router.delete('/:id/generated-rules/:ruleId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    const ruleId = req.params.ruleId;
    if (!(await hasPermission(userId, orgId, 'manage_organization_settings'))) {
      return res.status(403).json({ error: 'You do not have permission to delete generated rules' });
    }

    const { data: priorRule } = await supabase
      .from('organization_generated_rules')
      .select('id, cve_id, package_purl, generated_with_model, validation_status')
      .eq('organization_id', orgId)
      .eq('id', ruleId)
      .maybeSingle();

    if (!priorRule) return res.status(404).json({ error: 'Rule not found' });

    const { error } = await supabase
      .from('organization_generated_rules')
      .delete()
      .eq('organization_id', orgId)
      .eq('id', ruleId);
    if (error) throw error;

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'deleted_generated_rule',
      description: `deleted generated rule for ${priorRule.cve_id} (${priorRule.package_purl})`,
      metadata: {
        rule_id: ruleId,
        cve_id: priorRule.cve_id,
        package_purl: priorRule.package_purl,
        deleted_rule: priorRule,
      },
    });

    res.status(204).end();
  } catch (error: any) {
    console.error('Error deleting generated rule:', error);
    res.status(500).json({ error: error.message || 'Failed to delete generated rule' });
  }
});

// POST /api/organizations/:id/generated-rules/:ruleId/regenerate
router.post('/:id/generated-rules/:ruleId/regenerate', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    const ruleId = req.params.ruleId;
    if (!(await hasPermission(userId, orgId, 'manage_organization_settings'))) {
      return res.status(403).json({ error: 'You do not have permission to regenerate rules' });
    }

    const { provider, model } = req.body ?? {};
    if (!provider || !VALID_PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: `provider must be one of ${VALID_PROVIDERS.join('/')}` });
    }
    if (!model || typeof model !== 'string' || model.length === 0 || model.length > 100) {
      return res.status(400).json({ error: 'model must be a non-empty string ≤100 chars' });
    }

    const { data: rule } = await supabase
      .from('organization_generated_rules')
      .select('*')
      .eq('organization_id', orgId)
      .eq('id', ruleId)
      .maybeSingle();
    if (!rule) return res.status(404).json({ error: 'Rule not found' });

    // Push current state into previous_versions (LIFO, newest first), then
    // mark the row pending so the next scan picks it up via the in-process
    // generation step. The actual regeneration happens in the
    // extraction-worker; this endpoint only stages the request.
    const priorVersion = {
      rule_yaml: rule.rule_yaml,
      vulnerable_fixture: rule.vulnerable_fixture,
      safe_fixture: rule.safe_fixture,
      generated_with_provider: rule.generated_with_provider,
      generated_with_model: rule.generated_with_model,
      generation_cost_usd: rule.generation_cost_usd,
      validation_status: rule.validation_status,
      validation_log: rule.validation_log,
      generated_at: rule.generated_at,
      replaced_at: new Date().toISOString(),
      replaced_by_user_id: userId,
    };

    const newPreviousVersions = [priorVersion, ...(rule.previous_versions ?? [])].slice(0, 10);

    const { data, error } = await supabase
      .from('organization_generated_rules')
      .update({
        validation_status: 'pending',
        generated_with_provider: provider,
        generated_with_model: model,
        previous_versions: newPreviousVersions,
        // Keep the existing rule_yaml + fixtures live until regen lands so
        // Semgrep keeps matching. The pipeline overwrites them after
        // successful validation.
      })
      .eq('organization_id', orgId)
      .eq('id', ruleId)
      .select('*')
      .single();
    if (error) throw error;

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'regenerate_queued',
      description: `queued rule regeneration for ${rule.cve_id} (${rule.package_purl}) with ${provider}/${model}`,
      metadata: {
        rule_id: ruleId,
        cve_id: rule.cve_id,
        package_purl: rule.package_purl,
        from_model: `${rule.generated_with_provider}/${rule.generated_with_model}`,
        to_model: `${provider}/${model}`,
      },
    });

    res.status(202).json({
      rule: data,
      message: 'Regeneration queued. Will run on the next extraction scan for any project that uses this rule.',
    });
  } catch (error: any) {
    console.error('Error queueing rule regeneration:', error);
    res.status(500).json({ error: error.message || 'Failed to queue regeneration' });
  }
});

export default router;
