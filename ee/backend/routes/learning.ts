/**
 * Phase 16: Aegis Learning API (EE route)
 * Mounted at /api/organizations
 */

import express from 'express';
import { supabase } from '../../../backend/src/lib/supabase';
import { authenticateUser } from '../../../backend/src/middleware/auth';
import { recommendStrategies, getDashboardData } from '../lib/learning/recommendation-engine';
import { recomputePatterns } from '../lib/learning/pattern-engine';

const router = express.Router();

async function checkOrgMember(userId: string, orgId: string): Promise<{ isMember: boolean; permissions: Record<string, boolean> }> {
  const { data } = await supabase
    .from('organization_members')
    .select('role, organization_roles(permissions)')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();

  if (!data) return { isMember: false, permissions: {} };
  const perms = (data as any).organization_roles?.permissions || {};
  return { isMember: true, permissions: perms };
}

// GET /api/organizations/:id/learning/recommendations
router.get('/:id/learning/recommendations', authenticateUser, async (req, res) => {
  try {
    const orgId = req.params.id;
    const { isMember, permissions } = await checkOrgMember(req.user!.id, orgId);
    if (!isMember) return res.status(403).json({ error: 'Not a member of this organization' });
    if (!permissions.interact_with_aegis && !permissions.manage_aegis) {
      return res.status(403).json({ error: 'Missing interact_with_aegis permission' });
    }

    const ecosystem = (req.query.ecosystem as string) || 'npm';
    const vulnType = (req.query.vulnType as string) || null;
    const isDirect = req.query.isDirect === 'false' ? false : true;
    const fixType = (req.query.fixType as string as 'vulnerability' | 'semgrep' | 'secret') || 'vulnerability';

    const recommendations = await recommendStrategies(orgId, ecosystem, vulnType, isDirect, fixType);
    return res.json({ recommendations });
  } catch (e) {
    console.error('[learning] GET recommendations failed:', (e as Error).message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// GET /api/organizations/:id/learning/dashboard
router.get('/:id/learning/dashboard', authenticateUser, async (req, res) => {
  try {
    const orgId = req.params.id;
    const { isMember, permissions } = await checkOrgMember(req.user!.id, orgId);
    if (!isMember) return res.status(403).json({ error: 'Not a member of this organization' });
    if (!permissions.interact_with_aegis && !permissions.manage_aegis) {
      return res.status(403).json({ error: 'Missing interact_with_aegis permission' });
    }

    const timeRange = (req.query.timeRange as string) || undefined;
    const data = await getDashboardData(orgId, timeRange);
    return res.json(data);
  } catch (e) {
    console.error('[learning] GET dashboard failed:', (e as Error).message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// GET /api/organizations/:id/learning/outcomes
router.get('/:id/learning/outcomes', authenticateUser, async (req, res) => {
  try {
    const orgId = req.params.id;
    const { isMember, permissions } = await checkOrgMember(req.user!.id, orgId);
    if (!isMember) return res.status(403).json({ error: 'Not a member of this organization' });
    if (!permissions.interact_with_aegis && !permissions.manage_aegis) {
      return res.status(403).json({ error: 'Missing interact_with_aegis permission' });
    }

    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const offset = (page - 1) * limit;

    let query = supabase
      .from('fix_outcomes')
      .select('*', { count: 'exact' })
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (req.query.strategy) query = query.eq('strategy', req.query.strategy);
    if (req.query.success === 'true') query = query.eq('success', true);
    if (req.query.success === 'false') query = query.eq('success', false);
    if (req.query.ecosystem) query = query.eq('ecosystem', req.query.ecosystem);

    const { data, count, error } = await query;
    if (error) throw error;

    return res.json({
      outcomes: data || [],
      total: count || 0,
      page,
      limit,
    });
  } catch (e) {
    console.error('[learning] GET outcomes failed:', (e as Error).message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// POST /api/organizations/:id/learning/feedback
router.post('/:id/learning/feedback', authenticateUser, async (req, res) => {
  try {
    const orgId = req.params.id;
    const { isMember } = await checkOrgMember(req.user!.id, orgId);
    if (!isMember) return res.status(403).json({ error: 'Not a member of this organization' });

    const { fixOutcomeId, rating } = req.body;
    if (!fixOutcomeId || typeof rating !== 'number' || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'fixOutcomeId required, rating must be 1-5' });
    }

    const { data: outcome } = await supabase
      .from('fix_outcomes')
      .select('id, organization_id')
      .eq('id', fixOutcomeId)
      .eq('organization_id', orgId)
      .single();

    if (!outcome) {
      return res.status(404).json({ error: 'Fix outcome not found' });
    }

    const { error } = await supabase
      .from('fix_outcomes')
      .update({ human_quality_rating: Math.round(rating) })
      .eq('id', fixOutcomeId);

    if (error) throw error;

    try {
      await recomputePatterns(orgId);
    } catch {
      // Non-fatal
    }

    return res.json({ success: true });
  } catch (e) {
    console.error('[learning] POST feedback failed:', (e as Error).message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

export default router;
