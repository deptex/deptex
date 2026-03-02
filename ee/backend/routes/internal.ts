import express from 'express';
import { createBumpPrForProject } from '../lib/create-bump-pr';
import { supabase } from '../../../backend/src/lib/supabase';
import { emitEvent } from '../lib/event-bus';
import { invalidateCache } from '../lib/cache';

const router = express.Router();

const SLA_BATCH_LIMIT = 200;

const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY?.trim();

function requireInternalKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const raw = req.headers['x-internal-api-key'] as string || (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') ? req.headers.authorization.slice(7) : undefined);
  const key = raw?.trim();
  if (!INTERNAL_API_KEY || key !== INTERNAL_API_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

router.use(requireInternalKey);

/**
 * POST /api/internal/watchtower/create-bump-pr
 * Body: { organization_id, project_id, name, target_version [, current_version ] }
 * Used by the auto-bump worker to create bump PRs.
 */
router.post('/watchtower/create-bump-pr', async (req, res) => {
  try {
    const { organization_id, project_id, name, target_version, current_version } = req.body;
    if (!organization_id || !project_id || !name || !target_version) {
      res.status(400).json({ error: 'Missing organization_id, project_id, name, or target_version' });
      return;
    }
    const result = await createBumpPrForProject(
      organization_id,
      project_id,
      name,
      target_version,
      current_version
    );
    if ('error' in result) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ pr_url: result.pr_url, pr_number: result.pr_number });
  } catch (error: any) {
    console.error('Error creating bump PR (internal):', error);
    res.status(500).json({ error: error.message || 'Failed to create bump PR' });
  }
});

/**
 * POST /api/internal/sla-check
 * Phase 15: Called by QStash cron every 15 minutes.
 * Transitions vulns to warning/breached and emits notification events.
 */
router.post('/sla-check', async (_req, res) => {
  try {
    let warningCount = 0;
    let breachCount = 0;

    const { data: approaching, error: errApproaching } = await supabase.rpc('get_sla_approaching_warning', {
      p_batch_limit: SLA_BATCH_LIMIT,
    });
    if (errApproaching) {
      console.error('[SLA-Check] get_sla_approaching_warning error:', errApproaching.message);
    } else if (approaching?.length) {
      const now = new Date().toISOString();
      for (const row of approaching) {
        await supabase
          .from('project_dependency_vulnerabilities')
          .update({ sla_status: 'warning', sla_warning_notified_at: now })
          .eq('id', row.id);
        await emitEvent({
          type: 'sla_warning',
          organizationId: row.organization_id,
          projectId: row.project_id,
          payload: {
            osv_id: row.osv_id,
            severity: row.severity,
            sla_deadline_at: row.sla_deadline_at,
            hours_remaining: row.hours_remaining,
          },
          source: 'sla_check',
          priority: 'normal',
        }).catch((e) => console.error('[SLA-Check] emitEvent sla_warning failed:', e));
        warningCount++;
      }
    }

    const { data: breached, error: errBreached } = await supabase.rpc('get_sla_newly_breached', {
      p_batch_limit: SLA_BATCH_LIMIT,
    });
    if (errBreached) {
      console.error('[SLA-Check] get_sla_newly_breached error:', errBreached.message);
    } else if (breached?.length) {
      const now = new Date().toISOString();
      for (const row of breached) {
        await supabase
          .from('project_dependency_vulnerabilities')
          .update({
            sla_status: 'breached',
            sla_breached_at: now,
            sla_breach_notified_at: now,
          })
          .eq('id', row.id);
        const priority = row.severity === 'critical' || row.severity === 'high' ? 'critical' : 'high';
        await emitEvent({
          type: 'sla_breached',
          organizationId: row.organization_id,
          projectId: row.project_id,
          payload: {
            osv_id: row.osv_id,
            severity: row.severity,
            sla_deadline_at: row.sla_deadline_at,
            hours_overdue: row.hours_overdue,
          },
          source: 'sla_check',
          priority,
        }).catch((e) => console.error('[SLA-Check] emitEvent sla_breached failed:', e));
        breachCount++;
      }
    }

    // Phase 15: Invalidate stats caches for affected projects/orgs
    const projectIds = new Set<string>();
    const orgIds = new Set<string>();
    for (const row of approaching ?? []) {
      if (row.project_id) projectIds.add(row.project_id);
      if (row.organization_id) orgIds.add(row.organization_id);
    }
    for (const row of breached ?? []) {
      if (row.project_id) projectIds.add(row.project_id);
      if (row.organization_id) orgIds.add(row.organization_id);
    }
    for (const pid of projectIds) {
      await invalidateCache(`project-stats:${pid}`).catch(() => {});
    }
    for (const oid of orgIds) {
      await invalidateCache(`org-stats:${oid}`).catch(() => {});
    }

    res.json({ ok: true, warning_count: warningCount, breach_count: breachCount });
  } catch (error: any) {
    console.error('[SLA-Check] Error:', error);
    res.status(500).json({ error: error.message || 'SLA check failed' });
  }
});

export default router;
