/**
 * Phase 16: Learning Cron Endpoints (CE route)
 * - POST /recompute-patterns: Daily pattern recomputation + outcome backfill
 * - POST /check-feedback-prompts: Deliver feedback prompt notifications for merged fixes
 */

import express from 'express';
import { supabase } from '../lib/supabase';
import { getEeModulePath } from '../lib/ee-loader';

const router = express.Router();

async function verifyInternalAuth(req: express.Request): Promise<boolean> {
  const internalKey = process.env.INTERNAL_API_KEY;
  if (internalKey && req.headers['x-internal-api-key'] === internalKey) return true;

  try {
    const qstashKeys = {
      currentSigningKey: process.env.QSTASH_CURRENT_SIGNING_KEY,
      nextSigningKey: process.env.QSTASH_NEXT_SIGNING_KEY,
    };
    if (!qstashKeys.currentSigningKey) return false;
    const signature = req.headers['upstash-signature'] as string;
    if (!signature) return false;
    const { Receiver } = await import('@upstash/qstash');
    const receiver = new Receiver(qstashKeys as any);
    const rawBody = (req as any).rawBody || JSON.stringify(req.body);
    await receiver.verify({ signature, body: rawBody });
    return true;
  } catch {
    return false;
  }
}

router.post('/recompute-patterns', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    let backfilledCount = 0;
    let recomputedOrgs = 0;

    try {
      const { backfillMissingOutcomes } = await import(
        getEeModulePath('learning/outcome-recorder')
      );
      backfilledCount = await backfillMissingOutcomes();
    } catch (e) {
      console.warn('[learning-cron] Backfill failed (non-fatal):', (e as Error).message);
    }

    try {
      const { recomputeAllStaleOrgs } = await import(
        getEeModulePath('learning/pattern-engine')
      );
      recomputedOrgs = await recomputeAllStaleOrgs();
    } catch (e) {
      console.warn('[learning-cron] Pattern recompute failed (non-fatal):', (e as Error).message);
    }

    console.log(`[learning-cron] Recompute complete: ${backfilledCount} backfilled, ${recomputedOrgs} orgs recomputed`);
    return res.json({ success: true, backfilledCount, recomputedOrgs });
  } catch (e) {
    console.error('[learning-cron] recompute-patterns failed:', (e as Error).message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/check-feedback-prompts', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

    const { data: eligibleOutcomes } = await supabase
      .from('fix_outcomes')
      .select(`
        id, organization_id, fix_job_id, strategy, package_name,
        fix_type, project_id
      `)
      .eq('pr_merged', true)
      .is('human_quality_rating', null)
      .is('feedback_prompted_at', null)
      .lt('pr_merged_at', twentyFourHoursAgo)
      .gt('created_at', sevenDaysAgo)
      .limit(50);

    if (!eligibleOutcomes || eligibleOutcomes.length === 0) {
      return res.json({ success: true, promptsSent: 0 });
    }

    let promptsSent = 0;

    for (const outcome of eligibleOutcomes) {
      try {
        const { data: fixJob } = await supabase
          .from('project_security_fixes')
          .select('triggered_by, osv_id, payload')
          .eq('id', outcome.fix_job_id)
          .single();

        if (!fixJob?.triggered_by) continue;

        const identifier = fixJob.osv_id || outcome.package_name || outcome.fix_type;
        let projectName = 'your project';
        if (outcome.project_id) {
          const { data: project } = await supabase
            .from('projects')
            .select('name')
            .eq('id', outcome.project_id)
            .single();
          if (project?.name) projectName = project.name;
        }

        await supabase.from('user_notifications').insert({
          user_id: fixJob.triggered_by,
          organization_id: outcome.organization_id,
          title: 'How was the fix quality?',
          body: `You merged Aegis's fix for ${identifier} in ${projectName}. Rate the quality to help Aegis learn.`,
          severity: 'info',
          event_type: 'fix_feedback_request',
          project_id: outcome.project_id,
          deptex_url: `/organizations/${outcome.organization_id}/learning?feedback=${outcome.id}`,
          metadata: {
            fix_outcome_id: outcome.id,
            strategy: outcome.strategy,
            package_name: outcome.package_name,
          },
        });

        await supabase
          .from('fix_outcomes')
          .update({ feedback_prompted_at: new Date().toISOString() })
          .eq('id', outcome.id);

        promptsSent++;
      } catch (e) {
        console.warn(`[learning-cron] Failed to send feedback prompt for outcome ${outcome.id}:`, (e as Error).message);
      }
    }

    console.log(`[learning-cron] Feedback prompts sent: ${promptsSent}`);
    return res.json({ success: true, promptsSent });
  } catch (e) {
    console.error('[learning-cron] check-feedback-prompts failed:', (e as Error).message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

export default router;
