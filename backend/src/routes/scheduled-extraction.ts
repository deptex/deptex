/**
 * 8N: Daily/Weekly Extraction Scheduler (QStash cron endpoint)
 * CE route mounted outside isEeEdition() block.
 * Schedule: 0 *\/6 * * * (every 6 hours)
 */

import express from 'express';
import { supabase } from '../lib/supabase';
import { getEeModulePath } from '../lib/ee-loader';

const router = express.Router();

const MAX_JOBS_PER_INVOCATION = 20;
const MAX_JOBS_PER_ORG = 5;

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

router.post('/scheduled-extraction', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

    const { data: dailyProjects } = await supabase
      .from('project_repositories')
      .select('project_id, projects(organization_id)')
      .eq('sync_frequency', 'daily')
      .not('status', 'in', '("repo_deleted","access_revoked","installation_removed")')
      .or(`last_extracted_at.is.null,last_extracted_at.lt.${twentyFourHoursAgo}`);

    const { data: weeklyProjects } = await supabase
      .from('project_repositories')
      .select('project_id, projects(organization_id)')
      .eq('sync_frequency', 'weekly')
      .not('status', 'in', '("repo_deleted","access_revoked","installation_removed")')
      .or(`last_extracted_at.is.null,last_extracted_at.lt.${sevenDaysAgo}`);

    const eligible = [...(dailyProjects ?? []), ...(weeklyProjects ?? [])];

    const byOrg = new Map<string, string[]>();
    for (const row of eligible as any[]) {
      const orgId = Array.isArray(row.projects) ? row.projects[0]?.organization_id : row.projects?.organization_id;
      if (!orgId) continue;
      if (!byOrg.has(orgId)) byOrg.set(orgId, []);
      byOrg.get(orgId)!.push(row.project_id);
    }

    let queued = 0;
    let skippedDuplicate = 0;
    let skippedCap = 0;

    for (const [orgId, projectIds] of byOrg) {
      const toQueue = projectIds.slice(0, MAX_JOBS_PER_ORG);
      const capped = projectIds.length - toQueue.length;
      skippedCap += capped;

      for (const projectId of toQueue) {
        if (queued >= MAX_JOBS_PER_INVOCATION) {
          skippedCap++;
          continue;
        }

        try {
          const { queueExtractionJob } = await import(getEeModulePath('redis'));
          const { data: repo } = await supabase
            .from('project_repositories')
            .select('*')
            .eq('project_id', projectId)
            .single();

          if (!repo) continue;

          const result = await queueExtractionJob(projectId, orgId, repo);
          if (result.success) {
            queued++;
            console.log(`[scheduled-extraction] Queued extraction for project ${projectId}`);
          } else if (result.error?.includes('already')) {
            skippedDuplicate++;
          }
        } catch (err: any) {
          console.error(`[scheduled-extraction] Failed to queue project ${projectId}:`, err?.message);
        }
      }
    }

    res.json({ queued, skipped_duplicate: skippedDuplicate, skipped_cap: skippedCap });
  } catch (error: any) {
    console.error('[scheduled-extraction] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
