import express from 'express';
import { isValidInternalKey } from '../middleware/internal-key';

// Internal QStash-driven automations + debt-snapshot endpoints. (The legacy
// aegis-v2 `execute-task-step` handler was removed with the v2 task primitive;
// the new Aegis Task uses the project_security_fixes pipeline, not step jobs.)
const router = express.Router();

// POST /api/internal/aegis/check-due-automations
// Called by QStash cron every 5 min
router.post('/check-due-automations', async (req, res) => {
  try {
    const internalKey = req.headers['x-internal-api-key'] as string;
    const qstashSignature = req.headers['upstash-signature'] as string;

    if (!internalKey && !qstashSignature) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (internalKey && !isValidInternalKey(internalKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const { checkDueAutomations } = await import('../lib/aegis/automations-engine');

    await checkDueAutomations();
    res.json({ success: true });
  } catch (error: any) {
    console.error('[Aegis Automations] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/internal/aegis/run-automation/:id
router.post('/run-automation/:id', async (req, res) => {
  try {
    const internalKey = req.headers['x-internal-api-key'] as string;
    const qstashSignature = req.headers['upstash-signature'] as string;

    if (!internalKey && !qstashSignature) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (internalKey && !isValidInternalKey(internalKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const { runAutomation } = await import('../lib/aegis/automations-engine');

    await runAutomation(req.params.id);
    res.json({ success: true });
  } catch (error: any) {
    console.error('[Aegis Automation Run] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/internal/aegis/snapshot-debt
// Called by QStash cron daily at 2AM UTC
router.post('/snapshot-debt', async (req, res) => {
  try {
    const internalKey = req.headers['x-internal-api-key'] as string;
    const qstashSignature = req.headers['upstash-signature'] as string;

    if (!internalKey && !qstashSignature) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (internalKey && !isValidInternalKey(internalKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const { supabase } = await import('../lib/supabase');
    const { data: orgs } = await supabase.from('organizations').select('id');

    if (orgs?.length) {
      const { snapshotDebt } = await import('../lib/aegis/security-debt');
      for (const org of orgs) {
        try {
          await snapshotDebt(org.id);
        } catch (err) {
          console.error(`[Aegis Debt] Snapshot failed for org ${org.id}:`, err);
        }
      }
    }

    res.json({ success: true, orgsProcessed: orgs?.length || 0 });
  } catch (error: any) {
    console.error('[Aegis Debt Snapshot] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
