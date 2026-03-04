import express from 'express';

const router = express.Router();

// POST /api/internal/aegis/execute-task-step
// Called by QStash to execute individual task steps
router.post('/execute-task-step', async (req, res) => {
  try {
    // Verify auth: QStash signature or internal API key
    const internalKey = req.headers['x-internal-api-key'] as string;
    const qstashSignature = req.headers['upstash-signature'] as string;

    if (!internalKey && !qstashSignature) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (internalKey && internalKey !== process.env.INTERNAL_API_KEY) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const { taskId, stepId } = req.body;
    if (!taskId || !stepId) {
      return res.status(400).json({ error: 'taskId and stepId are required' });
    }

    const { executeTaskStep, getNextPendingStep } = await import('../lib/aegis/tasks');

    const result = await executeTaskStep(taskId, stepId);

    // Phase 17: Check if this step is part of an incident playbook
    const { data: completedStep } = await (await import('../lib/supabase')).supabase
      .from('aegis_task_steps')
      .select('*')
      .eq('id', stepId)
      .single();

    let incidentHandled = false;
    if (completedStep?.tool_params?.__incident_id) {
      try {
        const { handleIncidentStepCompletion } = await import('../lib/incident-engine');
        incidentHandled = await handleIncidentStepCompletion(taskId, completedStep, result);
      } catch (err) {
        console.error('[Aegis Task] Incident step handling failed:', err);
      }
    }

    // If there are more steps and incident engine didn't already handle queueing
    if (!incidentHandled && result.hasMore && result.success) {
      const nextStepId = await getNextPendingStep(taskId);
      if (nextStepId) {
        try {
          const qstashToken = process.env.QSTASH_TOKEN;
          const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
          if (qstashToken) {
            await fetch('https://qstash.upstash.io/v2/publish/' + encodeURIComponent(`${backendUrl}/api/internal/aegis/execute-task-step`), {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${qstashToken}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ taskId, stepId: nextStepId }),
            });
          }
        } catch (qErr) {
          console.error('[Aegis Task] Failed to queue next step via QStash:', qErr);
        }
      }
    }

    res.json(result);
  } catch (error: any) {
    console.error('[Aegis Task Step] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/internal/aegis/check-due-automations
// Called by QStash cron every 5 min
router.post('/check-due-automations', async (req, res) => {
  try {
    const internalKey = req.headers['x-internal-api-key'] as string;
    const qstashSignature = req.headers['upstash-signature'] as string;

    if (!internalKey && !qstashSignature) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (internalKey && internalKey !== process.env.INTERNAL_API_KEY) {
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

    if (internalKey && internalKey !== process.env.INTERNAL_API_KEY) {
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

    if (internalKey && internalKey !== process.env.INTERNAL_API_KEY) {
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
