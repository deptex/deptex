import express from 'express';
import { isValidInternalKey } from '../middleware/internal-key';

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

    if (internalKey && !isValidInternalKey(internalKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const { taskId, stepId } = req.body;
    if (!taskId || !stepId) {
      return res.status(400).json({ error: 'taskId and stepId are required' });
    }

    const { executeTaskStep, getNextPendingStep } = await import('../lib/aegis/tasks');

    const result = await executeTaskStep(taskId, stepId);

    // Check if this step is part of an incident playbook
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

export default router;
