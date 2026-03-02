/**
 * Phase 17: CE escalation route for incident phase timeouts.
 * Called by QStash delayed publish when a phase exceeds its timeout.
 */

import express from 'express';
import { supabase } from '../lib/supabase';

const router = express.Router();

router.post('/escalate', async (req, res) => {
  try {
    const internalKey = req.headers['x-internal-api-key'] as string;
    const qstashSignature = req.headers['upstash-signature'] as string;

    if (!internalKey && !qstashSignature) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (internalKey && internalKey !== process.env.INTERNAL_API_KEY) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const { incidentId, phase } = req.body;
    if (!incidentId || !phase) {
      return res.status(400).json({ error: 'Missing incidentId or phase' });
    }

    const { data: incident } = await supabase
      .from('security_incidents')
      .select('*')
      .eq('id', incidentId)
      .single();

    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    if (incident.current_phase !== phase) {
      return res.json({ skipped: true, reason: 'Phase already advanced' });
    }
    if (['resolved', 'closed', 'aborted'].includes(incident.status)) {
      return res.json({ skipped: true, reason: 'Incident already terminal' });
    }

    const newLevel = (incident.escalation_level || 0) + 1;

    await supabase
      .from('security_incidents')
      .update({ escalation_level: newLevel })
      .eq('id', incidentId);

    await supabase.from('incident_timeline').insert({
      incident_id: incidentId,
      phase,
      event_type: 'escalation_fired',
      description: `Phase "${phase}" timed out — escalated to level ${newLevel}`,
      actor: 'system',
    });

    try {
      const { emitEvent } = require('../../../ee/backend/lib/event-bus');
      await emitEvent({
        type: 'incident_escalated',
        organizationId: incident.organization_id,
        payload: {
          incident_id: incidentId,
          title: incident.title,
          severity: incident.severity,
          phase,
          escalation_level: newLevel,
        },
        source: 'incident_engine',
        priority: 'critical',
      });
    } catch (_) {}

    res.json({ escalated: true, level: newLevel });
  } catch (error: any) {
    console.error('[Incident Escalation] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
