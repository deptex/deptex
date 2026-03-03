/**
 * Phase 17: Incident Response API endpoints (EE).
 * Handles incident CRUD, playbook management, stats, notes, post-mortem, and dry-run.
 */

import express from 'express';
import { authenticateUser, AuthRequest } from '../../../backend/src/middleware/auth';
import { supabase } from '../../../backend/src/lib/supabase';

const router = express.Router();

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

// ─── Incidents ───────────────────────────────────────────────────────────────

// GET /api/organizations/:id/incidents
router.get('/:id/incidents', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await requireMembership(req.user!.id, orgId))) {
      return res.status(403).json({ error: 'Not a member' });
    }

    const { status, type, severity, page = '1', limit = '20' } = req.query;
    const pageNum = Math.max(1, parseInt(page as string, 10) || 1);
    const pageSize = Math.min(50, parseInt(limit as string, 10) || 20);
    const offset = (pageNum - 1) * pageSize;

    let query = supabase
      .from('security_incidents')
      .select('*', { count: 'exact' })
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (status) {
      const statuses = (status as string).split(',');
      query = query.in('status', statuses);
    }
    if (type) query = query.eq('incident_type', type as string);
    if (severity) query = query.eq('severity', severity as string);

    const { data, count, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    res.json({
      incidents: data || [],
      total: count || 0,
      page: pageNum,
      pageSize,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/organizations/:id/incidents/stats
router.get('/:id/incidents/stats', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await requireMembership(req.user!.id, orgId))) {
      return res.status(403).json({ error: 'Not a member' });
    }

    const { count: activeCount } = await supabase
      .from('security_incidents')
      .select('id', { count: 'exact', head: true })
      .eq('organization_id', orgId)
      .not('status', 'in', '("resolved","closed","aborted")');

    const { data: activeByPriority } = await supabase
      .from('security_incidents')
      .select('severity')
      .eq('organization_id', orgId)
      .not('status', 'in', '("resolved","closed","aborted")');

    const severityBreakdown: Record<string, number> = {};
    for (const i of activeByPriority || []) {
      severityBreakdown[i.severity] = (severityBreakdown[i.severity] || 0) + 1;
    }

    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);

    const { data: monthly } = await supabase
      .from('security_incidents')
      .select('status, total_duration_ms')
      .eq('organization_id', orgId)
      .gte('declared_at', monthStart.toISOString());

    const monthlyCount = monthly?.length || 0;
    const resolvedThisMonth = (monthly || []).filter(
      (i: any) => i.status === 'resolved' || i.status === 'closed',
    ).length;

    const resolvedDurations = (monthly || [])
      .filter((i: any) => i.total_duration_ms && i.total_duration_ms > 0)
      .map((i: any) => i.total_duration_ms as number);
    const avgResolutionMs =
      resolvedDurations.length > 0
        ? Math.round(resolvedDurations.reduce((a, b) => a + b, 0) / resolvedDurations.length)
        : null;

    const { count: totalResolved } = await supabase
      .from('security_incidents')
      .select('id', { count: 'exact', head: true })
      .eq('organization_id', orgId)
      .in('status', ['resolved', 'closed']);

    res.json({
      active: activeCount || 0,
      severityBreakdown,
      monthlyCount,
      resolvedThisMonth,
      activeThisMonth: monthlyCount - resolvedThisMonth,
      avgResolutionMs,
      totalResolved: totalResolved || 0,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/organizations/:id/incidents/:incidentId
router.get('/:id/incidents/:incidentId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await requireMembership(req.user!.id, orgId))) {
      return res.status(403).json({ error: 'Not a member' });
    }

    const { data: incident } = await supabase
      .from('security_incidents')
      .select('*')
      .eq('id', req.params.incidentId)
      .eq('organization_id', orgId)
      .single();

    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    const { data: timeline } = await supabase
      .from('incident_timeline')
      .select('*')
      .eq('incident_id', incident.id)
      .order('created_at', { ascending: true });

    const { data: notes } = await supabase
      .from('incident_notes')
      .select('*')
      .eq('incident_id', incident.id)
      .order('created_at', { ascending: true });

    res.json({ ...incident, timeline: timeline || [], notes: notes || [] });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/organizations/:id/incidents (manual declaration)
router.post('/:id/incidents', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await hasPermission(req.user!.id, orgId, 'manage_incidents'))) {
      return res.status(403).json({ error: 'manage_incidents permission required' });
    }

    const { title, severity, incidentType, affectedProjects, affectedPackages, playbookId } = req.body;
    if (!title || !severity || !incidentType) {
      return res.status(400).json({ error: 'title, severity, and incidentType are required' });
    }

    if (playbookId) {
      const { data: playbook } = await supabase
        .from('incident_playbooks')
        .select('*')
        .eq('id', playbookId)
        .eq('organization_id', orgId)
        .single();

      if (playbook) {
        const { declareIncident } = require('../lib/incident-engine');
        const syntheticEvent = {
          event_type: 'manual_declaration',
          organization_id: orgId,
          project_id: affectedProjects?.[0],
          payload: { title, severity, incidentType, affected_packages: affectedPackages },
          source: 'manual',
        };
        const incidentId = await declareIncident(orgId, playbook, syntheticEvent);
        return res.json({ id: incidentId });
      }
    }

    const { data: incident, error } = await supabase
      .from('security_incidents')
      .insert({
        organization_id: orgId,
        title,
        incident_type: incidentType,
        severity,
        status: 'active',
        current_phase: 'contain',
        trigger_source: 'manual',
        declared_by: req.user!.id,
        affected_projects: affectedProjects || [],
        affected_packages: affectedPackages || [],
      })
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });

    await supabase.from('incident_timeline').insert({
      incident_id: incident.id,
      phase: 'contain',
      event_type: 'phase_started',
      description: `Incident manually declared by user`,
      actor: req.user!.email || 'user',
    });

    res.json(incident);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/organizations/:id/incidents/:incidentId/resolve
router.patch('/:id/incidents/:incidentId/resolve', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await hasPermission(req.user!.id, orgId, 'manage_incidents'))) {
      return res.status(403).json({ error: 'manage_incidents permission required' });
    }

    const { resolveIncident, addTimelineEvent } = require('../lib/incident-engine');
    await addTimelineEvent(
      req.params.incidentId, 'report', 'action_taken',
      `Incident resolved by ${req.user!.email || 'user'}`, req.user!.email,
    );
    await resolveIncident(req.params.incidentId);
    res.json({ resolved: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/organizations/:id/incidents/:incidentId/close
router.patch('/:id/incidents/:incidentId/close', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await hasPermission(req.user!.id, orgId, 'manage_incidents'))) {
      return res.status(403).json({ error: 'manage_incidents permission required' });
    }

    const { is_false_positive } = req.body;
    const now = new Date().toISOString();
    await supabase
      .from('security_incidents')
      .update({
        status: 'closed',
        closed_at: now,
        is_false_positive: is_false_positive || false,
      })
      .eq('id', req.params.incidentId)
      .eq('organization_id', orgId);

    await supabase.from('incident_timeline').insert({
      incident_id: req.params.incidentId,
      phase: 'report',
      event_type: 'action_taken',
      description: is_false_positive
        ? `Incident closed as false positive by ${req.user!.email}`
        : `Incident closed by ${req.user!.email}`,
      actor: req.user!.email || 'user',
    });

    res.json({ closed: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/organizations/:id/incidents/:incidentId/abort
router.patch('/:id/incidents/:incidentId/abort', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await hasPermission(req.user!.id, orgId, 'manage_incidents'))) {
      return res.status(403).json({ error: 'manage_incidents permission required' });
    }

    const { data: incident } = await supabase
      .from('security_incidents')
      .select('task_id')
      .eq('id', req.params.incidentId)
      .eq('organization_id', orgId)
      .single();

    await supabase
      .from('security_incidents')
      .update({ status: 'aborted' })
      .eq('id', req.params.incidentId);

    if (incident?.task_id) {
      await supabase
        .from('aegis_tasks')
        .update({ status: 'cancelled', completed_at: new Date().toISOString() })
        .eq('id', incident.task_id);
      await supabase
        .from('aegis_task_steps')
        .update({ status: 'skipped' })
        .eq('task_id', incident.task_id)
        .in('status', ['pending', 'running']);
    }

    await supabase.from('incident_timeline').insert({
      incident_id: req.params.incidentId,
      phase: 'report',
      event_type: 'action_taken',
      description: `Incident aborted by ${req.user!.email}`,
      actor: req.user!.email || 'user',
    });

    try {
      const { emitEvent } = require('../lib/event-bus');
      const { data: inc } = await supabase
        .from('security_incidents')
        .select('organization_id, title, severity')
        .eq('id', req.params.incidentId)
        .single();
      if (inc) {
        await emitEvent({
          type: 'incident_aborted',
          organizationId: inc.organization_id,
          payload: { incident_id: req.params.incidentId, title: inc.title, severity: inc.severity },
          source: 'incident_engine',
          priority: 'high',
        });
      }
    } catch (_) {}

    res.json({ aborted: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/organizations/:id/incidents/:incidentId/notes
router.post('/:id/incidents/:incidentId/notes', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await requireMembership(req.user!.id, orgId))) {
      return res.status(403).json({ error: 'Not a member' });
    }

    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ error: 'content is required' });

    const { data, error } = await supabase
      .from('incident_notes')
      .insert({
        incident_id: req.params.incidentId,
        author_id: req.user!.id,
        content: content.trim(),
      })
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });

    await supabase.from('incident_timeline').insert({
      incident_id: req.params.incidentId,
      phase: 'report',
      event_type: 'note_added',
      description: `Note added by ${req.user!.email}`,
      actor: req.user!.email || 'user',
    });

    res.json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/organizations/:id/incidents/:incidentId/post-mortem
router.get('/:id/incidents/:incidentId/post-mortem', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await requireMembership(req.user!.id, orgId))) {
      return res.status(403).json({ error: 'Not a member' });
    }

    const { data: incident } = await supabase
      .from('security_incidents')
      .select('post_mortem')
      .eq('id', req.params.incidentId)
      .eq('organization_id', orgId)
      .single();

    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    if (incident.post_mortem) {
      return res.json({ markdown: incident.post_mortem });
    }

    const { generatePostMortem } = require('../lib/incident-postmortem');
    const markdown = await generatePostMortem(req.params.incidentId);
    res.json({ markdown });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Playbooks ───────────────────────────────────────────────────────────────

// GET /api/organizations/:id/playbooks
router.get('/:id/playbooks', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await requireMembership(req.user!.id, orgId))) {
      return res.status(403).json({ error: 'Not a member' });
    }

    const { data, error } = await supabase
      .from('incident_playbooks')
      .select('*')
      .eq('organization_id', orgId)
      .order('is_template', { ascending: false })
      .order('created_at', { ascending: true });

    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/organizations/:id/playbooks
router.post('/:id/playbooks', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await hasPermission(req.user!.id, orgId, 'manage_incidents'))) {
      return res.status(403).json({ error: 'manage_incidents permission required' });
    }

    const { name, description, triggerType, triggerCriteria, phases, autoExecute, notificationChannels } = req.body;
    if (!name || !triggerType || !phases?.length) {
      return res.status(400).json({ error: 'name, triggerType, and phases are required' });
    }

    const { data, error } = await supabase
      .from('incident_playbooks')
      .insert({
        organization_id: orgId,
        name,
        description: description || null,
        trigger_type: triggerType,
        trigger_criteria: triggerCriteria || null,
        phases,
        auto_execute: autoExecute || false,
        notification_channels: notificationChannels || null,
        created_by: req.user!.id,
      })
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/organizations/:id/playbooks/:playbookId
router.put('/:id/playbooks/:playbookId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await hasPermission(req.user!.id, orgId, 'manage_incidents'))) {
      return res.status(403).json({ error: 'manage_incidents permission required' });
    }

    const { name, description, triggerCriteria, phases, autoExecute, enabled, notificationChannels } = req.body;
    const updates: Record<string, any> = { updated_by: req.user!.id, updated_at: new Date().toISOString() };
    if (name !== undefined) updates.name = name;
    if (description !== undefined) updates.description = description;
    if (triggerCriteria !== undefined) updates.trigger_criteria = triggerCriteria;
    if (phases !== undefined) updates.phases = phases;
    if (autoExecute !== undefined) updates.auto_execute = autoExecute;
    if (enabled !== undefined) updates.enabled = enabled;
    if (notificationChannels !== undefined) updates.notification_channels = notificationChannels;

    const { data, error } = await supabase
      .from('incident_playbooks')
      .update(updates)
      .eq('id', req.params.playbookId)
      .eq('organization_id', orgId)
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/organizations/:id/playbooks/:playbookId
router.delete('/:id/playbooks/:playbookId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await hasPermission(req.user!.id, orgId, 'manage_incidents'))) {
      return res.status(403).json({ error: 'manage_incidents permission required' });
    }

    const { data: playbook } = await supabase
      .from('incident_playbooks')
      .select('is_template')
      .eq('id', req.params.playbookId)
      .eq('organization_id', orgId)
      .single();

    if (!playbook) return res.status(404).json({ error: 'Playbook not found' });
    if (playbook.is_template) return res.status(400).json({ error: 'Cannot delete template playbooks' });

    await supabase
      .from('incident_playbooks')
      .delete()
      .eq('id', req.params.playbookId)
      .eq('organization_id', orgId);

    res.json({ deleted: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/organizations/:id/playbooks/:playbookId/dry-run
router.post('/:id/playbooks/:playbookId/dry-run', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    if (!(await hasPermission(req.user!.id, orgId, 'manage_incidents'))) {
      return res.status(403).json({ error: 'manage_incidents permission required' });
    }

    const { data: playbook } = await supabase
      .from('incident_playbooks')
      .select('*')
      .eq('id', req.params.playbookId)
      .eq('organization_id', orgId)
      .single();

    if (!playbook) return res.status(404).json({ error: 'Playbook not found' });

    const phases = Array.isArray(playbook.phases) ? playbook.phases : [];
    const simulation = phases.map((phase: any) => ({
      phase: phase.phase,
      name: phase.name,
      requiresApproval: phase.requiresApproval,
      timeoutMinutes: phase.timeoutMinutes || null,
      steps: (phase.steps || []).map((step: any) => ({
        tool: step.tool,
        params: step.params,
        condition: step.condition || null,
        onFailure: step.onFailure,
        wouldExecute: true,
      })),
    }));

    res.json({
      playbook: { id: playbook.id, name: playbook.name, trigger_type: playbook.trigger_type },
      simulation,
      totalSteps: phases.reduce((sum: number, p: any) => sum + (p.steps?.length || 0), 0),
      phasesWithApproval: phases.filter((p: any) => p.requiresApproval).map((p: any) => p.phase),
      estimatedMinutes: phases.reduce((sum: number, p: any) => sum + (p.timeoutMinutes || 10), 0),
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
