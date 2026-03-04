/**
 * Phase 17: Incident execution engine.
 *
 * Converts playbook phases into aegis_task + aegis_task_steps,
 * handles phase transitions, escalation scheduling, and resolution.
 */

import { supabase } from '../lib/supabase';
import { getNextPendingStep } from './aegis/tasks';
import { logSecurityEvent } from './security-audit';

interface IncidentPlaybook {
  id: string;
  trigger_type: string;
  auto_execute: boolean;
  phases: PlaybookPhase[];
  notification_channels?: any;
  usage_count: number;
}

interface PlaybookPhase {
  phase: string;
  name: string;
  steps: PlaybookStep[];
  requiresApproval: boolean;
  timeoutMinutes?: number;
}

interface PlaybookStep {
  id: string;
  tool: string;
  params: Record<string, any>;
  condition?: string;
  onFailure: 'continue' | 'pause' | 'abort';
}

const PHASE_ORDER = ['contain', 'assess', 'communicate', 'remediate', 'verify', 'report'] as const;

const PHASE_STATUS_MAP: Record<string, string> = {
  contain: 'active',
  assess: 'assessing',
  communicate: 'communicating',
  remediate: 'remediating',
  verify: 'verifying',
  report: 'resolved',
};

function getBackendUrl(): string {
  return process.env.BACKEND_URL || process.env.API_BASE_URL || 'http://localhost:3001';
}

function getQStashToken(): string | undefined {
  return process.env.QSTASH_TOKEN;
}

async function publishToQStash(url: string, body: any, delaySeconds?: number): Promise<void> {
  const token = getQStashToken();
  if (!token) return;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
  if (delaySeconds) {
    headers['Upstash-Delay'] = `${delaySeconds}s`;
  }
  await fetch(
    'https://qstash.upstash.io/v2/publish/' + encodeURIComponent(url),
    { method: 'POST', headers, body: JSON.stringify(body) },
  );
}

// ─── Public API ──────────────────────────────────────────────────────────────

export async function declareIncident(
  orgId: string,
  playbook: IncidentPlaybook,
  triggerEvent: any,
): Promise<string> {
  const scope = extractScope(triggerEvent);
  const { buildDedupKey } = await import('./incident-triggers');

  const { data: incident, error } = await supabase
    .from('security_incidents')
    .insert({
      organization_id: orgId,
      playbook_id: playbook.id,
      title: buildIncidentTitle(playbook.trigger_type, triggerEvent),
      incident_type: playbook.trigger_type,
      severity: determineSeverity(triggerEvent),
      trigger_source: triggerEvent.source || 'notification_event',
      trigger_data: triggerEvent.payload || {},
      dedup_key: buildDedupKey(playbook.trigger_type, triggerEvent),
      affected_projects: scope.projects,
      affected_packages: scope.packages,
      affected_cves: scope.cves,
    })
    .select()
    .single();

  if (error || !incident) {
    console.error('[incident-engine] Failed to create incident:', error?.message);
    throw error || new Error('Failed to create incident');
  }

  const taskId = await createIncidentTask(orgId, incident, playbook);
  await supabase
    .from('security_incidents')
    .update({ task_id: taskId })
    .eq('id', incident.id);

  await addTimelineEvent(
    incident.id,
    'contain',
    'phase_started',
    `Incident declared: ${incident.title}`,
    'system',
  );

  try {
    const { emitEvent } = require('./event-bus');
    await emitEvent({
      type: 'incident_declared',
      organizationId: orgId,
      payload: {
        incident_id: incident.id,
        title: incident.title,
        severity: incident.severity,
        incident_type: incident.incident_type,
        affected_projects_count: scope.projects.length,
        affected_packages: scope.packages,
      },
      source: 'incident_engine',
      priority: 'critical',
    });
  } catch (_) {}

  await logSecurityEvent({
    organizationId: orgId,
    action: 'incident_declared',
    targetType: 'security_incident',
    targetId: incident.id,
    metadata: {
      severity: incident.severity,
      trigger_type: playbook.trigger_type,
      auto_execute: playbook.auto_execute,
    },
    severity: 'critical',
  });

  if (playbook.auto_execute) {
    await autoStartIncident(incident, taskId, orgId);
  }

  await supabase
    .from('incident_playbooks')
    .update({
      usage_count: (playbook.usage_count || 0) + 1,
      last_used_at: new Date().toISOString(),
    })
    .eq('id', playbook.id);

  return incident.id;
}

export async function addTimelineEvent(
  incidentId: string,
  phase: string,
  eventType: string,
  description: string,
  actor?: string,
  metadata?: any,
  durationMs?: number,
): Promise<void> {
  await supabase.from('incident_timeline').insert({
    incident_id: incidentId,
    phase,
    event_type: eventType,
    description,
    actor: actor || 'system',
    metadata: metadata || null,
    duration_ms: durationMs || null,
  });
}

export async function advanceIncidentPhase(
  incidentId: string,
  nextPhase: string,
  previousPhase: string,
): Promise<void> {
  const updates: Record<string, any> = {
    current_phase: nextPhase,
    status: PHASE_STATUS_MAP[nextPhase] || 'active',
  };

  const now = new Date();

  if (previousPhase === 'contain') {
    const { data: incident } = await supabase
      .from('security_incidents')
      .select('declared_at')
      .eq('id', incidentId)
      .single();
    if (incident?.declared_at) {
      updates.contained_at = now.toISOString();
      updates.time_to_contain_ms = now.getTime() - new Date(incident.declared_at).getTime();
    }

    try {
      const { data: inc } = await supabase
        .from('security_incidents')
        .select('organization_id, title, severity')
        .eq('id', incidentId)
        .single();
      if (inc) {
        const { emitEvent } = require('./event-bus');
        await emitEvent({
          type: 'incident_contained',
          organizationId: inc.organization_id,
          payload: { incident_id: incidentId, title: inc.title, severity: inc.severity },
          source: 'incident_engine',
          priority: 'high',
        });
      }
    } catch (_) {}
  }

  if (previousPhase === 'remediate' || nextPhase === 'verify') {
    const { data: incident } = await supabase
      .from('security_incidents')
      .select('declared_at')
      .eq('id', incidentId)
      .single();
    if (incident?.declared_at) {
      updates.remediated_at = now.toISOString();
      updates.time_to_remediate_ms = now.getTime() - new Date(incident.declared_at).getTime();
    }
  }

  await supabase.from('security_incidents').update(updates).eq('id', incidentId);

  await addTimelineEvent(
    incidentId,
    nextPhase,
    'phase_started',
    `Phase "${nextPhase}" started (previous: "${previousPhase}")`,
    'system',
  );
}

export async function resolveIncident(incidentId: string): Promise<void> {
  const now = new Date();
  const { data: incident } = await supabase
    .from('security_incidents')
    .select('declared_at, organization_id, title, severity')
    .eq('id', incidentId)
    .single();

  const totalMs = incident?.declared_at
    ? now.getTime() - new Date(incident.declared_at).getTime()
    : null;

  await supabase
    .from('security_incidents')
    .update({
      status: 'resolved',
      current_phase: 'report',
      resolved_at: now.toISOString(),
      total_duration_ms: totalMs,
    })
    .eq('id', incidentId);

  await addTimelineEvent(
    incidentId,
    'report',
    'phase_started',
    'Incident resolved. Generating post-mortem.',
    'system',
  );

  try {
    const { generatePostMortem } = await import('./incident-postmortem');
    await generatePostMortem(incidentId);
  } catch (err: any) {
    console.error('[incident-engine] Post-mortem generation failed:', err.message);
  }

  if (incident) {
    try {
      const { emitEvent } = require('./event-bus');
      await emitEvent({
        type: 'incident_resolved',
        organizationId: incident.organization_id,
        payload: {
          incident_id: incidentId,
          title: incident.title,
          severity: incident.severity,
          total_duration_ms: totalMs,
        },
        source: 'incident_engine',
        priority: 'normal',
      });
    } catch (_) {}
  }
}

export async function requestPhaseApproval(
  incidentId: string,
  phase: string,
  taskId: string,
): Promise<void> {
  await supabase
    .from('aegis_tasks')
    .update({ status: 'awaiting_approval' })
    .eq('id', taskId);

  await addTimelineEvent(
    incidentId,
    phase,
    'approval_requested',
    `Phase "${phase}" requires approval before proceeding`,
    'system',
  );
}

export async function scheduleEscalation(
  incidentId: string,
  phase: string,
  timeoutMinutes: number,
): Promise<void> {
  const url = `${getBackendUrl()}/api/internal/incidents/escalate`;
  try {
    await publishToQStash(url, { incidentId, phase }, timeoutMinutes * 60);
  } catch (err: any) {
    console.error('[incident-engine] Failed to schedule escalation:', err.message);
  }
}

export function resolveVariables(
  params: Record<string, any>,
  incident: any,
): Record<string, any> {
  const context: Record<string, any> = {
    incident_id: incident.id,
    organization_id: incident.organization_id,
    affected_projects: incident.affected_projects || [],
    affected_packages: incident.affected_packages || [],
    affected_cves: incident.affected_cves || [],
    severity: incident.severity,
    incident_type: incident.incident_type,
    title: incident.title,
  };
  return JSON.parse(
    JSON.stringify(params).replace(/"\$(\w+)"/g, (_, key) =>
      context[key] !== undefined ? JSON.stringify(context[key]) : `"$${key}"`,
    ),
  );
}

export function evaluateCondition(condition: string, incident: any): boolean {
  const arrayLengthMatch = condition.match(
    /^\$(\w+)\.length\s*(>|<|>=|<=|===|==)\s*(\d+)$/,
  );
  if (arrayLengthMatch) {
    const [, field, op, val] = arrayLengthMatch;
    const arr = (incident as any)[field];
    if (!Array.isArray(arr)) return true;
    const num = parseInt(val, 10);
    switch (op) {
      case '>': return arr.length > num;
      case '<': return arr.length < num;
      case '>=': return arr.length >= num;
      case '<=': return arr.length <= num;
      case '===': case '==': return arr.length === num;
    }
  }

  const stringMatch = condition.match(/^\$(\w+)\s*===\s*'([^']+)'$/);
  if (stringMatch) {
    const [, field, val] = stringMatch;
    return (incident as any)[field] === val;
  }

  return true;
}

// ─── Phase-transition hook for aegis-task-step ───────────────────────────────

export async function handleIncidentStepCompletion(
  taskId: string,
  completedStep: any,
  result: { hasMore: boolean; taskCompleted: boolean },
): Promise<boolean> {
  const incidentId = completedStep.tool_params?.__incident_id;
  if (!incidentId) return false;

  if (result.taskCompleted) {
    await resolveIncident(incidentId);
    return true;
  }

  if (!result.hasMore) return false;

  const nextStepId = await getNextPendingStep(taskId);
  if (!nextStepId) return false;

  const { data: nextStep } = await supabase
    .from('aegis_task_steps')
    .select('*')
    .eq('id', nextStepId)
    .single();
  if (!nextStep) return false;

  const currentPhase = completedStep.tool_params.__incident_phase;
  const nextPhase = nextStep.tool_params?.__incident_phase;

  if (currentPhase && nextPhase && currentPhase !== nextPhase) {
    await advanceIncidentPhase(incidentId, nextPhase, currentPhase);

    if (nextStep.tool_params.__requires_approval) {
      await requestPhaseApproval(incidentId, nextPhase, taskId);
      return true;
    }

    if (nextStep.tool_params.__timeout_minutes) {
      await scheduleEscalation(incidentId, nextPhase, nextStep.tool_params.__timeout_minutes);
    }
  }

  // Check step condition
  if (nextStep.tool_params.__condition) {
    const { data: incident } = await supabase
      .from('security_incidents')
      .select('*')
      .eq('id', incidentId)
      .single();
    if (incident && !evaluateCondition(nextStep.tool_params.__condition, incident)) {
      await supabase
        .from('aegis_task_steps')
        .update({ status: 'skipped', completed_at: new Date().toISOString() })
        .eq('id', nextStepId);
      await addTimelineEvent(incidentId, nextPhase || currentPhase, 'action_taken',
        `Step "${nextStep.title}" skipped (condition not met)`, 'aegis');
    }
  }

  await publishToQStash(
    `${getBackendUrl()}/api/internal/aegis/execute-task-step`,
    { taskId, stepId: nextStepId },
  );

  return true;
}

// ─── Internal helpers ────────────────────────────────────────────────────────

async function createIncidentTask(
  orgId: string,
  incident: any,
  playbook: IncidentPlaybook,
): Promise<string> {
  const phases: PlaybookPhase[] = Array.isArray(playbook.phases) ? playbook.phases : [];

  const { data: task, error } = await supabase
    .from('aegis_tasks')
    .insert({
      organization_id: orgId,
      title: `Incident Response: ${incident.title}`,
      mode: playbook.auto_execute ? 'autonomous' : 'plan',
      status: playbook.auto_execute ? 'running' : 'awaiting_approval',
      plan_json: phases,
      total_steps: phases.reduce((sum, p) => sum + (p.steps?.length || 0), 0),
    })
    .select('id')
    .single();

  if (error || !task) throw error || new Error('Failed to create incident task');

  let stepNumber = 1;
  for (const phase of phases) {
    for (const step of phase.steps || []) {
      await supabase.from('aegis_task_steps').insert({
        task_id: task.id,
        step_number: stepNumber++,
        title: `[${phase.phase.toUpperCase()}] ${step.tool}`,
        tool_name: step.tool,
        tool_params: {
          ...step.params,
          __incident_id: incident.id,
          __incident_phase: phase.phase,
          __requires_approval: phase.requiresApproval,
          __on_failure: step.onFailure,
          __condition: step.condition || null,
          __timeout_minutes: phase.timeoutMinutes || null,
        },
        status: 'pending',
      });
    }
  }

  return task.id;
}

async function autoStartIncident(
  incident: any,
  taskId: string,
  orgId: string,
): Promise<void> {
  const { data: org } = await supabase
    .from('organizations')
    .select('allow_autonomous_containment')
    .eq('id', orgId)
    .single();

  if (org?.allow_autonomous_containment && incident.severity === 'critical') {
    await supabase
      .from('aegis_tasks')
      .update({ status: 'running', started_at: new Date().toISOString() })
      .eq('id', taskId);

    const firstStepId = await getNextPendingStep(taskId);
    if (firstStepId) {
      await publishToQStash(
        `${getBackendUrl()}/api/internal/aegis/execute-task-step`,
        { taskId, stepId: firstStepId },
      );
    }

    await logSecurityEvent({
      organizationId: orgId,
      action: 'incident_auto_started',
      targetType: 'security_incident',
      targetId: incident.id,
      metadata: { autonomous: true, severity: incident.severity },
      severity: 'critical',
    });
  }
}

function extractScope(event: any): {
  projects: string[];
  packages: string[];
  cves: string[];
} {
  const payload = event.payload || {};
  const projects: string[] = [];
  const packages: string[] = [];
  const cves: string[] = [];

  if (event.project_id) projects.push(event.project_id);
  if (payload.project_id && !projects.includes(payload.project_id)) {
    projects.push(payload.project_id);
  }

  const pkgName = payload.package_name || payload.dependency_name;
  if (pkgName) packages.push(pkgName);

  if (payload.osv_id) cves.push(payload.osv_id);

  return { projects, packages, cves };
}

function buildIncidentTitle(triggerType: string, event: any): string {
  const payload = event.payload || {};
  switch (triggerType) {
    case 'zero_day':
      return `Zero-Day: ${payload.osv_id || 'CVE'} in ${payload.dependency_name || payload.package_name || 'package'}`;
    case 'supply_chain':
      return `Supply Chain: ${payload.package_name || payload.dependency_name || 'package'} compromise`;
    case 'secret_exposure':
      return `Secret Exposure: ${payload.detector_type || 'credential'} detected in ${payload.project_name || 'project'}`;
    case 'compliance_breach':
      return `Compliance Breach: ${payload.project_name || 'project'}`;
    default:
      return `Security Incident: ${event.event_type}`;
  }
}

function determineSeverity(event: any): 'critical' | 'high' | 'medium' {
  const payload = event.payload || {};
  if (event.priority === 'critical') return 'critical';
  if (payload.severity === 'critical' || payload.cisa_kev) return 'critical';
  if (payload.severity === 'high' || (payload.epss_score && payload.epss_score > 0.7)) return 'high';
  if (payload.anomaly_score && payload.anomaly_score > 80) return 'high';
  if (event.event_type === 'malicious_package_detected') return 'critical';
  if (event.event_type === 'secret_exposure_verified') return 'high';
  return 'medium';
}
