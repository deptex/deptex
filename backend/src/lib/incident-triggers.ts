/**
 * Phase 17: Incident trigger system.
 *
 * Bridges Phase 9 notification events to incident creation.
 * Runs inline during notification dispatch — when an event fires,
 * also check if it matches any active playbook auto-triggers.
 */

import { supabase } from '../lib/supabase';

const TRIGGERABLE_EVENTS = [
  'vulnerability_discovered',
  'supply_chain_anomaly',
  'malicious_package_detected',
  'secret_exposure_verified',
  'sla_breached',
  'policy_violation',
] as const;

const EVENT_TO_TRIGGER_TYPE: Record<string, string> = {
  vulnerability_discovered: 'zero_day',
  supply_chain_anomaly: 'supply_chain',
  malicious_package_detected: 'supply_chain',
  secret_exposure_verified: 'secret_exposure',
  sla_breached: 'compliance_breach',
  policy_violation: 'compliance_breach',
};

const MAX_INCIDENTS_PER_HOUR = 5;

export async function checkIncidentTriggers(event: any): Promise<void> {
  if (!TRIGGERABLE_EVENTS.includes(event.event_type)) return;

  try {
    const triggerType = EVENT_TO_TRIGGER_TYPE[event.event_type];
    if (!triggerType) return;

    const { data: playbooks } = await supabase
      .from('incident_playbooks')
      .select('*')
      .eq('organization_id', event.organization_id)
      .eq('enabled', true)
      .eq('auto_execute', true);

    if (!playbooks?.length) return;

    for (const playbook of playbooks) {
      if (playbook.trigger_type !== triggerType && playbook.trigger_type !== 'custom') continue;
      if (!matchesTriggerCriteria(playbook.trigger_criteria, event)) continue;

      const dedupKey = buildDedupKey(triggerType, event);
      const { data: existing } = await supabase
        .from('security_incidents')
        .select('id')
        .eq('organization_id', event.organization_id)
        .eq('dedup_key', dedupKey)
        .not('status', 'in', '("resolved","closed","aborted")')
        .maybeSingle();

      if (existing) {
        await expandIncidentScope(existing.id, event);
        continue;
      }

      const { count } = await supabase
        .from('security_incidents')
        .select('id', { count: 'exact', head: true })
        .eq('organization_id', event.organization_id)
        .gte('declared_at', new Date(Date.now() - 3600_000).toISOString());
      if ((count || 0) >= MAX_INCIDENTS_PER_HOUR) continue;

      const { declareIncident } = await import('./incident-engine');
      await declareIncident(event.organization_id, playbook, event);
    }
  } catch (err: any) {
    console.error('[incident-triggers] Error checking triggers:', err.message);
  }
}

export function matchesTriggerCriteria(criteria: any, event: any): boolean {
  if (!criteria) return true;
  for (const [key, condition] of Object.entries(criteria)) {
    const eventValue = event.payload?.[key];
    if (typeof condition === 'object' && condition !== null) {
      const cond = condition as Record<string, any>;
      if ('$gt' in cond && !(eventValue > cond.$gt)) return false;
      if ('$gte' in cond && !(eventValue >= cond.$gte)) return false;
      if ('$lt' in cond && !(eventValue < cond.$lt)) return false;
      if ('$in' in cond && !cond.$in.includes(eventValue)) return false;
    } else {
      if (eventValue !== condition) return false;
    }
  }
  return true;
}

export function buildDedupKey(triggerType: string, event: any): string {
  const payload = event.payload || {};
  switch (triggerType) {
    case 'zero_day':
      return `zero_day:${payload.osv_id || 'unknown'}`;
    case 'supply_chain':
      return `supply_chain:${payload.package_name || payload.dependency_name || 'unknown'}`;
    case 'secret_exposure': {
      const filePath = payload.file_path || payload.file || 'unknown';
      const hash = require('crypto').createHash('sha256').update(filePath).digest('hex').slice(0, 16);
      return `secret_exposure:${payload.detector_type || 'unknown'}:${hash}`;
    }
    case 'compliance_breach':
      return `compliance_breach:${event.project_id || 'unknown'}`;
    default:
      return `custom:${event.event_type}:${Date.now()}`;
  }
}

async function expandIncidentScope(incidentId: string, event: any): Promise<void> {
  const { data: incident } = await supabase
    .from('security_incidents')
    .select('*')
    .eq('id', incidentId)
    .single();
  if (!incident) return;

  const updates: Record<string, any> = {};
  const payload = event.payload || {};

  if (
    event.project_id &&
    !incident.affected_projects?.includes(event.project_id)
  ) {
    updates.affected_projects = [...(incident.affected_projects || []), event.project_id];
  }
  const pkgName = payload.package_name || payload.dependency_name;
  if (pkgName && !incident.affected_packages?.includes(pkgName)) {
    updates.affected_packages = [...(incident.affected_packages || []), pkgName];
  }
  if (payload.osv_id && !incident.affected_cves?.includes(payload.osv_id)) {
    updates.affected_cves = [...(incident.affected_cves || []), payload.osv_id];
  }

  if (Object.keys(updates).length > 0) {
    await supabase.from('security_incidents').update(updates).eq('id', incidentId);
    const { addTimelineEvent } = await import('./incident-engine');
    await addTimelineEvent(
      incidentId,
      incident.current_phase,
      'scope_expanded',
      `Scope expanded: new affected ${Object.keys(updates).join(', ')} added`,
      'system',
    );
  }
}
