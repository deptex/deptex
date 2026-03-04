/**
 * Phase 17: Aegis incident response tools.
 * Registers declareIncident, getIncidentStatus, listActiveIncidents.
 */

// @ts-nocheck
import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../lib/supabase';

// 1. declareIncident
registerAegisTool(
  'declareIncident',
  {
    category: 'security_ops',
    permissionLevel: 'dangerous',
    requiredRbacPermissions: ['manage_incidents'],
  },
  tool({
    description:
      'Manually declare a security incident and optionally start a response playbook. Use for zero-day CVEs, supply chain compromises, secret exposures, or compliance breaches.',
    parameters: z.object({
      title: z.string().describe('Short incident title'),
      severity: z.enum(['critical', 'high', 'medium']),
      incidentType: z.enum([
        'zero_day',
        'supply_chain',
        'secret_exposure',
        'compliance_breach',
        'custom',
      ]),
      affectedPackages: z
        .array(z.string())
        .optional()
        .describe('Package names affected'),
      playbookId: z
        .string()
        .uuid()
        .optional()
        .describe('Optional playbook to execute'),
      organizationId: z.string().uuid(),
    }),
    execute: async ({
      title,
      severity,
      incidentType,
      affectedPackages,
      playbookId,
      organizationId,
    }) => {
      if (playbookId) {
        const { data: playbook } = await supabase
          .from('incident_playbooks')
          .select('*')
          .eq('id', playbookId)
          .eq('organization_id', organizationId)
          .single();

        if (playbook) {
          const { declareIncident } = require('../../incident-engine');
          const syntheticEvent = {
            event_type: 'manual_declaration',
            organization_id: organizationId,
            payload: { title, severity, incidentType, affected_packages: affectedPackages },
            source: 'aegis_chat',
          };
          const incidentId = await declareIncident(organizationId, playbook, syntheticEvent);
          return JSON.stringify({ success: true, incidentId, playbookUsed: playbook.name });
        }
      }

      const { data: incident, error } = await supabase
        .from('security_incidents')
        .insert({
          organization_id: organizationId,
          title,
          incident_type: incidentType,
          severity,
          status: 'active',
          current_phase: 'contain',
          trigger_source: 'aegis_chat',
          affected_packages: affectedPackages || [],
        })
        .select('id, title, severity, status')
        .single();

      if (error) return JSON.stringify({ error: error.message });

      await supabase.from('incident_timeline').insert({
        incident_id: incident.id,
        phase: 'contain',
        event_type: 'phase_started',
        description: `Incident declared via Aegis chat`,
        actor: 'aegis',
      });

      return JSON.stringify({ success: true, incident });
    },
  }),
);

// 2. getIncidentStatus
registerAegisTool(
  'getIncidentStatus',
  {
    category: 'security_ops',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description:
      'Get the current status of a security incident including phase, timeline, and affected scope.',
    parameters: z.object({
      incidentId: z.string().uuid(),
    }),
    execute: async ({ incidentId }) => {
      const { data: incident } = await supabase
        .from('security_incidents')
        .select('*')
        .eq('id', incidentId)
        .single();

      if (!incident) return JSON.stringify({ error: 'Incident not found' });

      const { data: timeline } = await supabase
        .from('incident_timeline')
        .select('phase, event_type, description, actor, created_at')
        .eq('incident_id', incidentId)
        .order('created_at', { ascending: true })
        .limit(50);

      return JSON.stringify({
        id: incident.id,
        title: incident.title,
        severity: incident.severity,
        status: incident.status,
        currentPhase: incident.current_phase,
        escalationLevel: incident.escalation_level,
        affectedProjects: incident.affected_projects?.length || 0,
        affectedPackages: incident.affected_packages || [],
        affectedCves: incident.affected_cves || [],
        timeToContain: incident.time_to_contain_ms,
        timeToRemediate: incident.time_to_remediate_ms,
        totalDuration: incident.total_duration_ms,
        declaredAt: incident.declared_at,
        resolvedAt: incident.resolved_at,
        timeline: timeline || [],
      });
    },
  }),
);

// 3. listActiveIncidents
registerAegisTool(
  'listActiveIncidents',
  {
    category: 'security_ops',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description:
      'List all active security incidents for the organization.',
    parameters: z.object({
      organizationId: z.string().uuid(),
    }),
    execute: async ({ organizationId }) => {
      const { data: incidents } = await supabase
        .from('security_incidents')
        .select(
          'id, title, severity, status, current_phase, incident_type, escalation_level, declared_at, affected_packages, affected_cves',
        )
        .eq('organization_id', organizationId)
        .not('status', 'in', '("resolved","closed","aborted")')
        .order('declared_at', { ascending: false })
        .limit(20);

      return JSON.stringify({
        count: incidents?.length || 0,
        incidents: (incidents || []).map((i: any) => ({
          id: i.id,
          title: i.title,
          severity: i.severity,
          status: i.status,
          currentPhase: i.current_phase,
          type: i.incident_type,
          escalationLevel: i.escalation_level,
          declaredAt: i.declared_at,
          packages: i.affected_packages || [],
          cves: i.affected_cves || [],
        })),
      });
    },
  }),
);
