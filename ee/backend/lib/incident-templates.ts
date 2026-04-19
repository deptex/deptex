/**
 * Phase 17: Pre-built incident response playbook templates.
 *
 * Four templates seeded as is_template=true when org enables incident response.
 * Orgs can clone and customize these.
 */

import { supabase } from '../../../backend/src/lib/supabase';

interface PlaybookTemplate {
  name: string;
  description: string;
  trigger_type: string;
  trigger_criteria: Record<string, any> | null;
  phases: PlaybookPhase[];
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

const ZERO_DAY_TEMPLATE: PlaybookTemplate = {
  name: 'Zero-Day CVE Response',
  description: 'Respond to critical zero-day vulnerabilities with CISA KEV or high EPSS score. Contains, assesses blast radius, notifies stakeholders, and orchestrates remediation.',
  trigger_type: 'zero_day',
  trigger_criteria: { severity: 'critical' },
  phases: [
    {
      phase: 'contain',
      name: 'Containment',
      requiresApproval: true,
      timeoutMinutes: 30,
      steps: [
        {
          id: 'zd-contain-1',
          tool: 'emergencyLockdownPackage',
          params: { packageName: '$affected_packages', organizationId: '$organization_id' },
          onFailure: 'pause',
        },
      ],
    },
    {
      phase: 'assess',
      name: 'Assessment',
      requiresApproval: false,
      timeoutMinutes: 60,
      steps: [
        {
          id: 'zd-assess-1',
          tool: 'assessBlastRadius',
          params: { packageName: '$affected_packages', organizationId: '$organization_id' },
          onFailure: 'continue',
        },
        {
          id: 'zd-assess-2',
          tool: 'getSLAStatus',
          params: { organizationId: '$organization_id' },
          condition: '$affected_cves.length > 0',
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'communicate',
      name: 'Communication',
      requiresApproval: false,
      steps: [
        {
          id: 'zd-comm-1',
          tool: 'createSlackMessage',
          params: {
            channel: '#security',
            message: '🚨 Zero-Day Incident: $title\nSeverity: $severity\nAffected packages: $affected_packages\nAffected projects: $affected_projects',
          },
          onFailure: 'continue',
        },
        {
          id: 'zd-comm-2',
          tool: 'sendEmail',
          params: {
            subject: '[SECURITY] Zero-Day: $title',
            body: 'A critical zero-day vulnerability has been detected. Incident response is in progress.',
            recipients: 'admins',
          },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'remediate',
      name: 'Remediation',
      requiresApproval: true,
      timeoutMinutes: 240,
      steps: [
        {
          id: 'zd-rem-1',
          tool: 'createSecuritySprint',
          params: { organizationId: '$organization_id', mode: 'auto' },
          onFailure: 'pause',
        },
      ],
    },
    {
      phase: 'verify',
      name: 'Verification',
      requiresApproval: false,
      timeoutMinutes: 120,
      steps: [
        {
          id: 'zd-ver-1',
          tool: 'triggerExtraction',
          params: { projectIds: '$affected_projects' },
          condition: '$affected_projects.length > 0',
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'report',
      name: 'Reporting',
      requiresApproval: false,
      steps: [
        {
          id: 'zd-rep-1',
          tool: 'generateSecurityReport',
          params: { organizationId: '$organization_id', reportType: 'incident' },
          onFailure: 'continue',
        },
      ],
    },
  ],
};

const SUPPLY_CHAIN_TEMPLATE: PlaybookTemplate = {
  name: 'Supply Chain Compromise',
  description: 'Respond to supply chain attacks: Watchtower anomaly detection, malicious package indicators. Blocks compromised versions and orchestrates safe rollback.',
  trigger_type: 'supply_chain',
  trigger_criteria: null,
  phases: [
    {
      phase: 'contain',
      name: 'Containment',
      requiresApproval: true,
      timeoutMinutes: 15,
      steps: [
        {
          id: 'sc-contain-1',
          tool: 'emergencyLockdownPackage',
          params: { packageName: '$affected_packages', organizationId: '$organization_id' },
          onFailure: 'pause',
        },
      ],
    },
    {
      phase: 'assess',
      name: 'Assessment',
      requiresApproval: false,
      timeoutMinutes: 60,
      steps: [
        {
          id: 'sc-assess-1',
          tool: 'assessBlastRadius',
          params: { packageName: '$affected_packages', organizationId: '$organization_id' },
          onFailure: 'continue',
        },
        {
          id: 'sc-assess-2',
          tool: 'getWatchtowerSummary',
          params: { packageName: '$affected_packages' },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'communicate',
      name: 'Communication',
      requiresApproval: false,
      steps: [
        {
          id: 'sc-comm-1',
          tool: 'createSlackMessage',
          params: {
            channel: '#security',
            message: '🔗 Supply Chain Incident: $title\nSeverity: $severity\nPackages: $affected_packages',
          },
          onFailure: 'continue',
        },
        {
          id: 'sc-comm-2',
          tool: 'sendEmail',
          params: {
            subject: '[SECURITY] Supply Chain: $title',
            body: 'A supply chain compromise has been detected. Containment measures are in effect.',
            recipients: 'admins',
          },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'remediate',
      name: 'Remediation',
      requiresApproval: true,
      timeoutMinutes: 240,
      steps: [
        {
          id: 'sc-rem-1',
          tool: 'createSecuritySprint',
          params: { organizationId: '$organization_id', mode: 'auto' },
          onFailure: 'pause',
        },
      ],
    },
    {
      phase: 'verify',
      name: 'Verification',
      requiresApproval: false,
      timeoutMinutes: 120,
      steps: [
        {
          id: 'sc-ver-1',
          tool: 'triggerExtraction',
          params: { projectIds: '$affected_projects' },
          condition: '$affected_projects.length > 0',
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'report',
      name: 'Reporting',
      requiresApproval: false,
      steps: [
        {
          id: 'sc-rep-1',
          tool: 'generateSecurityReport',
          params: { organizationId: '$organization_id', reportType: 'incident' },
          onFailure: 'continue',
        },
      ],
    },
  ],
};

const SECRET_EXPOSURE_TEMPLATE: PlaybookTemplate = {
  name: 'Secret Exposure Response',
  description: 'Respond to verified secret/credential exposure detected by TruffleHog. Alerts security team, remediates hardcoded values, and verifies cleanup.',
  trigger_type: 'secret_exposure',
  trigger_criteria: null,
  phases: [
    {
      phase: 'contain',
      name: 'Alert & Contain',
      requiresApproval: false,
      timeoutMinutes: 30,
      steps: [
        {
          id: 'se-contain-1',
          tool: 'createSlackMessage',
          params: {
            channel: '#security',
            message: '🔑 Secret Exposure Detected: $title\nRotate credentials immediately.',
          },
          onFailure: 'continue',
        },
        {
          id: 'se-contain-2',
          tool: 'sendEmail',
          params: {
            subject: '[URGENT] Secret Exposure: $title',
            body: 'A verified secret has been detected. Rotate affected credentials immediately.',
            recipients: 'admins',
          },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'assess',
      name: 'Assessment',
      requiresApproval: false,
      timeoutMinutes: 60,
      steps: [
        {
          id: 'se-assess-1',
          tool: 'getSecretFindings',
          params: { projectId: '$affected_projects' },
          condition: '$affected_projects.length > 0',
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'communicate',
      name: 'Communication',
      requiresApproval: false,
      steps: [
        {
          id: 'se-comm-1',
          tool: 'createSlackMessage',
          params: {
            channel: '#security',
            message: 'Secret exposure assessment complete for $title. Check incident timeline for details.',
          },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'remediate',
      name: 'Remediation',
      requiresApproval: true,
      timeoutMinutes: 120,
      steps: [
        {
          id: 'se-rem-1',
          tool: 'triggerFix',
          params: {
            fixType: 'secret',
            strategy: 'remediate_secret',
            projectId: '$affected_projects',
          },
          condition: '$affected_projects.length > 0',
          onFailure: 'pause',
        },
      ],
    },
    {
      phase: 'verify',
      name: 'Verification',
      requiresApproval: false,
      timeoutMinutes: 120,
      steps: [
        {
          id: 'se-ver-1',
          tool: 'triggerExtraction',
          params: { projectIds: '$affected_projects' },
          condition: '$affected_projects.length > 0',
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'report',
      name: 'Reporting',
      requiresApproval: false,
      steps: [
        {
          id: 'se-rep-1',
          tool: 'generateSecurityReport',
          params: { organizationId: '$organization_id', reportType: 'incident' },
          onFailure: 'continue',
        },
      ],
    },
  ],
};

const COMPLIANCE_BREACH_TEMPLATE: PlaybookTemplate = {
  name: 'Compliance Breach Response',
  description: 'Respond to policy violations and SLA breaches. Identifies scope of non-compliance, notifies compliance team, and generates exception requests.',
  trigger_type: 'compliance_breach',
  trigger_criteria: null,
  phases: [
    {
      phase: 'contain',
      name: 'Scope Identification',
      requiresApproval: false,
      timeoutMinutes: 30,
      steps: [
        {
          id: 'cb-contain-1',
          tool: 'getComplianceStatus',
          params: { organizationId: '$organization_id' },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'assess',
      name: 'Impact Analysis',
      requiresApproval: false,
      timeoutMinutes: 60,
      steps: [
        {
          id: 'cb-assess-1',
          tool: 'evaluatePolicy',
          params: { organizationId: '$organization_id' },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'communicate',
      name: 'Notification',
      requiresApproval: false,
      steps: [
        {
          id: 'cb-comm-1',
          tool: 'createSlackMessage',
          params: {
            channel: '#compliance',
            message: '📋 Compliance Breach: $title\nSeverity: $severity',
          },
          onFailure: 'continue',
        },
        {
          id: 'cb-comm-2',
          tool: 'sendEmail',
          params: {
            subject: '[COMPLIANCE] Breach: $title',
            body: 'A compliance breach has been detected. Review the incident for details.',
            recipients: 'admins',
          },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'remediate',
      name: 'Remediation',
      requiresApproval: false,
      timeoutMinutes: 240,
      steps: [
        {
          id: 'cb-rem-1',
          tool: 'listPolicyExceptions',
          params: { organizationId: '$organization_id' },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'verify',
      name: 'Verification',
      requiresApproval: false,
      timeoutMinutes: 120,
      steps: [
        {
          id: 'cb-ver-1',
          tool: 'evaluatePolicy',
          params: { organizationId: '$organization_id' },
          onFailure: 'continue',
        },
      ],
    },
    {
      phase: 'report',
      name: 'Reporting',
      requiresApproval: false,
      steps: [
        {
          id: 'cb-rep-1',
          tool: 'generateSecurityReport',
          params: { organizationId: '$organization_id', reportType: 'compliance_incident' },
          onFailure: 'continue',
        },
      ],
    },
  ],
};

const TEMPLATES: PlaybookTemplate[] = [
  ZERO_DAY_TEMPLATE,
  SUPPLY_CHAIN_TEMPLATE,
  SECRET_EXPOSURE_TEMPLATE,
  COMPLIANCE_BREACH_TEMPLATE,
];

export async function seedPlaybookTemplates(organizationId: string): Promise<void> {
  const { data: existing } = await supabase
    .from('incident_playbooks')
    .select('id')
    .eq('organization_id', organizationId)
    .eq('is_template', true)
    .limit(1);

  if (existing?.length) return;

  for (const template of TEMPLATES) {
    await supabase.from('incident_playbooks').insert({
      organization_id: organizationId,
      name: template.name,
      description: template.description,
      trigger_type: template.trigger_type,
      trigger_criteria: template.trigger_criteria,
      phases: template.phases,
      auto_execute: false,
      is_template: true,
      enabled: true,
    });
  }
}

export function getTemplateDefinitions(): PlaybookTemplate[] {
  return TEMPLATES;
}
