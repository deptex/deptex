/**
 * Event payload schemas for the flow builder.
 *
 * Each trigger event type lists the fields downstream nodes (IF, Filter, etc.)
 * can reference. Fields are dot-paths into the event's payload.
 *
 * Source of truth: keep in sync with backend `emitEvent()` call sites and
 * `notification-validator.ts#SAMPLE_CONTEXTS`. When a new event is added or a
 * payload shape changes, update this file.
 */

export type EventFieldType = 'string' | 'number' | 'boolean' | 'enum';

export interface EventField {
  /** Dot-path into event payload, e.g. "vulnerability.severity". */
  path: string;
  /** Human-readable label shown in the field picker. */
  label: string;
  /** Group heading shown in the picker (e.g. "Vulnerability", "Project"). */
  group: string;
  type: EventFieldType;
  /** Enum values when type === 'enum' — presented as a value picker. */
  enumValues?: readonly string[];
  /** Short helper text shown under the field. */
  hint?: string;
}

export interface EventSchema {
  eventType: string;
  fields: EventField[];
}

// ─── Reusable field groups ───────────────────────────────────────────────────

const PROJECT_FIELDS: EventField[] = [
  { path: 'project.name', label: 'Project name', group: 'Project', type: 'string' },
  { path: 'project.tier', label: 'Asset tier', group: 'Project', type: 'string'},
  { path: 'project.framework', label: 'Framework', group: 'Project', type: 'string' },
];

const DEPENDENCY_FIELDS: EventField[] = [
  { path: 'dependency.name', label: 'Dependency name', group: 'Dependency', type: 'string' },
  { path: 'dependency.version', label: 'Dependency version', group: 'Dependency', type: 'string' },
  { path: 'dependency.isDirect', label: 'Is direct dependency', group: 'Dependency', type: 'boolean' },
];

// ─── Schemas per event type ──────────────────────────────────────────────────

export const EVENT_SCHEMAS: Record<string, EventSchema> = {
  // Vulnerabilities group
  vulnerability_discovered: {
    eventType: 'vulnerability_discovered',
    fields: [
      ...PROJECT_FIELDS,
      ...DEPENDENCY_FIELDS,
      { path: 'vulnerability.osvId', label: 'OSV / GHSA ID', group: 'Vulnerability', type: 'string' },
      {
        path: 'vulnerability.severity',
        label: 'Severity',
        group: 'Vulnerability',
        type: 'enum',
        enumValues: ['critical', 'high', 'medium', 'low'] as const,
      },
      { path: 'vulnerability.cvssScore', label: 'CVSS score', group: 'Vulnerability', type: 'number'},
      { path: 'vulnerability.epssScore', label: 'EPSS score', group: 'Vulnerability', type: 'number'},
      { path: 'vulnerability.cisaKev', label: 'Is in CISA KEV', group: 'Vulnerability', type: 'boolean' },
      { path: 'vulnerability.isReachable', label: 'Is reachable', group: 'Vulnerability', type: 'boolean' },
      {
        path: 'vulnerability.reachabilityLevel',
        label: 'Reachability level',
        group: 'Vulnerability',
        type: 'enum',
        enumValues: ['confirmed', 'data_flow', 'function', 'module', 'not_reachable'] as const,
      },
      { path: 'vulnerability.depscore', label: 'Depscore', group: 'Vulnerability', type: 'number'},
    ],
  },

  malicious_package_detected: {
    eventType: 'malicious_package_detected',
    fields: [
      ...PROJECT_FIELDS,
      ...DEPENDENCY_FIELDS,
      { path: 'dependency.maliciousIndicator.source', label: 'Detection source', group: 'Malicious', type: 'string'},
      { path: 'dependency.maliciousIndicator.confidence', label: 'Detection confidence', group: 'Malicious', type: 'number'},
      { path: 'dependency.maliciousIndicator.reason', label: 'Detection reason', group: 'Malicious', type: 'string' },
    ],
  },

  new_version_available: {
    eventType: 'new_version_available',
    fields: [
      ...PROJECT_FIELDS,
      ...DEPENDENCY_FIELDS,
      { path: 'dependency.latestVersion', label: 'Latest version', group: 'Dependency', type: 'string' },
    ],
  },

  // Projects & dependencies group
  project_created: {
    eventType: 'project_created',
    fields: [
      { path: 'projectName', label: 'Project name', group: 'Project', type: 'string' },
      { path: 'teamIds', label: 'Team IDs', group: 'Project', type: 'string'},
    ],
  },

  project_deleted: {
    eventType: 'project_deleted',
    fields: [
      // project_deleted carries only organizationId + projectId in payload today.
      // The runtime will hydrate project name from the event context.
    ],
  },

  dependency_added: {
    eventType: 'dependency_added',
    fields: [
      ...PROJECT_FIELDS,
      ...DEPENDENCY_FIELDS,
      { path: 'dependency.license', label: 'License', group: 'Dependency', type: 'string'},
      { path: 'dependency.score', label: 'Dependency score', group: 'Dependency', type: 'number'},
    ],
  },

  dependency_updated: {
    eventType: 'dependency_updated',
    fields: [
      ...PROJECT_FIELDS,
      ...DEPENDENCY_FIELDS,
      { path: 'dependency.previousVersion', label: 'Previous version', group: 'Dependency', type: 'string' },
    ],
  },

  // Policies & status group
  status_changed: {
    eventType: 'status_changed',
    fields: [
      ...PROJECT_FIELDS,
      { path: 'previous.status', label: 'Previous status', group: 'Status', type: 'string' },
    ],
  },

  policy_violation: {
    eventType: 'policy_violation',
    fields: [
      ...PROJECT_FIELDS,
      { path: 'policy.codeType', label: 'Policy type', group: 'Policy', type: 'enum', enumValues: ['packagePolicy', 'projectStatus', 'pullRequestCheck'] as const },
      { path: 'violation.message', label: 'Violation message', group: 'Policy', type: 'string' },
    ],
  },

  policy_code_updated: {
    eventType: 'policy_code_updated',
    fields: [
      {
        path: 'codeType',
        label: 'Policy type',
        group: 'Policy',
        type: 'enum',
        enumValues: ['packagePolicy', 'projectStatus', 'pullRequestCheck'] as const,
      },
      { path: 'updatedBy', label: 'Updated by (user ID)', group: 'Policy', type: 'string' },
    ],
  },

  security_analysis_failure: {
    eventType: 'security_analysis_failure',
    fields: [
      ...PROJECT_FIELDS,
      { path: 'stage', label: 'Failed stage', group: 'Analysis', type: 'string'},
      { path: 'error', label: 'Error message', group: 'Analysis', type: 'string' },
    ],
  },

  // Incidents group — all incidents share the same payload shape
  incident_declared: {
    eventType: 'incident_declared',
    fields: incidentFields(),
  },
  incident_auto_started: {
    eventType: 'incident_auto_started',
    fields: incidentFields(),
  },
  incident_escalated: {
    eventType: 'incident_escalated',
    fields: incidentFields(),
  },
  incident_contained: {
    eventType: 'incident_contained',
    fields: incidentFields(),
  },
  incident_resolved: {
    eventType: 'incident_resolved',
    fields: incidentFields(),
  },
  incident_aborted: {
    eventType: 'incident_aborted',
    fields: incidentFields(),
  },

  // Organization group
  member_invited: {
    eventType: 'member_invited',
    fields: [
      { path: 'email', label: 'Invited email', group: 'Member', type: 'string' },
      { path: 'role', label: 'Role', group: 'Member', type: 'string' },
      { path: 'teamIds', label: 'Team IDs', group: 'Member', type: 'string'},
    ],
  },

  member_removed: {
    eventType: 'member_removed',
    fields: [
      { path: 'removedEmail', label: 'Removed email', group: 'Member', type: 'string' },
      { path: 'removedUserId', label: 'Removed user ID', group: 'Member', type: 'string' },
      { path: 'selfRemoval', label: 'Was self-removal', group: 'Member', type: 'boolean' },
    ],
  },

  integration_connected: {
    eventType: 'integration_connected',
    fields: [
      {
        path: 'provider',
        label: 'Provider',
        group: 'Integration',
        type: 'enum',
        enumValues: ['github', 'gitlab', 'bitbucket', 'slack', 'discord', 'jira', 'linear', 'asana', 'pagerduty', 'email', 'webhook'] as const,
      },
      { path: 'displayName', label: 'Display name', group: 'Integration', type: 'string' },
    ],
  },

  integration_disconnected: {
    eventType: 'integration_disconnected',
    fields: [
      {
        path: 'provider',
        label: 'Provider',
        group: 'Integration',
        type: 'enum',
        enumValues: ['github', 'gitlab', 'bitbucket', 'slack', 'discord', 'jira', 'linear', 'asana', 'pagerduty', 'email', 'webhook'] as const,
      },
      { path: 'displayName', label: 'Display name', group: 'Integration', type: 'string' },
    ],
  },
};

function incidentFields(): EventField[] {
  return [
    { path: 'incidentId', label: 'Incident ID', group: 'Incident', type: 'string' },
    {
      path: 'severity',
      label: 'Severity',
      group: 'Incident',
      type: 'enum',
      enumValues: ['critical', 'high', 'medium', 'low'] as const,
    },
    { path: 'title', label: 'Title', group: 'Incident', type: 'string' },
    ...PROJECT_FIELDS,
  ];
}

// ─── Lookup helpers ──────────────────────────────────────────────────────────

export function getEventSchema(eventType: string | null | undefined): EventSchema | null {
  if (!eventType) return null;
  return EVENT_SCHEMAS[eventType] ?? null;
}

/** Group fields by `group` preserving first-seen order. */
export function groupEventFields(fields: EventField[]): Array<{ group: string; fields: EventField[] }> {
  const order: string[] = [];
  const byGroup = new Map<string, EventField[]>();
  for (const f of fields) {
    if (!byGroup.has(f.group)) {
      byGroup.set(f.group, []);
      order.push(f.group);
    }
    byGroup.get(f.group)!.push(f);
  }
  return order.map((g) => ({ group: g, fields: byGroup.get(g)! }));
}
