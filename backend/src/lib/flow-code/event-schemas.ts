/**
 * Backend mirror of `frontend/src/lib/flow-event-schemas.ts`.
 *
 * Used for sample-context conformance testing and for the save-time validator
 * to know which fields each event type exposes. Kept lean (path + type only —
 * no labels, groups, or hints) since backend doesn't render the field picker.
 *
 * **Drift policy:** when a new event type lands, update both this file and the
 * frontend mirror. The conformance test in this folder will fail until both
 * have a sample. A shared package is on the roadmap once a third consumer
 * appears.
 */

export type EventFieldType = 'string' | 'number' | 'boolean' | 'enum';

export interface EventFieldSpec {
  path: string;
  type: EventFieldType;
  enumValues?: readonly string[];
}

export interface EventSchemaSpec {
  eventType: string;
  fields: EventFieldSpec[];
}

const PROJECT: EventFieldSpec[] = [
  { path: 'project.name', type: 'string' },
  { path: 'project.tier', type: 'string' },
  { path: 'project.framework', type: 'string' },
];

const DEPENDENCY: EventFieldSpec[] = [
  { path: 'dependency.name', type: 'string' },
  { path: 'dependency.version', type: 'string' },
  { path: 'dependency.isDirect', type: 'boolean' },
];

const SEVERITY = ['critical', 'high', 'medium', 'low'] as const;
const REACHABILITY = ['confirmed', 'data_flow', 'function', 'module', 'not_reachable'] as const;
const POLICY_CODE_TYPE = ['packagePolicy', 'projectStatus', 'pullRequestCheck'] as const;
const PROVIDER = [
  'github', 'gitlab', 'bitbucket', 'slack', 'discord', 'jira', 'linear',
  'asana', 'pagerduty', 'email', 'webhook',
] as const;

function incident(): EventFieldSpec[] {
  return [
    { path: 'incidentId', type: 'string' },
    { path: 'severity', type: 'enum', enumValues: SEVERITY },
    { path: 'title', type: 'string' },
    ...PROJECT,
  ];
}

export const EVENT_SCHEMAS: Record<string, EventSchemaSpec> = {
  vulnerability_discovered: {
    eventType: 'vulnerability_discovered',
    fields: [
      ...PROJECT,
      ...DEPENDENCY,
      { path: 'vulnerability.osvId', type: 'string' },
      { path: 'vulnerability.severity', type: 'enum', enumValues: SEVERITY },
      { path: 'vulnerability.cvssScore', type: 'number' },
      { path: 'vulnerability.epssScore', type: 'number' },
      { path: 'vulnerability.cisaKev', type: 'boolean' },
      { path: 'vulnerability.isReachable', type: 'boolean' },
      { path: 'vulnerability.reachabilityLevel', type: 'enum', enumValues: REACHABILITY },
      { path: 'vulnerability.depscore', type: 'number' },
    ],
  },
  malicious_package_detected: {
    eventType: 'malicious_package_detected',
    fields: [
      ...PROJECT,
      ...DEPENDENCY,
      { path: 'dependency.maliciousIndicator.source', type: 'string' },
      { path: 'dependency.maliciousIndicator.confidence', type: 'number' },
      { path: 'dependency.maliciousIndicator.reason', type: 'string' },
    ],
  },
  new_version_available: {
    eventType: 'new_version_available',
    fields: [
      ...PROJECT,
      ...DEPENDENCY,
      { path: 'dependency.latestVersion', type: 'string' },
    ],
  },
  project_created: {
    eventType: 'project_created',
    fields: [
      { path: 'projectName', type: 'string' },
      { path: 'teamIds', type: 'string' },
    ],
  },
  project_deleted: {
    eventType: 'project_deleted',
    fields: [],
  },
  dependency_added: {
    eventType: 'dependency_added',
    fields: [
      ...PROJECT,
      ...DEPENDENCY,
      { path: 'dependency.license', type: 'string' },
      { path: 'dependency.score', type: 'number' },
    ],
  },
  dependency_updated: {
    eventType: 'dependency_updated',
    fields: [
      ...PROJECT,
      ...DEPENDENCY,
      { path: 'dependency.previousVersion', type: 'string' },
    ],
  },
  status_changed: {
    eventType: 'status_changed',
    fields: [
      ...PROJECT,
      { path: 'previous.status', type: 'string' },
    ],
  },
  policy_violation: {
    eventType: 'policy_violation',
    fields: [
      ...PROJECT,
      { path: 'policy.codeType', type: 'enum', enumValues: POLICY_CODE_TYPE },
      { path: 'violation.message', type: 'string' },
    ],
  },
  policy_code_updated: {
    eventType: 'policy_code_updated',
    fields: [
      { path: 'codeType', type: 'enum', enumValues: POLICY_CODE_TYPE },
      { path: 'updatedBy', type: 'string' },
    ],
  },
  security_analysis_failure: {
    eventType: 'security_analysis_failure',
    fields: [
      ...PROJECT,
      { path: 'stage', type: 'string' },
      { path: 'error', type: 'string' },
    ],
  },
  incident_declared: { eventType: 'incident_declared', fields: incident() },
  incident_auto_started: { eventType: 'incident_auto_started', fields: incident() },
  incident_escalated: { eventType: 'incident_escalated', fields: incident() },
  incident_contained: { eventType: 'incident_contained', fields: incident() },
  incident_resolved: { eventType: 'incident_resolved', fields: incident() },
  incident_aborted: { eventType: 'incident_aborted', fields: incident() },
  member_invited: {
    eventType: 'member_invited',
    fields: [
      { path: 'email', type: 'string' },
      { path: 'role', type: 'string' },
      { path: 'teamIds', type: 'string' },
    ],
  },
  member_removed: {
    eventType: 'member_removed',
    fields: [
      { path: 'removedEmail', type: 'string' },
      { path: 'removedUserId', type: 'string' },
      { path: 'selfRemoval', type: 'boolean' },
    ],
  },
  integration_connected: {
    eventType: 'integration_connected',
    fields: [
      { path: 'provider', type: 'enum', enumValues: PROVIDER },
      { path: 'displayName', type: 'string' },
    ],
  },
  integration_disconnected: {
    eventType: 'integration_disconnected',
    fields: [
      { path: 'provider', type: 'enum', enumValues: PROVIDER },
      { path: 'displayName', type: 'string' },
    ],
  },
};

export const EVENT_TYPES: readonly string[] = Object.keys(EVENT_SCHEMAS);
