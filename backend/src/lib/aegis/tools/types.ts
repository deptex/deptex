export type ToolCategory =
  | 'org_management'
  | 'project_ops'
  | 'security_ops'
  | 'policy'
  | 'compliance'
  | 'intelligence'
  | 'reporting'
  | 'external'
  | 'memory'
  | 'automation';

export type PermissionLevel = 'safe' | 'moderate' | 'dangerous';

export interface AegisToolMeta {
  category: ToolCategory;
  permissionLevel: PermissionLevel;
  requiredRbacPermissions: string[];
}

export interface ToolContext {
  organizationId: string;
  userId: string;
  projectId?: string;
  threadId?: string;
  taskId?: string;
  operatingMode: 'readonly' | 'propose' | 'autopilot';
}

export interface AegisToolDef {
  meta: AegisToolMeta;
  tool: any;
}

export const TOOL_PROFILES = {
  default: [
    'listProjects', 'getProjectSummary', 'getProjectDependencies', 'getProjectVulnerabilities',
    'getDependencyGraph', 'getProjectSecurityPosture', 'getVulnerabilityDetail',
    'getFixStatus', 'getComplianceStatus', 'getSLAStatus', 'getSLAReport',
    'searchPackages', 'getPackageReputation',
    'storeMemory', 'queryMemory', 'listMemories',
    'generateSecurityReport', 'generateComplianceReport', 'generateExecutiveSummary', 'getROIMetrics', 'getSecurityMetrics',
    'listTeams', 'listMembers',
  ],
  security: [
    'suppressVulnerability', 'acceptRisk', 'revertSuppression', 'triggerFix',
    'createSecuritySprint', 'getSprintStatus', 'assessBlastRadius',
    'emergencyLockdownPackage', 'getReachabilityFlows', 'analyzeUpgradePath',
    'getSLAStatus',
    'declareIncident', 'getIncidentStatus', 'listActiveIncidents',
  ],
  policy: [
    'listPolicies', 'getPolicy', 'createPolicy', 'updatePolicy', 'deletePolicy',
    'testPolicyDryRun', 'generatePolicyFromDescription',
  ],
  intelligence: [
    'getPackageReputation', 'analyzeUpgradePath', 'getEPSSTrends', 'checkCISAKEV',
    'searchPackages', 'analyzeNewDependency',
  ],
  external: [
    'sendSlackMessage', 'sendEmail', 'createJiraTicket', 'createLinearTicket',
    'postPRComment', 'sendWebhook',
  ],
  admin: [
    'createTeam', 'updateTeam', 'deleteTeam', 'inviteMember', 'removeMember',
    'updateMemberRole', 'triggerExtraction',
    'createScheduledJob', 'updateScheduledJob', 'deleteScheduledJob',
  ],
  compliance: [
    'getComplianceStatus', 'generateSBOM', 'generateVEX', 'generateLicenseNotice',
    'generateAuditPackage',
  ],
} as const;
