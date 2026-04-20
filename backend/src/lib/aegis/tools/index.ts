import type { ToolSet } from 'ai';
import { listProjectsTool } from './list-projects';
import { getProjectSummaryTool } from './get-project-summary';
import { listProjectDependenciesTool } from './list-project-dependencies';
import { getProjectVulnerabilitiesTool } from './get-project-vulnerabilities';
import { getReachabilityFlowsTool } from './get-reachability-flows';
import { getSecurityPostureTool } from './get-security-posture';
import { getVulnerabilityDetailTool } from './get-vulnerability-detail';
import { getPackageReputationTool } from './get-package-reputation';
import { getEpssScoreTool } from './get-epss-score';
import { checkCisaKevTool } from './check-cisa-kev';
import { listPoliciesTool } from './list-policies';
import { analyzeUpgradePathTool } from './analyze-upgrade-path';

export interface AegisToolContext {
  organizationId: string;
  userId: string;
}

export function getAegisTools(ctx: AegisToolContext): ToolSet {
  return {
    list_projects: listProjectsTool(ctx),
    get_project_summary: getProjectSummaryTool(ctx),
    list_project_dependencies: listProjectDependenciesTool(ctx),
    get_project_vulnerabilities: getProjectVulnerabilitiesTool(ctx),
    get_reachability_flows: getReachabilityFlowsTool(ctx),
    get_security_posture: getSecurityPostureTool(ctx),
    get_vulnerability_detail: getVulnerabilityDetailTool(ctx),
    get_package_reputation: getPackageReputationTool(ctx),
    get_epss_score: getEpssScoreTool(ctx),
    check_cisa_kev: checkCisaKevTool(ctx),
    list_policies: listPoliciesTool(ctx),
    analyze_upgrade_path: analyzeUpgradePathTool(ctx),
  };
}
