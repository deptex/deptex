/**
 * Phase 7B: PR Security Review triggered by Phase 8 webhooks.
 * Runs autonomous Aegis analysis for dependency changes in PRs.
 */
import { supabase } from '../../../../backend/src/lib/supabase';
import { getVulnCountsForPackageVersion, type VulnCounts } from '../../../../backend/src/lib/vuln-counts';
import { getEffectivePolicies, isLicenseAllowed } from '../project-policies';

export interface DepAdded {
  name: string;
  version: string;
}

export interface DepUpdated {
  name: string;
  oldVersion: string;
  newVersion: string;
}

export interface ReviewPRParams {
  organizationId: string;
  projectId: string;
  prNumber: number;
  diff?: string;
  changedFiles: string[];
  depsAdded: DepAdded[];
  depsUpdated: DepUpdated[];
  depsRemoved: string[];
  provider: 'github' | 'gitlab' | 'bitbucket';
}

export type CheckStatus = 'pass' | 'warn' | 'fail';

export interface NewDepAnalysis {
  name: string;
  version: string;
  license: string | null;
  score: number | null;
  vulnCount: number;
  criticalCount: number;
  highCount: number;
  isMalicious: boolean;
  riskScore: number;
  recommendation: string;
  policyCompliant: boolean | null;
}

export interface VersionChangeAnalysis {
  name: string;
  oldVersion: string;
  newVersion: string;
  oldVulns: VulnCounts;
  newVulns: VulnCounts;
  cvesResolved: number;
  cvesIntroduced: number;
  policyCompliant: boolean | null;
  license: string | null;
}

export interface PRReviewResult {
  summary: string;
  checkStatus: CheckStatus;
  comment: string;
  newDeps?: NewDepAnalysis[];
  versionChanges?: VersionChangeAnalysis[];
  policyViolations?: string[];
}

const DEPTEX_AEGIS_REVIEW_MARKER = '<!-- deptex-aegis-review -->';

async function analyzeNewDependency(
  packageName: string,
  version: string,
  acceptedLicenses: string[]
): Promise<NewDepAnalysis> {
  const { data: dep } = await supabase
    .from('dependencies')
    .select('id, name, score, openssf_score, license, weekly_downloads, is_malicious, ecosystem')
    .eq('name', packageName)
    .single();

  const license = dep?.license ?? (await getLicenseFromRegistry(packageName));
  const policyCompliant =
    acceptedLicenses.length > 0 ? isLicenseAllowed(license, acceptedLicenses) : null;

  if (!dep) {
    return {
      name: packageName,
      version,
      license,
      score: null,
      vulnCount: 0,
      criticalCount: 0,
      highCount: 0,
      isMalicious: false,
      riskScore: 50,
      recommendation: 'Package not in database. Run extraction or add to a project first to get full analysis.',
      policyCompliant,
    };
  }

  const { data: vulns } = await supabase
    .from('dependency_vulnerabilities')
    .select('osv_id, severity')
    .eq('dependency_id', dep.id);

  const critical = (vulns ?? []).filter((v: { severity?: string }) => v.severity === 'critical').length;
  const high = (vulns ?? []).filter((v: { severity?: string }) => v.severity === 'high').length;
  const vulnCount = vulns?.length ?? 0;

  const vulnCounts = await getVulnCountsForPackageVersion(supabase, packageName, version);
  const totalAffected =
    vulnCounts.critical_vulns + vulnCounts.high_vulns + vulnCounts.medium_vulns + vulnCounts.low_vulns;

  const riskScore = dep.is_malicious
    ? 100
    : Math.min(100, critical * 25 + high * 10 + (dep.score != null ? 100 - dep.score : 30));

  const recommendation = dep.is_malicious
    ? 'DO NOT ADD — flagged as malicious'
    : critical > 0
      ? 'High risk — has critical vulnerabilities'
      : high > 0
        ? 'Moderate risk — has high severity vulnerabilities'
        : (dep.score ?? 50) < 40
          ? 'Caution — low reputation score'
          : 'Generally acceptable — review license and maintenance';

  return {
    name: packageName,
    version,
    license,
    score: dep.score ?? null,
    vulnCount: totalAffected,
    criticalCount: vulnCounts.critical_vulns,
    highCount: vulnCounts.high_vulns,
    isMalicious: dep.is_malicious ?? false,
    riskScore,
    recommendation,
    policyCompliant,
  };
}

async function getLicenseFromRegistry(name: string): Promise<string | null> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
      headers: { Accept: 'application/json', 'User-Agent': 'Deptex-App' },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { license?: string | { type?: string }; [key: string]: unknown };
    const lic = data?.license;
    if (typeof lic === 'string') return lic;
    if (lic && typeof lic === 'object' && 'type' in lic) return (lic as { type?: string }).type ?? null;
    return null;
  } catch {
    return null;
  }
}

async function analyzeVersionChange(
  name: string,
  oldVersion: string,
  newVersion: string,
  acceptedLicenses: string[]
): Promise<VersionChangeAnalysis> {
  const [oldVulns, newVulns] = await Promise.all([
    getVulnCountsForPackageVersion(supabase, name, oldVersion),
    getVulnCountsForPackageVersion(supabase, name, newVersion),
  ]);

  const oldTotal =
    oldVulns.critical_vulns + oldVulns.high_vulns + oldVulns.medium_vulns + oldVulns.low_vulns;
  const newTotal =
    newVulns.critical_vulns + newVulns.high_vulns + newVulns.medium_vulns + newVulns.low_vulns;

  const cvesResolved = Math.max(0, oldTotal - newTotal);
  const cvesIntroduced = Math.max(0, newTotal - oldTotal);

  const license = (await supabase.from('dependencies').select('license').eq('name', name).single()).data?.license ?? await getLicenseFromRegistry(name);
  const policyCompliant =
    acceptedLicenses.length > 0 ? isLicenseAllowed(license, acceptedLicenses) : null;

  return {
    name,
    oldVersion,
    newVersion,
    oldVulns,
    newVulns,
    cvesResolved,
    cvesIntroduced,
    policyCompliant,
    license,
  };
}

function formatVulnCounts(v: VulnCounts): string {
  const parts = [];
  if (v.critical_vulns > 0) parts.push(`${v.critical_vulns} critical`);
  if (v.high_vulns > 0) parts.push(`${v.high_vulns} high`);
  if (v.medium_vulns > 0) parts.push(`${v.medium_vulns} medium`);
  if (v.low_vulns > 0) parts.push(`${v.low_vulns} low`);
  return parts.length > 0 ? parts.join(', ') : '0 vulnerabilities';
}

/**
 * Run autonomous Aegis PR security analysis.
 */
export async function reviewPR(params: ReviewPRParams): Promise<PRReviewResult> {
  const { organizationId, projectId, depsAdded, depsUpdated, depsRemoved } = params;

  const { acceptedLicenses } = await getEffectivePolicies(organizationId, projectId);

  const newDeps: NewDepAnalysis[] = [];
  const versionChanges: VersionChangeAnalysis[] = [];
  const policyViolations: string[] = [];
  let hasFailure = false;
  let hasWarning = false;

  for (const d of depsAdded) {
    const analysis = await analyzeNewDependency(d.name, d.version, acceptedLicenses);
    newDeps.push(analysis);
    if (analysis.isMalicious || analysis.criticalCount > 0) hasFailure = true;
    else if (analysis.highCount > 0 || analysis.riskScore >= 70) hasWarning = true;
    if (analysis.policyCompliant === false) {
      policyViolations.push(`${d.name}@${d.version}: license ${analysis.license ?? 'unknown'} not in allowed list`);
      hasFailure = true;
    }
  }

  for (const d of depsUpdated) {
    const analysis = await analyzeVersionChange(
      d.name,
      d.oldVersion,
      d.newVersion,
      acceptedLicenses
    );
    versionChanges.push(analysis);
    if (analysis.cvesIntroduced > 0) hasWarning = true;
    if (analysis.policyCompliant === false) {
      policyViolations.push(`${d.name}@${d.newVersion}: license not in allowed list`);
      hasFailure = true;
    }
  }

  const checkStatus: CheckStatus = hasFailure ? 'fail' : hasWarning ? 'warn' : 'pass';

  const sections: string[] = [];

  sections.push('## Security Summary');
  sections.push('');
  sections.push(`- **Status:** ${checkStatus.toUpperCase()}`);
  sections.push(`- **New dependencies:** ${depsAdded.length}`);
  sections.push(`- **Updated dependencies:** ${depsUpdated.length}`);
  sections.push(`- **Removed dependencies:** ${depsRemoved.length}`);
  sections.push('');

  if (newDeps.length > 0) {
    sections.push('## New Dependencies');
    sections.push('');
    for (const a of newDeps) {
      const licStr = a.license ?? 'Unknown';
      const policyNote = a.policyCompliant === false ? ' ⚠️ **Policy violation**' : '';
      sections.push(`- **${a.name}** \`${a.version}\``);
      sections.push(`  - License: ${licStr}; ${a.vulnCount} vulnerabilities (${a.criticalCount} critical, ${a.highCount} high)${policyNote}`);
      sections.push(`  - *${a.recommendation}*`);
      sections.push('');
    }
  }

  if (versionChanges.length > 0) {
    sections.push('## Vulnerability Impact');
    sections.push('');
    for (const v of versionChanges) {
      const resolvedStr = v.cvesResolved > 0 ? ` ${v.cvesResolved} resolved` : '';
      const introStr = v.cvesIntroduced > 0 ? ` ${v.cvesIntroduced} introduced` : '';
      sections.push(`- **${v.name}** \`${v.oldVersion}\` → \`${v.newVersion}\``);
      sections.push(`  - Before: ${formatVulnCounts(v.oldVulns)}`);
      sections.push(`  - After: ${formatVulnCounts(v.newVulns)}${resolvedStr}${introStr}`);
      sections.push('');
    }
  }

  if (newDeps.length > 0 || versionChanges.length > 0) {
    const licenses = [
      ...newDeps.map((a) => a.license ?? 'Unknown'),
      ...versionChanges.map((v) => v.license ?? 'Unknown'),
    ];
    const uniqueLicenses = [...new Set(licenses)];
    sections.push('## License Changes');
    sections.push('');
    sections.push(`Affected licenses: ${uniqueLicenses.join(', ')}`);
    sections.push('');
  }

  if (policyViolations.length > 0) {
    sections.push('## Policy Compliance');
    sections.push('');
    sections.push('The following packages do not comply with this project\'s policy:');
    sections.push('');
    for (const p of policyViolations) {
      sections.push(`- ${p}`);
    }
    sections.push('');
  }

  const comment = sections.join('\n');
  const summary =
    checkStatus === 'pass'
      ? 'All dependency changes meet security and policy requirements.'
      : checkStatus === 'warn'
        ? 'Some dependency changes have moderate risks; review recommended.'
        : 'Some dependency changes have critical issues or policy violations.';

  return {
    summary,
    checkStatus,
    comment,
    newDeps: newDeps.length > 0 ? newDeps : undefined,
    versionChanges: versionChanges.length > 0 ? versionChanges : undefined,
    policyViolations: policyViolations.length > 0 ? policyViolations : undefined,
  };
}

/**
 * Format the review result as a GitHub/GitLab/Bitbucket compatible PR comment
 * with the <!-- deptex-aegis-review --> marker.
 */
export function generatePRComment(reviewResult: PRReviewResult): string {
  return `${DEPTEX_AEGIS_REVIEW_MARKER}\n${reviewResult.comment}`;
}
