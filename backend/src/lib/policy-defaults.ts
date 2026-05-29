/**
 * Default policy templates and seed data for the Policy-as-Code Engine.
 * Used when creating new organizations and for fallback values.
 */

export const DEFAULT_STATUSES = [
  {
    name: 'Compliant',
    color: '#22c55e',
    rank: 1,
    description: 'Project meets all policy requirements',
    is_system: true,
    is_passing: true,
  },
  {
    name: 'Non-Compliant',
    color: '#ef4444',
    rank: 100,
    description: 'Project does not meet policy requirements',
    is_system: true,
    is_passing: false,
  },
];

export const DEFAULT_PACKAGE_POLICY_CODE = `function packagePolicy(context) {
  // Block malicious packages
  if (context.dependency.maliciousIndicator) {
    return { allowed: false, reasons: ['Package flagged as malicious: ' + (context.dependency.maliciousIndicator.reason || 'unknown')] };
  }

  // For higher-importance projects (importance >= 1.3), apply stricter rules
  if (context.importance >= 1.3) {
    const BANNED_LICENSES = ['GPL-3.0', 'AGPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later', 'AGPL-3.0-only', 'AGPL-3.0-or-later'];
    if (context.dependency.license && BANNED_LICENSES.some(b => context.dependency.license.includes(b))) {
      return { allowed: false, reasons: ['Banned license for high-importance project: ' + context.dependency.license] };
    }
    if (context.dependency.dependencyScore != null && context.dependency.dependencyScore < 40) {
      return { allowed: false, reasons: ['Low reputation score for high-importance project: ' + context.dependency.dependencyScore] };
    }
  } else {
    // Lower-importance projects: block AGPL only
    if (context.dependency.license && context.dependency.license.includes('AGPL')) {
      return { allowed: false, reasons: ['AGPL not allowed'] };
    }
  }

  return { allowed: true, reasons: [] };
}`;

/**
 * Default projectStatus: if any dependency was disallowed by packagePolicy, project is Non-Compliant
 * with per-dependency reasons; otherwise Compliant. Matches engine fallback when no status code exists.
 */
export const DEFAULT_PROJECT_STATUS_CODE = `function projectStatus(context) {
  var deps = context.dependencies || [];
  var blocked = deps.filter(function(d) {
    return d.policyResult && d.policyResult.allowed === false;
  });
  if (blocked.length > 0) {
    return {
      status: 'Non-Compliant',
      violations: blocked.map(function(d) {
        return d.name + ': ' + (d.policyResult.reasons || []).join(', ');
      })
    };
  }
  return { status: 'Compliant', violations: [] };
}`;

export const DEFAULT_PR_CHECK_CODE = `function pullRequestCheck(context) {
  return { passed: true, violations: [] };
}`;
