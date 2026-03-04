/**
 * Default policy templates and seed data for Phase 4: Policy-as-Code Engine.
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

export const DEFAULT_ASSET_TIERS = [
  {
    name: 'Crown Jewels',
    description: 'Mission-critical systems with highest security requirements',
    color: '#ef4444',
    rank: 1,
    is_system: true,
    environmental_multiplier: 1.5,
  },
  {
    name: 'External',
    description: 'External-facing applications',
    color: '#f97316',
    rank: 2,
    is_system: true,
    environmental_multiplier: 1.2,
  },
  {
    name: 'Internal',
    description: 'Internal tools and services',
    color: '#3b82f6',
    rank: 3,
    is_system: true,
    environmental_multiplier: 1.0,
  },
  {
    name: 'Non-Production',
    description: 'Development, staging, and test environments',
    color: '#6b7280',
    rank: 4,
    is_system: true,
    environmental_multiplier: 0.6,
  },
];

export const DEFAULT_PACKAGE_POLICY_CODE = `function packagePolicy(context) {
  // Block malicious packages for all tiers
  if (context.dependency.maliciousIndicator) {
    return { allowed: false, reasons: ['Package flagged as malicious: ' + (context.dependency.maliciousIndicator.reason || 'unknown')] };
  }

  // Critical tiers (Crown Jewels, External): stricter rules
  if (context.tier.rank <= 2) {
    const BANNED_LICENSES = ['GPL-3.0', 'AGPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later', 'AGPL-3.0-only', 'AGPL-3.0-or-later'];
    if (context.dependency.license && BANNED_LICENSES.some(b => context.dependency.license.includes(b))) {
      return { allowed: false, reasons: ['Banned license for ' + context.tier.name + ': ' + context.dependency.license] };
    }
    if (context.dependency.dependencyScore != null && context.dependency.dependencyScore < 40) {
      return { allowed: false, reasons: ['Low reputation score for ' + context.tier.name + ': ' + context.dependency.dependencyScore] };
    }
  }

  // Internal tier: block AGPL only
  if (context.tier.rank === 3) {
    if (context.dependency.license && context.dependency.license.includes('AGPL')) {
      return { allowed: false, reasons: ['AGPL not allowed for Internal projects'] };
    }
  }

  return { allowed: true, reasons: [] };
}`;

export const DEFAULT_PROJECT_STATUS_CODE = `function projectStatus(context) {
  var violations = [];
  var blocked = context.dependencies.filter(function(d) { return d.policyResult && !d.policyResult.allowed; });
  var reachableCritical = context.dependencies.filter(function(d) {
    return d.vulnerabilities && d.vulnerabilities.some(function(v) {
      return v.severity === 'critical' && v.isReachable;
    });
  });

  if (blocked.length > 0) {
    blocked.forEach(function(d) {
      violations.push(d.name + ': ' + (d.policyResult.reasons || []).join(', '));
    });
  }
  if (reachableCritical.length > 0) {
    reachableCritical.forEach(function(d) {
      violations.push(d.name + ': reachable critical vulnerability');
    });
  }

  if (blocked.length > 5 || reachableCritical.length > 0) {
    return { status: 'Non-Compliant', violations: violations };
  }
  if (blocked.length > 0) {
    return { status: 'Non-Compliant', violations: violations };
  }
  return { status: 'Compliant', violations: [] };
}`;

export const DEFAULT_PR_CHECK_CODE = `function pullRequestCheck(context) {
  var newViolations = context.added.concat(context.updated).filter(function(d) {
    return d.policyResult && !d.policyResult.allowed;
  });

  if (newViolations.length > 0) {
    var violations = newViolations.map(function(d) {
      return d.name + ': ' + (d.policyResult.reasons || []).join(', ');
    });
    return { status: 'Non-Compliant', violations: violations };
  }
  return { status: 'Compliant', violations: [] };
}`;

/**
 * Maps legacy asset_tier enum values to default tier names.
 */
export const LEGACY_TIER_MAP: Record<string, string> = {
  CROWN_JEWELS: 'Crown Jewels',
  EXTERNAL: 'External',
  INTERNAL: 'Internal',
  NON_PRODUCTION: 'Non-Production',
};
