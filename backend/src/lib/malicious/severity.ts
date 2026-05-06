import type { MaliciousSeverity } from './types';
import type { MaintainerSignals } from './maintainer-signals';

/**
 * Severity mapping for malicious-package findings.
 *
 * The schema CHECK is 5-wide (`critical | high | medium | low | info`) for
 * forward compatibility, but v1 produces only three effective levels:
 *
 *   - feed match (OSV / GHSA confirmed-malicious advisory)  ->  critical
 *   - GuardDog ERROR rule hit                              ->  high
 *   - GuardDog WARNING rule hit                            ->  medium
 *
 * Anything else is mapped to `info` rather than rejected — GuardDog's rule
 * set evolves, and an unfamiliar severity should still surface (just not
 * gate on severity-driven UI thresholds).
 */
export function severityForFeedFinding(): MaliciousSeverity {
  return 'critical';
}

export function severityForGuardDogFinding(rawSeverity: string | null | undefined): MaliciousSeverity {
  switch ((rawSeverity ?? '').toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    case 'INFO':
      return 'info';
    default:
      return 'info';
  }
}

const SEVERITY_RANK: Record<MaliciousSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Numeric rank for sorting by severity. Higher = more severe.
 */
export function severityRank(severity: MaliciousSeverity): number {
  return SEVERITY_RANK[severity];
}

/**
 * Highest-severity wins when multiple findings collapse onto the same row
 * (e.g. when picking the `top_finding_id` for the notification indicator).
 */
export function maxSeverity(a: MaliciousSeverity, b: MaliciousSeverity): MaliciousSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/**
 * Map a per-package maintainer-signal set to a single best-fit finding.
 *
 * Returns `null` when the signal set is too weak to surface a finding —
 * the cron route iterates past these packages without writing rows.
 *
 * Severity ladder (highest match wins):
 *   - critical: account <30d AND install_script_present       (Shai-Hulud-class fresh package shipping install hook)
 *   - critical: email_changed_in_last_30d AND new_postinstall_added       (ownership transfer + new install hook)
 *   - critical: maintainer_changed_in_last_30d AND new_postinstall_added  (ownership transfer + new install hook)
 *   - high:     new_postinstall_added                          (install hook newly added on established package)
 *   - high:     signing_setup_changed                          (provenance changed mid-stream)
 *   - medium:   email_changed_in_last_30d                      (lone email diff; could be legit)
 *   - medium:   maintainer_changed_in_last_30d                 (lone maintainer-set diff; could be legit)
 *   - medium:   account <30d                                   (brand-new package, no install hook)
 *
 * `rule_id` is the `'maintainer:<kind>'` slug stored on `project_malicious_findings.rule_id`.
 * `message` is human-readable + injection-clean (no registry-supplied strings inlined).
 */
export interface MaintainerFinding {
  rule_id: string;
  severity: MaliciousSeverity;
  message: string;
  signals: MaintainerSignals;
}

const NEW_ACCOUNT_THRESHOLD_DAYS = 30;

export function severityForMaintainerSignal(signals: MaintainerSignals): MaintainerFinding | null {
  const isNewAccount = (signals.account_age_days ?? Number.POSITIVE_INFINITY) < NEW_ACCOUNT_THRESHOLD_DAYS;

  // ── critical ──────────────────────────────────────────────────────────
  if (isNewAccount && signals.install_script_present) {
    return {
      rule_id: 'maintainer:new_account_with_install_script',
      severity: 'critical',
      message:
        'Package was first published in the last 30 days and ships an install hook. Treat as a Shai-Hulud-class supply-chain risk.',
      signals,
    };
  }
  if (signals.email_changed_in_last_30d && signals.new_postinstall_added) {
    return {
      rule_id: 'maintainer:email_changed_with_new_postinstall',
      severity: 'critical',
      message:
        'Maintainer email changed in the last 30 days AND a new install hook was added in the same window. Strong account-takeover signal.',
      signals,
    };
  }
  if (signals.maintainer_changed_in_last_30d && signals.new_postinstall_added) {
    return {
      rule_id: 'maintainer:maintainer_changed_with_new_postinstall',
      severity: 'critical',
      message:
        'Package maintainer set changed in the last 30 days AND a new install hook was added in the same window. Strong ownership-transfer attack signal.',
      signals,
    };
  }

  // ── high ──────────────────────────────────────────────────────────────
  if (signals.new_postinstall_added) {
    return {
      rule_id: 'maintainer:new_postinstall_added',
      severity: 'high',
      message:
        'A new install hook was added since the last 30-day baseline. Verify the change is intentional before installing.',
      signals,
    };
  }
  if (signals.signing_setup_changed) {
    return {
      rule_id: 'maintainer:signing_setup_changed',
      severity: 'high',
      message:
        'Package signing / provenance configuration changed since the last 30-day baseline. Verify the publisher key is still legitimate.',
      signals,
    };
  }

  // ── medium ────────────────────────────────────────────────────────────
  if (signals.email_changed_in_last_30d) {
    return {
      rule_id: 'maintainer:email_changed',
      severity: 'medium',
      message:
        'Primary maintainer email changed in the last 30 days. Could be a legitimate ownership update; verify before pinning a new version.',
      signals,
    };
  }
  if (signals.maintainer_changed_in_last_30d) {
    return {
      rule_id: 'maintainer:maintainer_changed',
      severity: 'medium',
      message:
        'Package maintainer set changed in the last 30 days. Could be a legitimate ownership update; verify before pinning a new version.',
      signals,
    };
  }
  if (isNewAccount) {
    return {
      rule_id: 'maintainer:new_account',
      severity: 'medium',
      message:
        'Package was first published in the last 30 days. No install hook detected, but new packages should be reviewed before adoption.',
      signals,
    };
  }

  return null;
}
