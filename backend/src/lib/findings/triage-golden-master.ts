/**
 * GOLDEN MASTER — frozen auto-triage contract for the findings-status foundation.
 *
 * Today the "is this finding auto-ignored?" verdict is computed in THREE places
 * that have silently drifted apart:
 *   1. frontend  `autoTriageRow()`        (VulnerabilityExpandableTable.tsx) — canonical, what the user sees
 *   2. backend   `vulnAutoIgnoreReason()` (lib/aegis-v3/finding-triage.ts)   — SCA-only mirror for Aegis
 *   3. SQL       `security_summary_counts` (phase54)                          — a LOSSY re-impl for the count pills
 *
 * The findings-status foundation collapses these into ONE source: a stored
 * `auto_ignored` column computed in SQL (`compute_auto_ignored()`), backfilled
 * by phase55. Before `autoTriageRow` is deleted, we FREEZE its current per-row
 * behavior here so the new SQL can be proven byte-equal to it — and so the
 * IaC/DAST cases where the phase54 SQL *disagrees* with the TS truth (the lossy
 * mirror) are pinned to the TS verdict, not the SQL's.
 *
 * `referenceStoredAutoIgnored()` below is the canonical, hand-frozen port of
 * `autoTriageRow`'s per-row branches. The SQL `compute_auto_ignored()` mirrors
 * THIS function; the parity tests diff the two. Do not "improve" the logic here
 * — it is a snapshot of behavior as of the freeze, deliberately bug-for-bug.
 *
 * Provenance split (per the plan):
 *   - SCA / container  → TS-frozen (TS and phase54 already agree here).
 *   - IaC / DAST       → TS-frozen, and the divergence cases vs phase54 are
 *     marked `divergesFromPhase54` so the parity suite proves the new SQL
 *     follows TS, fixing the count/table drift.
 *
 * STORED vs EFFECTIVE (the runtime override):
 *   The stored `auto_ignored` for SCA is computed from reachability ONLY. A
 *   later DAST run can flip `runtime_confirmed_at` to non-null WITHOUT re-running
 *   extraction/finalize, so the runtime gate is applied as a READ-TIME override
 *   (`auto_ignored AND runtime_confirmed_at IS NULL`) by every reader rather than
 *   baked into the stored column. `referenceEffectiveAutoIgnored()` composes the
 *   two and reproduces `autoTriageRow` exactly.
 */

/** The canonical stored reason vocabulary (== frontend AutoTriageReason). */
export type AutoIgnoreReason =
  | 'not_reachable'
  | 'unconfirmed_reachable'
  | 'base_image'
  | 'passive_hygiene'
  | 'iac_hardening';

/** Finding types that carry a stored auto_ignored verdict. `secret`, `semgrep`,
 *  `malicious`, and `taint_flow` are never auto-ignored (their only "ignored"
 *  state is a manual disposition), so they always resolve to (false, null). */
export type TriageType =
  | 'vulnerability'
  | 'container'
  | 'iac'
  | 'dast'
  | 'secret'
  | 'semgrep'
  | 'malicious'
  | 'taint_flow';

/** The per-row inputs `autoTriageRow` reads, across all types. Every field is
 *  optional; the type tag selects which are consulted. */
export interface TriageInput {
  // SCA (vulnerability)
  reachability_level?: string | null;
  is_reachable?: boolean | null;
  runtime_confirmed_at?: string | null;
  // container
  is_kev?: boolean | null;
  // iac
  rule_id?: string | null;
  severity?: string | null;
  // dast
  payload_redacted?: string | null;
}

export interface TriageVerdict {
  auto_ignored: boolean;
  auto_ignore_reason: AutoIgnoreReason | null;
}

export interface GoldenCase {
  name: string;
  type: TriageType;
  input: TriageInput;
  /** The reachability-only stored verdict (what `compute_auto_ignored` writes). */
  stored: TriageVerdict;
  /** What the user actually sees (`autoTriageRow` output) — stored, with the
   *  PDV runtime override applied. Equals `stored` for every non-SCA row. */
  effective: TriageVerdict;
  /** True where the phase54 SQL gives a DIFFERENT open/ignored verdict than the
   *  TS truth — the lossy-mirror cases the new SQL must fix by following TS. */
  divergesFromPhase54?: boolean;
}

const OPEN: TriageVerdict = { auto_ignored: false, auto_ignore_reason: null };

// ---------------------------------------------------------------------------
// The frozen reference implementation. Mirrors autoTriageRow() branch-for-branch.
// ---------------------------------------------------------------------------

/** IaC criticality, frozen from `iacRuleInfo()` in
 *  frontend/src/components/security/infra-format.ts. Per-rule entries in
 *  K8S_RULES win (case-sensitive exact match); unmapped rules fall back to
 *  severity (HIGH/CRITICAL → critical). A critical rule stays Open; the
 *  hardening tail is auto-ignored. */
const IAC_CRITICAL_RULES = new Set<string>([
  'CKV_K8S_16', 'CKV_K8S_20', 'CKV_K8S_23', 'CKV_K8S_19', 'CKV_K8S_17', 'CKV_K8S_18',
  'KSV-0023', 'KSV023', 'AVD-KSV-0023', 'KSV-0121',
]);
const IAC_NONCRITICAL_RULES = new Set<string>([
  'CKV_K8S_38', 'CKV_K8S_28', 'CKV_K8S_37', 'CKV2_K8S_6', 'CKV_K8S_31', 'CKV_K8S_22',
  'CKV_K8S_29', 'CKV_K8S_14', 'CKV_K8S_43', 'CKV_K8S_40', 'CKV_K8S_13', 'CKV_K8S_11',
  'CKV_K8S_10', 'CKV_K8S_12', 'CKV_K8S_8', 'CKV_K8S_9', 'CKV_K8S_21',
]);

function iacIsCritical(ruleId: string | null | undefined, severity: string | null | undefined): boolean {
  if (ruleId && IAC_CRITICAL_RULES.has(ruleId)) return true;
  if (ruleId && IAC_NONCRITICAL_RULES.has(ruleId)) return false;
  const sev = (severity ?? '').toUpperCase();
  return sev === 'HIGH' || sev === 'CRITICAL';
}

/**
 * The STORED per-row verdict — reachability-only for SCA (the runtime gate is a
 * read-time override). This is the exact contract `compute_auto_ignored()`
 * implements in SQL.
 */
export function referenceStoredAutoIgnored(type: TriageType, input: TriageInput): TriageVerdict {
  switch (type) {
    case 'container':
      // KEV base-image CVEs stay Open; the rest are remediated by upgrading the
      // base image, so they're folded behind the base-image recommendation.
      return input.is_kev === true ? OPEN : { auto_ignored: true, auto_ignore_reason: 'base_image' };
    case 'iac':
      return iacIsCritical(input.rule_id, input.severity)
        ? OPEN
        : { auto_ignored: true, auto_ignore_reason: 'iac_hardening' };
    case 'dast': {
      const sev = (input.severity ?? '').toLowerCase();
      const exploited = Boolean(input.payload_redacted && input.payload_redacted.trim());
      if (!exploited && sev !== 'high' && sev !== 'critical') {
        return { auto_ignored: true, auto_ignore_reason: 'passive_hygiene' };
      }
      return OPEN;
    }
    case 'vulnerability': {
      // Reachability only — NOT runtime_confirmed_at (read-time override).
      const level = (input.reachability_level ?? '').toLowerCase();
      if (level === 'confirmed' || level === 'data_flow') return OPEN;
      if (level === 'unreachable' || input.is_reachable === false) {
        return { auto_ignored: true, auto_ignore_reason: 'not_reachable' };
      }
      if (level === 'module') return { auto_ignored: true, auto_ignore_reason: 'unconfirmed_reachable' };
      return OPEN;
    }
    // secret / semgrep / malicious / taint_flow — never auto-ignored.
    default:
      return OPEN;
  }
}

/**
 * The EFFECTIVE verdict the user sees — stored, with the PDV runtime override.
 * For SCA, `runtime_confirmed_at` being set forces the row Open. Equals the
 * stored verdict for every other type. Reproduces `autoTriageRow()` exactly.
 */
export function referenceEffectiveAutoIgnored(type: TriageType, input: TriageInput): TriageVerdict {
  const stored = referenceStoredAutoIgnored(type, input);
  if (type === 'vulnerability' && input.runtime_confirmed_at) return OPEN;
  return stored;
}

// ---------------------------------------------------------------------------
// The frozen cases. Every branch of autoTriageRow, plus the phase54 divergences.
// ---------------------------------------------------------------------------

export const GOLDEN_CASES: GoldenCase[] = [
  // --- SCA / vulnerability (reachability + runtime override) ---
  {
    name: 'sca: confirmed reachable stays open regardless of score',
    type: 'vulnerability',
    input: { reachability_level: 'confirmed' },
    stored: OPEN, effective: OPEN,
  },
  {
    name: 'sca: data_flow reachable stays open',
    type: 'vulnerability',
    input: { reachability_level: 'data_flow' },
    stored: OPEN, effective: OPEN,
  },
  {
    name: 'sca: unreachable → not_reachable',
    type: 'vulnerability',
    input: { reachability_level: 'unreachable' },
    stored: { auto_ignored: true, auto_ignore_reason: 'not_reachable' },
    effective: { auto_ignored: true, auto_ignore_reason: 'not_reachable' },
  },
  {
    name: 'sca: is_reachable=false → not_reachable',
    type: 'vulnerability',
    input: { is_reachable: false },
    stored: { auto_ignored: true, auto_ignore_reason: 'not_reachable' },
    effective: { auto_ignored: true, auto_ignore_reason: 'not_reachable' },
  },
  {
    name: 'sca: module → unconfirmed_reachable',
    type: 'vulnerability',
    input: { reachability_level: 'module' },
    stored: { auto_ignored: true, auto_ignore_reason: 'unconfirmed_reachable' },
    effective: { auto_ignored: true, auto_ignore_reason: 'unconfirmed_reachable' },
  },
  {
    name: 'sca: function-level stays open',
    type: 'vulnerability',
    input: { reachability_level: 'function' },
    stored: OPEN, effective: OPEN,
  },
  {
    name: 'sca: no reachability verdict stays open',
    type: 'vulnerability',
    input: { reachability_level: null },
    stored: OPEN, effective: OPEN,
  },
  {
    // The crux of the read-time override: stored says not_reachable, but a
    // runtime-confirmed (DAST-verified) finding is forced Open at read time.
    name: 'sca: runtime-confirmed + unreachable → stored not_reachable, effective OPEN',
    type: 'vulnerability',
    input: { reachability_level: 'unreachable', runtime_confirmed_at: '2026-06-05T00:00:00Z' },
    stored: { auto_ignored: true, auto_ignore_reason: 'not_reachable' },
    effective: OPEN,
  },
  {
    name: 'sca: runtime-confirmed + module → stored unconfirmed_reachable, effective OPEN',
    type: 'vulnerability',
    input: { reachability_level: 'module', runtime_confirmed_at: '2026-06-05T00:00:00Z' },
    stored: { auto_ignored: true, auto_ignore_reason: 'unconfirmed_reachable' },
    effective: OPEN,
  },

  // --- container (KEV vs base-image) ---
  {
    name: 'container: non-KEV (even critical) → base_image',
    type: 'container',
    input: { is_kev: false, severity: 'CRITICAL' },
    stored: { auto_ignored: true, auto_ignore_reason: 'base_image' },
    effective: { auto_ignored: true, auto_ignore_reason: 'base_image' },
  },
  {
    name: 'container: is_kev null → base_image',
    type: 'container',
    input: { is_kev: null, severity: 'high' },
    stored: { auto_ignored: true, auto_ignore_reason: 'base_image' },
    effective: { auto_ignored: true, auto_ignore_reason: 'base_image' },
  },
  {
    name: 'container: KEV → stays open',
    type: 'container',
    input: { is_kev: true, severity: 'medium' },
    stored: OPEN, effective: OPEN,
  },

  // --- iac (per-rule critical map + severity fallback) ---
  {
    name: 'iac: CKV_K8S_16 (privileged) is per-rule critical → open',
    type: 'iac',
    input: { rule_id: 'CKV_K8S_16', severity: 'LOW' },
    stored: OPEN, effective: OPEN,
  },
  {
    name: 'iac: KSV-0023 (hostPath) is per-rule critical → open',
    type: 'iac',
    input: { rule_id: 'KSV-0023', severity: 'MEDIUM' },
    stored: OPEN, effective: OPEN,
  },
  {
    name: 'iac: CKV_K8S_13 (no memory limit) is per-rule hardening → iac_hardening',
    type: 'iac',
    input: { rule_id: 'CKV_K8S_13', severity: 'MEDIUM' },
    stored: { auto_ignored: true, auto_ignore_reason: 'iac_hardening' },
    effective: { auto_ignored: true, auto_ignore_reason: 'iac_hardening' },
  },
  {
    // DIVERGENCE: phase54 only opens its narrow k8s-critical IN-list or
    // (dockerfile AND high/crit). An UNMAPPED HIGH-severity rule (e.g. a
    // terraform CKV_AWS_* or a new CKV_K8S_*) is auto-ignored by phase54 but
    // kept OPEN by the TS severity fallback. The new SQL must follow TS.
    name: 'iac: unmapped HIGH-severity rule → severity fallback OPEN (phase54 hides it)',
    type: 'iac',
    input: { rule_id: 'CKV_AWS_23', severity: 'HIGH' },
    stored: OPEN, effective: OPEN,
    divergesFromPhase54: true,
  },
  {
    name: 'iac: unmapped CRITICAL-severity rule → severity fallback OPEN',
    type: 'iac',
    input: { rule_id: 'CKV_AWS_999', severity: 'CRITICAL' },
    stored: OPEN, effective: OPEN,
    divergesFromPhase54: true,
  },
  {
    name: 'iac: unmapped MEDIUM-severity rule → hardening',
    type: 'iac',
    input: { rule_id: 'CKV_AWS_50', severity: 'MEDIUM' },
    stored: { auto_ignored: true, auto_ignore_reason: 'iac_hardening' },
    effective: { auto_ignored: true, auto_ignore_reason: 'iac_hardening' },
  },
  {
    // A known non-critical rule stays hardening EVEN at HIGH severity — the
    // per-rule map wins over severity. phase54 (severity-only on unmapped, but
    // this rule isn't in its critical IN-list either) happens to agree here.
    name: 'iac: known hardening rule at HIGH severity stays hardening (per-rule wins)',
    type: 'iac',
    input: { rule_id: 'CKV_K8S_22', severity: 'HIGH' },
    stored: { auto_ignored: true, auto_ignore_reason: 'iac_hardening' },
    effective: { auto_ignored: true, auto_ignore_reason: 'iac_hardening' },
  },

  // --- dast (passive vs active/high) ---
  {
    name: 'dast: passive (no payload, low sev) → passive_hygiene',
    type: 'dast',
    input: { severity: 'low', payload_redacted: null },
    stored: { auto_ignored: true, auto_ignore_reason: 'passive_hygiene' },
    effective: { auto_ignored: true, auto_ignore_reason: 'passive_hygiene' },
  },
  {
    name: 'dast: passive (no payload, info sev) → passive_hygiene',
    type: 'dast',
    input: { severity: 'info', payload_redacted: '' },
    stored: { auto_ignored: true, auto_ignore_reason: 'passive_hygiene' },
    effective: { auto_ignored: true, auto_ignore_reason: 'passive_hygiene' },
  },
  {
    name: 'dast: has payload (exploited) → open even at low sev',
    type: 'dast',
    input: { severity: 'low', payload_redacted: "' OR 1=1--" },
    stored: OPEN, effective: OPEN,
  },
  {
    name: 'dast: high severity (no payload) → open',
    type: 'dast',
    input: { severity: 'high', payload_redacted: null },
    stored: OPEN, effective: OPEN,
  },
  {
    name: 'dast: critical severity → open',
    type: 'dast',
    input: { severity: 'critical', payload_redacted: '   ' /* whitespace-only = not exploited */ },
    stored: { auto_ignored: false, auto_ignore_reason: null }, effective: OPEN,
  },

  // --- types that are never auto-ignored ---
  { name: 'secret: never auto-ignored', type: 'secret', input: { severity: 'critical' }, stored: OPEN, effective: OPEN },
  { name: 'semgrep: never auto-ignored', type: 'semgrep', input: { severity: 'high' }, stored: OPEN, effective: OPEN },
  { name: 'malicious: never auto-ignored', type: 'malicious', input: { severity: 'critical' }, stored: OPEN, effective: OPEN },
  { name: 'taint_flow: never auto-ignored', type: 'taint_flow', input: {}, stored: OPEN, effective: OPEN },
];
