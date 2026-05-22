// ZAP report parser + log scrub helpers.

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface DastFindingRaw {
  endpoint_url: string;
  http_method: string;
  vulnerability_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe_id: string | null;
  owasp_top10_ref: string | null;
  rule_id: string | null;
  message: string | null;
  payload_redacted: string | null;
  response_evidence_redacted: string | null;
  confidence: 'confirmed' | 'high' | 'medium' | 'low';
  // ---- v2.1c — Nuclei engine fields ----
  // All optional: ZAP findings leave them unset. The pipeline defaults
  // `engine` to 'zap' on the ZAP path so every inserted row is tagged.
  /** Which DAST engine produced this finding. */
  engine?: 'zap' | 'nuclei';
  /** Nuclei template id (mirrors rule_id for Nuclei findings). */
  template_id?: string | null;
  /** True when the Nuclei template is tagged `kev` (CISA Known Exploited). */
  kev?: boolean;
  /** CVE ids from the Nuclei template classification — drives the SCA flip. */
  cve_ids?: string[];
  /** EPSS score from the Nuclei template classification, when present. */
  epss_score?: number | null;
  /** CPE string from the Nuclei template classification, when present. */
  cpe?: string | null;
  /** Values extracted by the Nuclei template's extractors (redacted). */
  extracted_values?: string[] | null;
}

export type DastScanProfile = 'auto' | 'quick' | 'full' | 'api';

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const REDACTION_PATTERNS: Array<[RegExp, string]> = [
  // JWTs
  [/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[REDACTED_JWT]'],
  // AWS access keys
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED_AWS_KEY]'],
  // Bearer tokens
  [/(?:Bearer|bearer)\s+[A-Za-z0-9+/=._-]{20,}/g, 'Bearer [REDACTED]'],
  // Cookie / Set-Cookie request and response headers — cookie-strategy
  // credentials are emitted by ZAP as `Cookie: session=…; csrf=…` when
  // verbose tracing is enabled. We redact the entire header value (rather
  // than only the first name=value pair) because every pair on the line is
  // potentially sensitive and `;`-separated continuations would otherwise
  // slip through. Stops at end-of-line so multi-header logs aren't squashed.
  [/(?:^|\b)((?:set-)?cookie)\s*:\s*[^\r\n]+/gi, '$1: [REDACTED]'],
  // GitHub tokens
  [/\bghp_[A-Za-z0-9]{36}\b/g, '[REDACTED_GHP]'],
  [/\bghs_[A-Za-z0-9]{36}\b/g, '[REDACTED_GHS]'],
  // Password assignments — stop at URL / cookie delimiters (`?`, `&`, `;`, `#`)
  // and structural chars (`)`, `]`, `>`, `\`) in addition to whitespace and
  // JSON quote/comma/brace boundaries. Without this the assignment value
  // greedily swallowed surrounding query-string state, and downstream rules
  // (e.g. the api_key matcher) couldn't fire on credentials embedded later
  // in the same URL.
  [/(?:password|passwd|pwd)["']?\s*[:=]\s*["']?[^\s"',;&?#}\])>\\]+/gi, 'password=[REDACTED]'],
  // API key assignments — accept base64 (`+`, `/`, `=`) so padded tokens
  // aren't truncated mid-redact, and stop at the same URL / cookie
  // delimiter set as the password matcher.
  [/(?:api[_-]?key|apikey|access[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{12,}(?=[\s"',;&?#}\])>\\]|$)/gi, 'api_key=[REDACTED]'],
  // Slack tokens
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED_SLACK]'],
  // Phase 36 (v1.1) — setHeader("Cookie", "name=value;…") JS-source literal
  // emitted by replay-zap-auth.ts's generateReplayAuthScript. The header-form
  // matcher above requires `cookie:` (colon-separated) so it doesn't fire on
  // this comma-separated JS-source shape. Defense-in-depth against ZAP /
  // Graal.js emitting the offending script source on a parse / registration
  // error to stderr — pipeline.ts:runReplayLoginProbe forwards every stderr
  // chunk through redactCredentials.
  [/setHeader\s*\(\s*["'](?:Cookie|Set-Cookie|Authorization)["']\s*,\s*["'][^"']*["']/gi, 'setHeader("[REDACTED]")'],
  // Bare RFC 4648 base32 strings of ≥16 chars (legitimate TOTP secrets are
  // 16-32). The positive lookahead requires at least one base32-digit char
  // (2-7) somewhere in the match — without it the regex would false-positive
  // on long all-uppercase identifiers like `LONGCONSTNAMEHERE`. TOTP secrets
  // from real IdPs always carry digits (base32 alphabet has 8 digits in 32
  // chars; 16-char run averages ~4). Matches the inlined
  // `__DEPTEX_TOTP_SECRET = "JBSWY3DPEHPK3PXP"` shape in the generated
  // Graal.js source — the cookie / api_key / password matchers above are
  // key-prefix-anchored and don't catch a bare base32 literal living in a
  // `var X = "…"` assignment.
  [/\b(?=[A-Z2-7]*[2-7])[A-Z2-7]{16,256}={0,6}\b/g, '[REDACTED_BASE32]'],
];

export function redactCredentials(input: string | null | undefined): string | null {
  if (input == null) return null;
  let out = input;
  for (const [re, replacement] of REDACTION_PATTERNS) {
    out = out.replace(re, replacement);
  }
  return out;
}

// ---------------------------------------------------------------------------
// ZAP JSON parser
// ---------------------------------------------------------------------------

interface ZapInstance {
  uri?: string;
  method?: string;
  attack?: string;
  evidence?: string;
  param?: string;
}

interface ZapAlert {
  alert?: string;
  name?: string;
  riskcode?: string;
  confidence?: string;
  cweid?: string;
  wascid?: string;
  alertRef?: string;
  pluginid?: string;
  desc?: string;
  instances?: ZapInstance[];
}

interface ZapSite {
  '@name'?: string;
  alerts?: ZapAlert[];
}

interface ZapReport {
  site?: ZapSite[];
}

const RISK_CODE_TO_SEVERITY: Record<string, DastFindingRaw['severity']> = {
  '0': 'info',
  '1': 'low',
  '2': 'medium',
  '3': 'high',
  '4': 'critical',
};

const CONFIDENCE_TO_LABEL: Record<string, DastFindingRaw['confidence']> = {
  '1': 'low',
  '2': 'medium',
  '3': 'high',
  '4': 'confirmed',
};

export function owaspRefForCwe(cweId: string | null): string | null {
  if (!cweId) return null;
  // Coarse OWASP Top 10 2021 mapping covering the most common ZAP rule classes.
  const cweNum = parseInt(cweId, 10);
  if (Number.isNaN(cweNum)) return null;
  if ([89, 90, 564, 78, 77, 917].includes(cweNum)) return 'A03:2021';
  if ([79, 116, 80].includes(cweNum)) return 'A03:2021';
  if ([287, 290, 798, 521, 522, 384].includes(cweNum)) return 'A07:2021';
  if ([200, 201, 209, 532, 538].includes(cweNum)) return 'A04:2021';
  if ([285, 639, 22, 23, 35].includes(cweNum)) return 'A01:2021';
  if ([311, 312, 327, 328, 916].includes(cweNum)) return 'A02:2021';
  if ([352].includes(cweNum)) return 'A01:2021';
  if ([502].includes(cweNum)) return 'A08:2021';
  if ([601].includes(cweNum)) return 'A10:2021';
  return null;
}

export function parseZapReport(report: ZapReport): DastFindingRaw[] {
  const out: DastFindingRaw[] = [];
  for (const site of report.site ?? []) {
    for (const alert of site.alerts ?? []) {
      const severity = RISK_CODE_TO_SEVERITY[alert.riskcode ?? '0'] ?? 'info';
      const confidence = CONFIDENCE_TO_LABEL[alert.confidence ?? '2'] ?? 'medium';
      const cwe = alert.cweid && alert.cweid !== '-1' ? alert.cweid : null;

      const instances = alert.instances ?? [];
      if (instances.length === 0) {
        // Some ZAP rules emit alert-level only with no instances; record once.
        out.push({
          endpoint_url: site['@name'] ?? '',
          http_method: 'GET',
          vulnerability_type: alert.name ?? alert.alert ?? 'Unknown',
          severity,
          cwe_id: cwe,
          owasp_top10_ref: owaspRefForCwe(cwe),
          rule_id: alert.alertRef ?? alert.pluginid ?? null,
          message: alert.desc ?? null,
          payload_redacted: null,
          response_evidence_redacted: null,
          confidence,
        });
        continue;
      }

      for (const inst of instances) {
        out.push({
          endpoint_url: inst.uri ?? site['@name'] ?? '',
          http_method: (inst.method ?? 'GET').toUpperCase(),
          vulnerability_type: alert.name ?? alert.alert ?? 'Unknown',
          severity,
          cwe_id: cwe,
          owasp_top10_ref: owaspRefForCwe(cwe),
          rule_id: alert.alertRef ?? alert.pluginid ?? null,
          message: alert.desc ?? null,
          payload_redacted: redactCredentials(inst.attack ?? null),
          response_evidence_redacted: redactCredentials(inst.evidence ?? null),
          confidence,
        });
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Default scan timeout — single source of truth shared with pipeline.ts.
// ---------------------------------------------------------------------------

export const ZAP_DEFAULT_TIMEOUT_MS = 30 * 60_000; // 30 min

// ---------------------------------------------------------------------------
// v2.1d — Recorded-login diagnostic parser
// ---------------------------------------------------------------------------

import type { RecordedStepAction } from './auth-config';

/** Mirror of backend/src/types/dast.ts — fields the parser populates. */
export interface FailedAtStepRaw {
  step_index: number;
  action: RecordedStepAction;
  selector?: string;
  reason:
    | 'selector_not_visible_after_timeout'
    | 'cross_origin_blocked'
    | 'totp_generation_failed'
    | 'browser_crashed'
    | 'logged_in_indicator_missed'
    | 'logged_out_indicator_present_after_login'
    | 'unknown';
  detail?: string;
  dom_excerpt?: string;
}

export interface DastLoginTestResultRaw {
  success: boolean;
  duration_ms: number;
  steps_run: number;
  step_index?: number;
  failed_at_step?: FailedAtStepRaw;
  raw_log?: string;
}

/**
 * Subset of ZAP's `auth-report-json` report template we read. The shape
 * was captured empirically against ZAP 2.17.0 + authhelper v0.39.0; the
 * fixture corpus lives at depscanner/test/fixtures/zap-login-diagnostics/.
 *
 * - `summaryItems[]` — per-check pass/fail. The load-bearing entry is
 *   `key === 'auth.summary.auth'`; everything else is informational.
 * - `failureReasons[]` — keyed reasons (e.g. `auth.failure.logged_in`),
 *   present when summaryItems.auth.passed is false.
 * - `afPlanErrors[]` — present when the AF YAML itself failed to parse /
 *   couldn't reach a job (distinct from auth-method failures).
 */
export interface ZapAuthReport {
  summaryItems?: Array<{ key?: string; description?: string; passed?: boolean }>;
  failureReasons?: Array<{ key?: string; description?: string }>;
  afPlanErrors?: Array<{ description?: string } | string>;
  afEnv?: string;
  statistics?: Array<{ key?: string; value?: number }>;
}

// Maps ZAP's `auth.failure.*` keys to our reason enum. Empirically captured;
// best-effort across ZAP versions. Anything unmapped → 'unknown' + raw_log.
const FAILURE_KEY_TO_REASON: Record<string, FailedAtStepRaw['reason']> = {
  'auth.failure.logged_in': 'logged_in_indicator_missed',
  'auth.failure.logged_out': 'logged_out_indicator_present_after_login',
  // ZAP exposes username/password field-identification failures via
  // summaryItems[auth.summary.username|password], but the discriminator
  // for the *failure* surfaces here. Map both to the selector-timeout
  // reason — the user's fix is the same (adjust the selector).
  'auth.failure.username': 'selector_not_visible_after_timeout',
  'auth.failure.password': 'selector_not_visible_after_timeout',
  // 'auth.failure.no_successful_logins' is a roll-up of the more
  // specific reasons; we intentionally don't map it as the primary cause
  // because the next entry in failureReasons[] is more actionable.
};

const SUMMARY_AUTH_KEY = 'auth.summary.auth';

/**
 * Parse ZAP's `auth-report-json` report template into a structured
 * DastLoginTestResultRaw. The empirical v2.1d spike against ZAP 2.17.0 +
 * authhelper v0.39.0 confirmed this is the ONLY structured signal — ZAP
 * does NOT emit per-step success/failure events on stderr/stdout/zap.log.
 *
 * `step_index` is always 0 on failure: ZAP doesn't tell us which step
 * failed (it just exposes a roll-up verdict per check). The
 * `internalIndexToZapIndex[]` plumbing on the build-side is retained as
 * informational metadata but no longer drives parser output.
 *
 * Every string field in the output is redacted via redactCredentials() so
 * a diagnostic that accidentally echoes a credential can't leak it through
 * to the FE.
 */
export function parseZapLoginDiagnostics(
  authReportJson: unknown,
  durationMs = 0,
): DastLoginTestResultRaw {
  // Defensive coerce: callers might pass null when the file was missing
  // (ZAP crashed before emitting) or a parse error when the JSON is corrupt.
  if (authReportJson === null || authReportJson === undefined) {
    return {
      success: false,
      duration_ms: durationMs,
      steps_run: 0,
      failed_at_step: {
        step_index: 0,
        action: 'click',
        reason: 'browser_crashed',
        detail: 'ZAP auth-report.json was missing — likely a browser crash',
      },
    };
  }
  if (typeof authReportJson !== 'object') {
    return {
      success: false,
      duration_ms: durationMs,
      steps_run: 0,
      failed_at_step: {
        step_index: 0,
        action: 'click',
        reason: 'unknown',
        detail: 'ZAP auth-report payload was not a JSON object',
      },
    };
  }

  const report = authReportJson as ZapAuthReport;
  const summary = Array.isArray(report.summaryItems) ? report.summaryItems : [];
  const failures = Array.isArray(report.failureReasons) ? report.failureReasons : [];
  const planErrors = Array.isArray(report.afPlanErrors) ? report.afPlanErrors : [];

  // AF plan errors mean ZAP couldn't even run the auth method — distinct
  // from "auth method ran and failed verification". Surface as 'unknown'
  // with the first error as detail; raw_log carries the full set.
  if (planErrors.length > 0) {
    const first = planErrors[0];
    const detail =
      typeof first === 'string'
        ? first
        : typeof first === 'object' && first !== null && typeof first.description === 'string'
          ? first.description
          : 'AF plan error';
    return {
      success: false,
      duration_ms: durationMs,
      steps_run: 0,
      failed_at_step: {
        step_index: 0,
        action: 'click',
        reason: 'unknown',
        detail: redactCredentials(`AF plan error: ${detail}`) ?? undefined,
      },
      raw_log: redactCredentials(JSON.stringify(planErrors)) ?? undefined,
    };
  }

  const authItem = summary.find((s) => s?.key === SUMMARY_AUTH_KEY);
  const success = authItem?.passed === true;

  if (success) {
    return {
      success: true,
      duration_ms: durationMs,
      // ZAP doesn't expose a per-step success count — surface 0 (downstream
      // FE displays "Logged in" without counting steps).
      steps_run: 0,
    };
  }

  // Failure path — pick the first mapped failureReason. If none map (or
  // failureReasons[] is empty even though auth.passed=false), emit
  // 'unknown' with the first failure's description as detail.
  let reason: FailedAtStepRaw['reason'] = 'unknown';
  let detail: string | undefined;
  for (const f of failures) {
    if (!f?.key) continue;
    if (f.key === 'auth.failure.no_successful_logins') {
      // Roll-up; skip in favor of more specific entries.
      continue;
    }
    const mapped = FAILURE_KEY_TO_REASON[f.key];
    if (mapped) {
      reason = mapped;
      detail = f.description ?? f.key;
      break;
    }
  }
  if (reason === 'unknown' && failures.length > 0) {
    // No mapped key. Use first non-roll-up entry as detail.
    const first = failures.find((f) => f?.key !== 'auth.failure.no_successful_logins') ?? failures[0];
    detail = first?.description ?? first?.key;
  }

  // Cap raw_log at 8 KB so the JSONB column stays bounded; useful for FE
  // "view details" disclosure.
  const RAW_LOG_CAP = 8 * 1024;
  let rawLog: string | undefined;
  try {
    const serialized = JSON.stringify({ summaryItems: summary, failureReasons: failures });
    const redacted = redactCredentials(serialized) ?? '';
    rawLog = redacted.length > RAW_LOG_CAP ? redacted.slice(0, RAW_LOG_CAP) : redacted;
  } catch {
    /* noop */
  }

  return {
    success: false,
    duration_ms: durationMs,
    steps_run: 0,
    failed_at_step: {
      step_index: 0,
      // ZAP doesn't expose which step failed; surface 'click' as a placeholder
      // (the FE banner shows the reason as the actionable signal, not action).
      action: 'click',
      reason,
      detail: detail ? (redactCredentials(detail) ?? undefined) : undefined,
    },
    raw_log: rawLog,
  };
}
