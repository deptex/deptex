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

// Maps ZAP step types back to our action enum (inverse of auth-config's
// ACTION_TO_ZAP_TYPE). The `goto` action never appears in the ZAP log
// because it collapses into loginPageUrl during emit.
const ZAP_TYPE_TO_ACTION: Record<string, RecordedStepAction> = {
  CLICK: 'click',
  USERNAME: 'type_username',
  PASSWORD: 'type_password',
  TOTP_FIELD: 'type_totp',
  CUSTOM_FIELD: 'type_custom',
  WAIT: 'wait',
  RETURN: 'return',
  ESCAPE: 'escape',
};

// Map ZAP-reported failure phrases to our reason enum. These patterns are
// best-evidence — M0 Spike-3 captures real fixtures and the regex set is
// tightened then. Each pattern is intentionally loose so the parser stays
// useful across ZAP versions.
const REASON_PATTERNS: Array<[RegExp, FailedAtStepRaw['reason']]> = [
  [/(?:not\s+visible|element\s+not\s+found|timed?\s*out|timeout)/i, 'selector_not_visible_after_timeout'],
  [/(?:cross[-\s]?origin|navigation\s+blocked|out\s+of\s+scope)/i, 'cross_origin_blocked'],
  [/(?:totp|2FA|otp).*(?:gen|invalid|failed)/i, 'totp_generation_failed'],
  [/(?:browser\s+(?:crashed|died|exited)|webdriver\s+(?:disconnected|died))/i, 'browser_crashed'],
  [/(?:loggedin\s*regex.*(?:no\s+match|missed|did\s+not\s+match)|verification\s+failed)/i, 'logged_in_indicator_missed'],
  [/loggedout\s*regex.*match/i, 'logged_out_indicator_present_after_login'],
];

function detectReason(phrase: string): FailedAtStepRaw['reason'] {
  for (const [re, reason] of REASON_PATTERNS) {
    if (re.test(phrase)) return reason;
  }
  return 'unknown';
}

/**
 * Translate a ZAP-coordinate step index back into a UI-coordinate step index
 * using the mapping array produced by buildRecordedAuthForZap. Returns -1
 * (i.e. unknown) if no UI index maps to that ZAP step.
 */
function zapToUiIndex(zapIdx: number, internalIndexToZapIndex: number[]): number {
  for (let i = 0; i < internalIndexToZapIndex.length; i++) {
    if (internalIndexToZapIndex[i] === zapIdx) return i;
  }
  return -1;
}

/**
 * Parse a ZAP browser-auth `diagnostics: true` log into a structured
 * DastLoginTestResultRaw. Best-effort: looks for per-step success / failure
 * markers; falls back to `{success: false, raw_log}` when the log shape is
 * unrecognizable.
 *
 * The parser returns the FIRST replay's verdict on multi-replay logs
 * (Spike-2B mid-scan re-login interleave). Subsequent re-login failures are
 * surfaced via the existing `consecutive_lost_count` mechanism on
 * error_payload.kind='session_loss', not here.
 *
 * Every string field in the output is redacted via redactCredentials() so a
 * diagnostic that accidentally echoes a credential can't leak it through to
 * the FE.
 */
export function parseZapLoginDiagnostics(
  rawLog: string,
  internalIndexToZapIndex: number[],
  durationMs = 0,
): DastLoginTestResultRaw {
  if (typeof rawLog !== 'string' || rawLog.length === 0) {
    return {
      success: false,
      duration_ms: durationMs,
      steps_run: 0,
      failed_at_step: {
        step_index: 0,
        action: 'click',
        reason: 'unknown',
        detail: 'ZAP diagnostic log was empty',
      },
    };
  }

  const lines = rawLog.split(/\r?\n/);
  let stepsRun = 0;
  let firstFailure: { zapIdx: number; type?: string; selector?: string; phrase: string } | null = null;
  let sawSuccessMarker = false;
  let sawVerificationFail = false;
  let verificationPhrase = '';

  // Patterns are written defensively for several plausible ZAP log shapes;
  // they tolerate the actual format Spike-3 captures. We use SEPARATE regexes
  // for step-line detection vs type/selector extraction so optional-group
  // skipping doesn't drop the fields we need (a single mega-regex with
  // optional groups + non-greedy `.*?` lets the engine skip type/selector
  // captures when SUCCESS/FAILED is reachable without them).
  const STEP_LINE_RE =
    /(?:BrowserBased(?:Auth)?|Browser\s+auth|browser-?auth).*?step\s*#?(\d+).*?(SUCCESS|FAILED?|failure|success|completed|error)/i;
  const STEP_TYPE_RE = /type[=:]\s*([A-Za-z_]+)/i;
  const STEP_SELECTOR_RE = /selector[=:]?\s*([^\s,)]+)/i;
  const VERIFY_RE =
    /(?:verification\s+(failed|succeeded)|loggedin\s*regex\s*(no\s+match|matched|failed)|loggedout\s*regex\s*matched)/i;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const stepMatch = line.match(STEP_LINE_RE);
    if (stepMatch) {
      stepsRun++;
      const zapIdx = parseInt(stepMatch[1], 10);
      const typeMatch = line.match(STEP_TYPE_RE);
      const selMatch = line.match(STEP_SELECTOR_RE);
      const type = typeMatch?.[1]?.toUpperCase();
      const sel = selMatch?.[1];
      const verdict = (stepMatch[2] ?? '').toLowerCase();
      const failed = /^fail|error/.test(verdict);
      if (failed && firstFailure === null) {
        firstFailure = { zapIdx, type, selector: sel, phrase: line };
      } else if (!failed) {
        sawSuccessMarker = true;
      }
      continue;
    }

    const verifyMatch = line.match(VERIFY_RE);
    if (verifyMatch) {
      if (/(failed|no\s+match|loggedout\s*regex\s*matched)/i.test(line)) {
        sawVerificationFail = true;
        verificationPhrase = line;
      }
    }
  }

  if (firstFailure !== null) {
    const uiIdx = zapToUiIndex(firstFailure.zapIdx, internalIndexToZapIndex);
    const mapped =
      firstFailure.type && firstFailure.type.length > 0
        ? ZAP_TYPE_TO_ACTION[firstFailure.type]
        : undefined;
    const action: RecordedStepAction = mapped ?? 'click';
    return {
      success: false,
      duration_ms: durationMs,
      steps_run: stepsRun,
      step_index: uiIdx >= 0 ? uiIdx : firstFailure.zapIdx,
      failed_at_step: {
        step_index: uiIdx >= 0 ? uiIdx : firstFailure.zapIdx,
        action,
        selector: firstFailure.selector
          ? (redactCredentials(firstFailure.selector) ?? undefined)
          : undefined,
        reason: detectReason(firstFailure.phrase),
        detail: redactCredentials(firstFailure.phrase) ?? undefined,
      },
    };
  }

  if (sawVerificationFail) {
    return {
      success: false,
      duration_ms: durationMs,
      steps_run: stepsRun,
      failed_at_step: {
        step_index: stepsRun > 0 ? stepsRun - 1 : 0,
        action: 'click',
        reason:
          detectReason(verificationPhrase) === 'logged_out_indicator_present_after_login'
            ? 'logged_out_indicator_present_after_login'
            : 'logged_in_indicator_missed',
        detail: redactCredentials(verificationPhrase) ?? undefined,
      },
    };
  }

  if (sawSuccessMarker) {
    return {
      success: true,
      duration_ms: durationMs,
      steps_run: stepsRun,
    };
  }

  // Unstructured fallback — emit raw_log so a human can inspect via the UI.
  // Cap at 8 KB so the JSONB column stays bounded.
  const RAW_LOG_CAP = 8 * 1024;
  const redacted = redactCredentials(rawLog) ?? '';
  return {
    success: false,
    duration_ms: durationMs,
    steps_run: stepsRun,
    failed_at_step: {
      step_index: 0,
      action: 'click',
      reason: 'unknown',
      detail: 'ZAP diagnostic log was unstructured — see raw_log',
    },
    raw_log: redacted.length > RAW_LOG_CAP ? redacted.slice(0, RAW_LOG_CAP) : redacted,
  };
}
