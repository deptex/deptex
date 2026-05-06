// ZAP report parser + log scrub. Phase 23b/24a left this file holding three
// concerns; v2.1a hardening retired the helper-script + dual-runner dispatcher
// (runZap / runZapHelperScript / runZapAutomationFramework / pickRunnerMode /
// DAST_RUNNER_MODE) which were never reachable from production — the worker
// pipeline.ts has its own runZapWithControlPlane that spawns ZAP directly via
// the AF YAML path. With those gone the only surface left here is the bits
// pipeline.ts actually imports: types, redaction, ZAP JSON parsing.
//
// What remains:
//   - DastFindingRaw / DastScanProfile types
//   - REDACTION_PATTERNS + redactCredentials (called from pipeline.ts and
//     control-plane.ts to scrub stderr before it lands in Fly logs)
//   - parseZapReport (called from pipeline.ts to convert ZAP JSON → finding
//     rows; the redactCredentials step also happens here on payload/evidence)
//   - ZAP_DEFAULT_TIMEOUT_MS (re-exported for callers that need the wall-time)

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
  // Password assignments
  [/(?:password|passwd|pwd)["']?\s*[:=]\s*["']?[^\s"',}]+/gi, 'password=[REDACTED]'],
  // API key assignments
  [/(?:api[_-]?key|apikey|access[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{12,}/gi, 'api_key=[REDACTED]'],
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

function owaspRefForCwe(cweId: string | null): string | null {
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
