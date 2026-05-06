// Phase 23b PR 3: ZAP runner. Wraps the ZAP helper scripts with a Promise-based
// `child_process.spawn` invocation (NEVER `execSync` — heartbeat must survive a
// 25-minute scan; see plan Task 8 + `feedback_simplicity_bias`).
//
// Three profiles:
//   * 'quick' or 'auto'-without-routes → zap-baseline.py (~1-2 min, passive)
//   * 'auto'-with-routes               → zap-api-scan.py + synthesized OpenAPI
//   * 'full'                           → zap-full-scan.py (~20+ min, active)
//
// ZAP exit codes 1-2 mean "scan completed but findings were emitted" — we do
// NOT treat those as runner failures. Exit code 3+ is a real subprocess error.

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

import {
  buildAutomationYaml,
  type AfScanProfile,
  type DetectedRuntime,
  type ScopeConfig,
} from './yaml-builder';
import type { CredentialPayload, DastAuthStrategy } from './auth-config';

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

/** Subset of project_entry_points used to build the API-scan OpenAPI stub. */
export interface DastEntryPointInput {
  framework: string;
  http_method: string | null;
  route_pattern: string | null;
  handler_name: string | null;
}

export type DastScanProfile = 'auto' | 'quick' | 'full' | 'api';

export type DastRunnerMode = 'helper_script' | 'af';

export interface RunZapOptions {
  targetUrl: string;
  scanProfile: DastScanProfile;
  routes: DastEntryPointInput[];
  timeoutMs?: number;

  // v2.1a additions — only consumed by the AF dispatcher path. Optional so
  // existing callers (pipeline.ts at v1) compile unchanged.
  detectedRuntime?: DetectedRuntime;
  scope?: ScopeConfig;
  authStrategy?: DastAuthStrategy;
  authPayload?: CredentialPayload;
  loggedInIndicator?: string;
  loggedOutIndicator?: string;
  // Mode override for tests; production reads `DAST_RUNNER_MODE` env.
  runnerMode?: DastRunnerMode;
}

export interface RunZapResult {
  findings: DastFindingRaw[];
  scriptUsed: 'baseline' | 'full' | 'api' | 'af';
  exitCode: number | null;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Profile selection
// ---------------------------------------------------------------------------

export function selectScript(
  scanProfile: DastScanProfile,
  hasRoutes: boolean
): 'baseline' | 'full' | 'api' {
  if (scanProfile === 'full') return 'full';
  if (scanProfile === 'quick') return 'baseline';
  if (scanProfile === 'api') return 'api';
  // 'auto': API scan when we have route info, baseline otherwise.
  return hasRoutes ? 'api' : 'baseline';
}

// ---------------------------------------------------------------------------
// OpenAPI stub synthesis from project_entry_points
// ---------------------------------------------------------------------------

const SUPPORTED_HTTP_METHODS = new Set([
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'head',
  'options',
]);

/**
 * Convert a per-framework pattern into OpenAPI 3.0 path syntax.
 *
 * Express/Fastify/Sinatra `:id` → `{id}`. Rails/Gin `:id` and `*splat` → `{id}`
 * `{splat}`. FastAPI/Spring/Laravel `{id}` already match — we only strip `:type`
 * suffix and trailing `?`. Patterns from unsupported frameworks are returned
 * verbatim (best-effort; the API scan will skip them if ZAP refuses).
 */
export function patternToOpenApi(framework: string, pattern: string): string {
  const fw = framework.toLowerCase();
  let p = pattern;

  // Strip leading scheme+host if a full URL is supplied.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p)) {
    try {
      p = new URL(p).pathname || '/';
    } catch {
      // fall through
    }
  }

  if (fw === 'express' || fw === 'fastify' || fw === 'sinatra') {
    return p.replace(/:([A-Za-z0-9_]+)\??/g, '{$1}');
  }
  if (fw === 'rails') {
    p = p.replace(/\*([A-Za-z0-9_]+)/g, '{$1}');
    return p.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
  }
  if (fw === 'gin') {
    p = p.replace(/\*([A-Za-z0-9_]+)/g, '{$1}');
    return p.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
  }
  if (fw === 'fastapi' || fw === 'spring' || fw === 'laravel') {
    // {name:type} → {name}, {name?} → {name}
    return p.replace(/\{([A-Za-z0-9_]+)(?::[^}]+)?\??\}/g, '{$1}');
  }
  return p;
}

export function buildOpenApiStub(
  targetUrl: string,
  routes: DastEntryPointInput[]
): Record<string, unknown> {
  const url = new URL(targetUrl);
  const serverUrl = `${url.protocol}//${url.host}`;

  // Group routes by canonical path → method → minimal Operation object.
  const paths: Record<string, Record<string, unknown>> = {};
  for (const r of routes) {
    if (!r.route_pattern || !r.http_method) continue;
    const method = r.http_method.toLowerCase();
    if (!SUPPORTED_HTTP_METHODS.has(method)) continue;
    const oasPath = patternToOpenApi(r.framework, r.route_pattern);
    if (!oasPath.startsWith('/')) continue;

    if (!paths[oasPath]) paths[oasPath] = {};
    if (paths[oasPath][method]) continue; // first wins

    // Extract path params from `{name}` segments.
    const params: Array<Record<string, unknown>> = [];
    const matched = oasPath.matchAll(/\{([A-Za-z0-9_]+)\}/g);
    for (const m of matched) {
      params.push({
        name: m[1],
        in: 'path',
        required: true,
        schema: { type: 'string' },
      });
    }

    paths[oasPath][method] = {
      summary: r.handler_name ?? `${method.toUpperCase()} ${oasPath}`,
      ...(params.length > 0 ? { parameters: params } : {}),
      responses: {
        '200': { description: 'OK' },
      },
    };
  }

  return {
    openapi: '3.0.0',
    info: { title: 'Deptex DAST synthesized API', version: '1.0' },
    servers: [{ url: serverUrl }],
    paths,
  };
}

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
  // credentials are emitted by ZAP as `Cookie: session=...; csrf=...` when
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
// spawn wrapper (NEVER execSync — heartbeat must keep ticking during a 25-min
// scan; see `feedback_simplicity_bias` and plan Task 8 acceptance).
// ---------------------------------------------------------------------------

export interface SpawnResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export function spawnZap(
  command: string,
  args: string[],
  timeoutMs: number,
  onStderr?: (chunk: string) => void
): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      // Force kill 10s after SIGTERM if ZAP refuses.
      setTimeout(() => {
        if (!child.killed) child.kill('SIGKILL');
      }, 10_000).unref();
    }, timeoutMs);

    child.stdout?.on('data', (b: Buffer) => {
      stdout += b.toString('utf-8');
    });
    child.stderr?.on('data', (b: Buffer) => {
      const s = b.toString('utf-8');
      stderr += s;
      onStderr?.(s);
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error(`ZAP scan timed out after ${timeoutMs}ms (SIGTERM sent)`));
        return;
      }
      resolve({ exitCode: code, stdout, stderr });
    });
  });
}

// ---------------------------------------------------------------------------
// Public entry point — DUAL dispatcher (helper-script vs AF YAML)
// ---------------------------------------------------------------------------

export const ZAP_DEFAULT_TIMEOUT_MS = 30 * 60_000; // 30 min

/**
 * Resolve the runner mode for a given env value. Exported so unit tests can
 * exercise the parser without touching `process.env`.
 *
 *   'af'              → AF YAML (zap.sh -cmd -autorun)
 *   'helper_script'   → existing baseline / full / api helper scripts
 *   anything else     → 'helper_script' (default for v2.1a; flips to 'af' in
 *                       v2.1b when AF mode hits parity in production)
 */
export function pickRunnerMode(envValue: string | undefined | null): DastRunnerMode {
  if (typeof envValue === 'string' && envValue.trim().toLowerCase() === 'af') {
    return 'af';
  }
  return 'helper_script';
}

/**
 * Top-level entry. Dispatches to either the helper-script path (v1, default)
 * or the new AF YAML path. The api-scan profile is always served by the
 * helper-script path because the AF YAML schema doesn't have a clean OpenAPI
 * stub equivalent — that's a deliberate v2.1a boundary.
 */
export async function runZap(opts: RunZapOptions): Promise<RunZapResult> {
  const mode = opts.runnerMode ?? pickRunnerMode(process.env.DAST_RUNNER_MODE);
  if (mode === 'af' && opts.scanProfile !== 'api') {
    return runZapAutomationFramework(opts);
  }
  return runZapHelperScript(opts);
}

async function runZapHelperScript(opts: RunZapOptions): Promise<RunZapResult> {
  const startedAt = Date.now();
  const timeoutMs = opts.timeoutMs ?? ZAP_DEFAULT_TIMEOUT_MS;
  const script = selectScript(opts.scanProfile, opts.routes.length > 0);

  // ZAP helpers refuse any `-J / -t / -c / -g` path outside `/zap/wrk` when
  // running inside a Docker container (zap-baseline.py:374). We always run
  // inside the depscanner image at scan time, so default to /zap/wrk; allow
  // override for local dev where the dir doesn't exist.
  const zapWorkDir = process.env.DAST_WORK_DIR || '/zap/wrk';
  const tmpDir = fs.mkdtempSync(path.join(zapWorkDir, 'deptex-dast-'));
  const reportPath = path.join(tmpDir, 'zap-report.json');

  // ZAP's Automation Framework joins `reportDir` (= /zap/wrk) with whatever we
  // pass via -J, even when -J is absolute, producing /zap/wrk/zap/wrk/... and
  // failing the report write. Pass paths *relative to* /zap/wrk for any flag
  // that gets routed through the AF report job (`-J`) or the AF input file
  // resolver (`-t openapi.json`).
  const reportArg = path.relative(zapWorkDir, reportPath);

  let args: string[];
  let cleanup: (() => void) | null = null;

  if (script === 'api') {
    const stub = buildOpenApiStub(opts.targetUrl, opts.routes);
    const stubPath = path.join(tmpDir, 'openapi.json');
    fs.writeFileSync(stubPath, JSON.stringify(stub));
    const stubArg = path.relative(zapWorkDir, stubPath);
    args = [
      '-t', stubArg,
      '-f', 'openapi',
      '-J', reportArg,
      '-I', // do not return non-zero on warn/fail
    ];
    cleanup = () => {
      try { fs.unlinkSync(stubPath); } catch { /* noop */ }
    };
  } else if (script === 'full') {
    args = [
      '-t', opts.targetUrl,
      '-J', reportArg,
      '-I',
    ];
  } else {
    // baseline
    args = [
      '-t', opts.targetUrl,
      '-J', reportArg,
      '-I',
    ];
  }

  const command = `/zap/zap-${script === 'baseline' ? 'baseline' : script === 'full' ? 'full-scan' : 'api-scan'}.py`;

  let result: SpawnResult;
  try {
    result = await spawnZap(command, args, timeoutMs, (chunk) => {
      // Stream stderr to console for ops visibility; scrub credentials before
      // anything lands in the log.
      process.stderr.write(`[zap] ${redactCredentials(chunk)}`);
    });
  } finally {
    cleanup?.();
  }

  // Exit code 0 = clean, 1 = at least one FAIL rule, 2 = at least one WARN rule.
  // 1 + 2 are normal scan completions with findings — do NOT throw.
  // Any other code (3+, null from kill) is a runner-level failure.
  if (result.exitCode !== 0 && result.exitCode !== 1 && result.exitCode !== 2) {
    const tail = result.stderr.slice(-2_000);
    throw new Error(
      `ZAP ${script} exited with code ${result.exitCode}. stderr tail: ${redactCredentials(tail)}`
    );
  }

  if (!fs.existsSync(reportPath)) {
    throw new Error(`ZAP ${script} produced no report at ${reportPath}`);
  }

  const reportRaw = fs.readFileSync(reportPath, 'utf-8');
  let report: ZapReport;
  try {
    report = JSON.parse(reportRaw);
  } catch (e) {
    throw new Error(`Failed to parse ZAP JSON report: ${(e as Error).message}`);
  }

  try { fs.unlinkSync(reportPath); } catch { /* noop */ }
  try { fs.rmdirSync(tmpDir); } catch { /* noop */ }

  return {
    findings: parseZapReport(report),
    scriptUsed: script,
    exitCode: result.exitCode,
    durationMs: Date.now() - startedAt,
  };
}

// ---------------------------------------------------------------------------
// AF YAML path (v2.1a) — invoked when DAST_RUNNER_MODE=af
// ---------------------------------------------------------------------------

/**
 * Map a v1 DastScanProfile to the AF builder's narrower profile set.
 * `api` is intentionally rejected — runZap routes it to the helper-script
 * path before reaching this function.
 */
function toAfProfile(p: DastScanProfile): AfScanProfile {
  if (p === 'api') {
    throw new Error('runZapAutomationFramework: api profile uses helper-script path');
  }
  return p;
}

async function runZapAutomationFramework(opts: RunZapOptions): Promise<RunZapResult> {
  const startedAt = Date.now();
  const timeoutMs = opts.timeoutMs ?? ZAP_DEFAULT_TIMEOUT_MS;

  const zapWorkDir = process.env.DAST_WORK_DIR || '/zap/wrk';
  const tmpDir = fs.mkdtempSync(path.join(zapWorkDir, 'deptex-dast-af-'));
  const yamlPath = path.join(tmpDir, 'automation.yaml');
  const reportPath = path.join(tmpDir, 'zap-report.json');
  // Report path inside the AF YAML must be relative to /zap/wrk (same caveat
  // as the helper-script -J flag — AF joins reportDir+reportFile).
  const reportRelativePath = path.relative(zapWorkDir, reportPath);

  const yamlText = buildAutomationYaml({
    targetUrl: opts.targetUrl,
    scanProfile: toAfProfile(opts.scanProfile),
    detectedRuntime: opts.detectedRuntime ?? 'unknown',
    reportRelativePath,
    scope: opts.scope,
    authStrategy: opts.authStrategy,
    authPayload: opts.authPayload,
    loggedInIndicator: opts.loggedInIndicator,
    loggedOutIndicator: opts.loggedOutIndicator,
    scanTimeoutMinutes: Math.round(timeoutMs / 60_000),
  });
  fs.writeFileSync(yamlPath, yamlText, 'utf-8');

  let result: SpawnResult;
  try {
    result = await spawnZap(
      '/zap/zap.sh',
      ['-cmd', '-autorun', yamlPath],
      timeoutMs,
      (chunk) => {
        process.stderr.write(`[zap-af] ${redactCredentials(chunk)}`);
      },
    );
  } finally {
    // Drop the YAML even on failure — it can contain plaintext credentials
    // (form auth context.users[].credentials). The subprocess has already
    // read it; keeping it on disk is unnecessary risk.
    try { fs.unlinkSync(yamlPath); } catch { /* noop */ }
  }

  if (result.exitCode !== 0 && result.exitCode !== 1 && result.exitCode !== 2) {
    const tail = result.stderr.slice(-2_000);
    throw new Error(
      `ZAP AF exited with code ${result.exitCode}. stderr tail: ${redactCredentials(tail)}`,
    );
  }

  if (!fs.existsSync(reportPath)) {
    throw new Error(`ZAP AF produced no report at ${reportPath}`);
  }

  const reportRaw = fs.readFileSync(reportPath, 'utf-8');
  let report: ZapReport;
  try {
    report = JSON.parse(reportRaw);
  } catch (e) {
    throw new Error(`Failed to parse ZAP AF JSON report: ${(e as Error).message}`);
  }

  try { fs.unlinkSync(reportPath); } catch { /* noop */ }
  try { fs.rmdirSync(tmpDir); } catch { /* noop */ }

  return {
    findings: parseZapReport(report),
    scriptUsed: 'af',
    exitCode: result.exitCode,
    durationMs: Date.now() - startedAt,
  };
}
