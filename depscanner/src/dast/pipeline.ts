// Phase 24a (v2.1a): DAST pipeline rewrite.
//
// New flow:
//
//   1. Resolve target_id (NULL → first target row by created_at; legacy v1
//      pathway during shadow window).
//   2. Tenant-guard: SELECT target + project + scan_jobs in parallel; assert
//      all three organization_id values match. Abort with
//      `error_category='tenant_drift_detected'` BEFORE any decrypt if not.
//   3. Credential load: if target.has_credentials=true,
//        a. assert isDastEncryptionConfigured() — abort with
//           `error_category='dast_credential_key_missing'` if not.
//        b. assert credential row's encrypted_payload SHA-256 matches the
//           credential_payload_hash captured at queue time — abort with
//           `error_category='dast_credential_rotated'` if not.
//        c. decrypt; on failure (current+previous key both rejected), abort
//           with `error_category='dast_credential_key_stale'`.
//      The pipeline NEVER falls back to anonymous when has_credentials=true
//      (non-negotiable invariant — see plan §Task 7).
//   4. Build AF YAML (form auth → context.users; jwt/cookie → replacer).
//   5. Spawn ZAP via control-plane.spawnExternal — pipeline holds the abort
//      handle and triggers it on (a) cancellation poll between phases,
//      (b) auth-lost watcher reaching threshold, (c) scan timeout.
//   6. Plaintext credential buffer is zeroed via Buffer.fill(0) IMMEDIATELY
//      after the YAML is written to disk; YAML itself is unlinked after
//      spawn (success or failure).
//   7. Parse report → cross-link to SCA findings → atomic-commit via the
//      target-scoped commit_dast_target_run RPC.
//
// `auth_state` populated on every finding:
//   * 'authenticated'        — cred loaded, watcher never tripped threshold
//   * 'authentication_lost'  — watcher tripped during the run; findings
//                              collected before the trip stay 'authenticated'
//                              and findings collected after stay
//                              'authentication_lost' (per-finding tag, not a
//                              synthetic finding row)
//   * 'anonymous'            — no credential

import { randomUUID, createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  decryptCredential,
  isDastEncryptionConfigured,
  DastCredentialFormatError,
} from './encryption';
import { validateScanTimeHost } from '../scanners/host-guard';
import type { Storage } from '../storage';
import type { ExtractionJobRow } from '../job-db';
import { isJobCancelled, sendHeartbeat } from '../job-db';
import {
  buildAutomationYaml,
  type AfScanProfile,
  type DetectedRuntime,
  type ScopeConfig,
} from './yaml-builder';
import {
  buildAuthForStrategy,
  buildNucleiAuthHeaders,
  UnsupportedAuthStrategyError,
  InvalidCredentialCharacterError,
  type CredentialPayload,
  type DastAuthStrategy,
} from './auth-config';
import {
  parseZapReport,
  redactCredentials,
  ZAP_DEFAULT_TIMEOUT_MS,
  type DastFindingRaw,
  type DastScanProfile,
} from './runner';
import { runNuclei } from './nuclei-runner';
import { confirmPdvsFromDastRun } from './cross-link-cve';
import {
  spawnExternal,
  createAuthLostWatcher,
  type SpawnExternalHandle,
} from './control-plane';
import {
  crossLinkFinding,
  getActiveExtractionRunId,
  loadEntryPoints,
  loadPdvsForProject,
  loadReachableFlows,
  type EntryPointRow,
  type PdvRow,
  type ProjectDependencyRow,
  type ReachableFlowRow,
} from './cross-link';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

interface DastJobPayload {
  target_url?: string;
  scan_profile?: DastScanProfile;
  scan_timeout_minutes?: number;
}

export type DastAuthState = 'anonymous' | 'authenticated' | 'authentication_lost';

interface ScanJobRow {
  id: string;
  organization_id: string;
  project_id: string;
  target_id: string | null;
  credential_id: string | null;
  credential_payload_hash: string | null;
}

interface TargetRow {
  id: string;
  project_id: string;
  organization_id: string;
  target_url: string;
  detected_runtime: DetectedRuntime;
  enabled: boolean;
}

interface CredentialRow {
  id: string;
  target_id: string;
  organization_id: string;
  auth_strategy: DastAuthStrategy;
  encrypted_payload: string;
  encryption_key_version: number;
  logged_in_indicator: string | null;
  logged_out_indicator: string | null;
}

interface ProjectRow {
  id: string;
  organization_id: string;
}

// Stored scope_config shape (DB JSONB). Validated route-side via
// validateScopeConfig — keys are include_patterns / exclude_patterns /
// header_rules (NOT camelCase). The yaml-builder takes the camelCase shape;
// loadScopeConfig() does the rename on the way through the pipeline.
interface StoredScopeConfig {
  include_patterns?: unknown;
  exclude_patterns?: unknown;
  header_rules?: unknown;
}

interface DastFindingInsert {
  project_id: string;
  organization_id: string;
  target_id: string;
  dast_run_id: string;
  endpoint_url: string;
  http_method: string;
  vulnerability_type: string;
  severity: DastFindingRaw['severity'];
  cwe_id: string | null;
  owasp_top10_ref: string | null;
  rule_id: string | null;
  message: string | null;
  payload_redacted: string | null;
  response_evidence_redacted: string | null;
  confidence: DastFindingRaw['confidence'];
  handler_file_path: string | null;
  handler_function_name: string | null;
  handler_line: number | null;
  linked_sca_osv_id: string | null;
  linked_sca_project_dependency_id: string | null;
  cross_link_metadata: Record<string, unknown>;
  auth_state: DastAuthState;
  engine: 'zap' | 'nuclei';
  /** CISA Known-Exploited flag — always false for ZAP, tag-derived for Nuclei. */
  kev: boolean;
  status: 'open';
}

export type DastErrorCategory =
  | 'tenant_drift_detected'
  | 'dast_credential_key_missing'
  | 'dast_credential_key_stale'
  | 'dast_credential_rotated'
  | 'ssrf_blocked'
  | 'auth_failed'
  | 'timeout'
  | 'engine_crash'
  | 'unknown';

export class DastPipelineAbortError extends Error {
  constructor(
    public errorCategory: DastErrorCategory,
    public errorPayload: Record<string, unknown> | null,
    message: string,
  ) {
    super(message);
    this.name = 'DastPipelineAbortError';
  }
}

export interface RunDastPipelineOptions {
  /** Test seam — substitute the spawn implementation. */
  spawnImpl?: typeof import('child_process').spawn;
  /** Test seam — override the work dir; production uses /zap/wrk. */
  zapWorkDir?: string;
  /** Test seam — override the cancellation poll interval. */
  cancellationPollMs?: number;
}

export interface DastPipelineResult {
  dast_run_id: string;
  findings_count: number;
  duration_seconds: number;
  cross_linked_count: number;
  auth_state_summary: DastAuthState;
  /** PDV rows flipped to 'confirmed' by the Nuclei runtime-confirmation batch. */
  runtime_confirmed_count: number;
}

// ---------------------------------------------------------------------------
// Tenant guard
// ---------------------------------------------------------------------------

interface TenantGuardLoad {
  scanJob: ScanJobRow;
  target: TargetRow;
  project: ProjectRow;
}

async function loadTenantGuardRows(
  supabase: Storage,
  jobId: string,
  callerOrgId: string,
): Promise<TenantGuardLoad> {
  const { data: jobData, error: jobErr } = await supabase
    .from('scan_jobs')
    .select('id, organization_id, project_id, target_id, credential_id, credential_payload_hash')
    .eq('id', jobId)
    .single();
  if (jobErr || !jobData) {
    throw new DastPipelineAbortError(
      'unknown',
      { stage: 'load_scan_job' },
      `Failed to load scan_jobs row: ${jobErr?.message ?? 'not found'}`,
    );
  }
  const scanJob = jobData as ScanJobRow;

  // Resolve target_id during the shadow window. Phase 24b drops the NULL path.
  let targetId = scanJob.target_id;
  if (!targetId) {
    const { data: legacyTarget } = await supabase
      .from('project_dast_targets')
      .select('id')
      .eq('project_id', scanJob.project_id)
      .limit(1)
      .single();
    targetId = (legacyTarget as { id?: string } | null)?.id ?? null;
  }
  if (!targetId) {
    throw new DastPipelineAbortError(
      'unknown',
      { stage: 'resolve_target_id', project_id: scanJob.project_id },
      'No DAST target row found for this project',
    );
  }

  const [{ data: targetData, error: targetErr }, { data: projectData, error: projectErr }] =
    await Promise.all([
      supabase
        .from('project_dast_targets')
        .select('id, project_id, organization_id, target_url, detected_runtime, enabled')
        .eq('id', targetId)
        .single(),
      supabase
        .from('projects')
        .select('id, organization_id')
        .eq('id', scanJob.project_id)
        .single(),
    ]);
  if (targetErr || !targetData) {
    throw new DastPipelineAbortError(
      'unknown',
      { stage: 'load_target' },
      `Failed to load target row: ${targetErr?.message ?? 'not found'}`,
    );
  }
  if (projectErr || !projectData) {
    throw new DastPipelineAbortError(
      'unknown',
      { stage: 'load_project' },
      `Failed to load project row: ${projectErr?.message ?? 'not found'}`,
    );
  }

  const target = targetData as TargetRow;
  const project = projectData as ProjectRow;

  // Tenant-drift assertion. ALL THREE org ids must match. The route layer
  // (loadTargetOrDeny) and the queue_scan_job RPC already enforce this; the
  // worker check is defense-in-depth against TOCTOU races.
  if (
    target.organization_id !== callerOrgId ||
    project.organization_id !== callerOrgId ||
    scanJob.organization_id !== callerOrgId ||
    target.project_id !== scanJob.project_id
  ) {
    throw new DastPipelineAbortError(
      'tenant_drift_detected',
      {
        // Don't surface foreign org ids — leaking them would defeat the point.
        expected_org_id: callerOrgId,
        expected_project_id: scanJob.project_id,
      },
      'tenant drift detected between scan_jobs / project_dast_targets / projects',
    );
  }

  return { scanJob, target, project };
}

// ---------------------------------------------------------------------------
// Credential load
// ---------------------------------------------------------------------------

interface LoadedCredential {
  credentialRow: CredentialRow;
  payload: CredentialPayload;
}

async function loadCredentialOrAbort(
  supabase: Storage,
  scanJob: ScanJobRow,
  target: TargetRow,
): Promise<LoadedCredential | null> {
  const { data: credData, error: credErr } = await supabase
    .from('project_dast_credentials')
    .select(
      'id, target_id, organization_id, auth_strategy, encrypted_payload, encryption_key_version, logged_in_indicator, logged_out_indicator',
    )
    .eq('target_id', target.id)
    .maybeSingle();

  if (credErr) {
    // Transient Supabase failure — never fall through to anonymous, because an
    // authenticated scan may have been expected (scan_jobs.credential_id was
    // captured at queue time and the operator typed credentials). Hard-abort
    // so the run is retried instead of silently scanning unauthenticated.
    throw new DastPipelineAbortError(
      'unknown',
      { stage: 'load_credential' },
      `Failed to load credential row: ${credErr.message ?? 'unknown error'}`,
    );
  }

  if (!credData) {
    // Missing row. If scan_jobs.credential_id was captured at queue time, the
    // row was rotated/deleted between queue and worker — hard abort. Without
    // a captured credential_id, this scan was queued anonymous, which is OK.
    if (scanJob.credential_id) {
      throw new DastPipelineAbortError(
        'dast_credential_rotated',
        { credential_id_at_queue: scanJob.credential_id },
        'credential row missing — was rotated or deleted between queue time and worker spawn',
      );
    }
    return null;
  }
  const credRow = credData as CredentialRow;

  // Cross-tenant defense-in-depth: the credential row's organization_id MUST
  // match the target's organization_id. Worker uses service-role and bypasses
  // RLS, so a credential row whose organization_id has drifted from its
  // target (DB corruption, race during target re-parenting, RLS-bypassing
  // INSERT) would otherwise get decrypted and emitted into ZAP YAML for a
  // foreign-tenant scan. The 3-layer guard at loadTenantGuardRows above only
  // covers (scan_jobs, project, target) — credentials need their own check.
  if (credRow.organization_id !== target.organization_id) {
    throw new DastPipelineAbortError(
      'tenant_drift_detected',
      {
        stage: 'credential_org_mismatch',
        expected_org_id: target.organization_id,
      },
      'credential row organization_id does not match target organization_id',
    );
  }

  // Defense-in-depth: target row didn't say has_credentials but a row exists.
  // Run the credentialed scan anyway — scan_jobs.credential_id captured at
  // queue time is the source of truth for "this run was supposed to be auth'd".
  if (scanJob.credential_id && scanJob.credential_id !== credRow.id) {
    throw new DastPipelineAbortError(
      'dast_credential_rotated',
      { credential_id_at_queue: scanJob.credential_id, credential_id_now: credRow.id },
      'credential row was replaced between queue time and worker spawn',
    );
  }

  // Compare credential_payload_hash captured at queue time.
  const currentHash = createHash('sha256').update(credRow.encrypted_payload).digest('hex');
  if (scanJob.credential_payload_hash && scanJob.credential_payload_hash !== currentHash) {
    throw new DastPipelineAbortError(
      'dast_credential_rotated',
      { hash_at_queue: scanJob.credential_payload_hash, hash_now: currentHash },
      'credential payload was rotated between queue time and worker spawn',
    );
  }

  if (!isDastEncryptionConfigured()) {
    throw new DastPipelineAbortError(
      'dast_credential_key_missing',
      { key_version_attempted: credRow.encryption_key_version },
      'DAST_CREDENTIAL_KEY not configured but credential row exists',
    );
  }

  let plaintext: string;
  try {
    plaintext = decryptCredential(credRow.encrypted_payload, credRow.encryption_key_version);
  } catch (e) {
    if (e instanceof DastCredentialFormatError) {
      // Structurally corrupt credential / misconfigured key — NOT a stale-key
      // rotation problem. Report it as a distinct engine_crash so the operator
      // doesn't waste time rotating keys that are actually fine.
      console.error('[dast-pipeline] credential decrypt format error:', e.message);
      throw new DastPipelineAbortError(
        'engine_crash',
        { stage: 'credential_decrypt', key_version_attempted: credRow.encryption_key_version },
        'DAST credential could not be decrypted (corrupt credential or misconfigured key)',
      );
    }
    throw new DastPipelineAbortError(
      'dast_credential_key_stale',
      { key_version_attempted: credRow.encryption_key_version },
      `Credential decrypt failed under current+previous keys: ${(e as Error).message}`,
    );
  }

  let payload: CredentialPayload;
  try {
    payload = JSON.parse(plaintext) as CredentialPayload;
  } catch (e) {
    // Generic message — Node's JSON.parse errors embed an excerpt of the
    // input, and at this stage `plaintext` is the user's decrypted credential
    // payload. Surfacing the raw error to scan_jobs.error_payload would leak
    // ~11 chars of credential plaintext into a column that may be displayed
    // to other org members in the UI.
    // eslint-disable-next-line no-console
    console.error('[dast-pipeline] credential payload JSON malformed:', (e as Error).message);
    throw new DastPipelineAbortError(
      'dast_credential_key_stale',
      null,
      'credential payload is not valid JSON (try rotating credentials)',
    );
  }

  return { credentialRow: credRow, payload };
}

// ---------------------------------------------------------------------------
// Scope config load (project_dast_config.scope_config → ScopeConfig)
// ---------------------------------------------------------------------------

// Heuristic ReDoS guard. safe-regex2 is a backend dependency but not a
// depscanner one, so we replicate its core check: reject a pattern with
// nested quantifiers (a quantified group/char-class that is itself inside
// another quantifier), which is the catastrophic-backtracking shape. Also
// rejects patterns that fail to compile and absurdly long patterns. This is
// defense-in-depth — the route layer already runs full safe-regex2.
const REDOS_NESTED_QUANTIFIER = /(\([^)]*[+*][^)]*\)|\[[^\]]*\][^)]*)[+*]/;
function isRegexScanSafe(pattern: string): boolean {
  if (pattern.length > 512) return false;
  try {
    // eslint-disable-next-line no-new
    new RegExp(pattern);
  } catch {
    return false;
  }
  // Count repetition operators; a pattern with a quantified group followed by
  // another quantifier is the dangerous nested-repetition case.
  if (REDOS_NESTED_QUANTIFIER.test(pattern)) return false;
  // Reject more than 3 unbounded quantifiers — a crude star-height proxy.
  const quantifiers = (pattern.match(/[+*]|\{\d*,?\d*\}/g) || []).length;
  if (quantifiers > 8) return false;
  return true;
}

// Returns true if the include pattern can only ever match URLs within
// `baseUrl`'s origin — i.e. the pattern cannot widen scope past the target.
// We require the pattern to literally begin with the (regex-escaped) origin.
function includePatternStaysInOrigin(pattern: string, escapedOrigin: string): boolean {
  return pattern.startsWith(escapedOrigin) || pattern.startsWith(`^${escapedOrigin}`);
}

async function loadScopeConfig(
  supabase: Storage,
  projectId: string,
  targetUrl: string,
): Promise<ScopeConfig | undefined> {
  const { data, error } = await supabase
    .from('project_dast_config')
    .select('scope_config')
    .eq('project_id', projectId)
    .maybeSingle();
  if (error || !data) return undefined;
  const raw = (data as { scope_config?: StoredScopeConfig | null }).scope_config;
  if (!raw || typeof raw !== 'object') return undefined;

  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    // Malformed target URL — drop all include patterns rather than risk a
    // widened scope. The SSRF revalidation step will abort the run anyway.
    return undefined;
  }
  const escapedOrigin = origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const out: ScopeConfig = {};

  // include / exclude patterns: route layer already enforces string[], cap of
  // 32, ReDoS-safe (safe-regex2). Defense-in-depth: drop non-strings and cap
  // here too in case a row was inserted via raw SQL or a stale migration.
  // Also re-run a ReDoS heuristic and assert include patterns can only narrow
  // scope (must stay within the target origin), never widen it.
  if (Array.isArray(raw.include_patterns)) {
    const arr = raw.include_patterns
      .filter((v): v is string => typeof v === 'string')
      .slice(0, 32)
      .filter((p) => {
        if (!isRegexScanSafe(p)) {
          console.warn(`[dast-pipeline] dropped unsafe include pattern (ReDoS risk)`);
          return false;
        }
        if (!includePatternStaysInOrigin(p, escapedOrigin)) {
          console.warn(`[dast-pipeline] dropped include pattern that widens scope past target origin`);
          return false;
        }
        return true;
      });
    if (arr.length > 0) out.includePaths = arr;
  }
  if (Array.isArray(raw.exclude_patterns)) {
    const arr = raw.exclude_patterns
      .filter((v): v is string => typeof v === 'string')
      .slice(0, 32)
      .filter((p) => {
        if (!isRegexScanSafe(p)) {
          console.warn(`[dast-pipeline] dropped unsafe exclude pattern (ReDoS risk)`);
          return false;
        }
        // Exclude patterns can only narrow reach, so no origin assertion.
        return true;
      });
    if (arr.length > 0) out.excludePaths = arr;
  }
  if (Array.isArray(raw.header_rules)) {
    const rules: NonNullable<ScopeConfig['headerRules']> = [];
    for (const r of raw.header_rules.slice(0, 16)) {
      if (
        r != null &&
        typeof r === 'object' &&
        typeof (r as { name?: unknown }).name === 'string' &&
        typeof (r as { value?: unknown }).value === 'string'
      ) {
        const rec = r as { name: string; value: string; scope?: unknown };
        const scope: 'all' | 'requests' | 'responses' =
          rec.scope === 'requests' || rec.scope === 'responses' ? rec.scope : 'all';
        rules.push({ name: rec.name, value: rec.value, scope });
      }
    }
    if (rules.length > 0) out.headerRules = rules;
  }

  return out.includePaths || out.excludePaths || out.headerRules ? out : undefined;
}

// ---------------------------------------------------------------------------
// ZAP spawn via control-plane
// ---------------------------------------------------------------------------

interface ZapRunInputs {
  targetUrl: string;
  scanProfile: AfScanProfile;
  detectedRuntime: DetectedRuntime;
  scope?: ScopeConfig;
  authStrategy?: DastAuthStrategy;
  authPayload?: CredentialPayload;
  loggedInIndicator?: string;
  loggedOutIndicator?: string;
  scanTimeoutMinutes: number;
  zapWorkDir: string;
  spawnImpl?: typeof import('child_process').spawn;
}

interface ZapRunOutputs {
  findings: DastFindingRaw[];
  durationMs: number;
  exitCode: number | null;
  aborted: boolean;
  authLostState: ReturnType<ReturnType<typeof createAuthLostWatcher>['state']>;
  attachAbort: (handle: SpawnExternalHandle) => void;
}

async function runZapWithControlPlane(
  inputs: ZapRunInputs,
  options: {
    /** Heartbeat tick called from cancellation-poll loop. */
    onHeartbeat: () => Promise<void>;
    /** Returns true to trigger pipeline abort with reason 'cancellation_requested'. */
    isCancelled: () => Promise<boolean>;
    /** Polling cadence for cancellation+heartbeat. */
    pollIntervalMs: number;
  },
): Promise<ZapRunOutputs> {
  let yamlText: string;
  try {
    yamlText = buildAutomationYaml({
      targetUrl: inputs.targetUrl,
      scanProfile: inputs.scanProfile,
      detectedRuntime: inputs.detectedRuntime,
      reportRelativePath: 'zap-report.json',
      scope: inputs.scope,
      authStrategy: inputs.authStrategy,
      authPayload: inputs.authPayload,
      loggedInIndicator: inputs.loggedInIndicator,
      loggedOutIndicator: inputs.loggedOutIndicator,
      scanTimeoutMinutes: inputs.scanTimeoutMinutes,
    });
  } catch (e) {
    if (e instanceof InvalidCredentialCharacterError) {
      // A crafted credential (CR/LF/control char in a cookie, bad-alphabet
      // JWT) could inject headers into every ZAP request. Fail the job
      // cleanly with a generic, categorized error.
      console.error(`[dast-pipeline] credential rejected: ${e.message}`);
      throw new DastPipelineAbortError(
        'auth_failed',
        { stage: 'build_auth_yaml', reason: 'invalid_credential_characters' },
        'DAST credential contains invalid characters',
      );
    }
    throw e;
  }

  const tmpDir = fs.mkdtempSync(path.join(inputs.zapWorkDir, 'deptex-dast-af-'));
  const yamlPath = path.join(tmpDir, 'automation.yaml');
  const reportPath = path.join(tmpDir, 'zap-report.json');
  // automation.yaml embeds plaintext form/JWT/cookie credentials — write it
  // owner-read/write only so it is never world-readable on disk.
  fs.writeFileSync(yamlPath, yamlText, { encoding: 'utf-8', mode: 0o600 });

  const watcher = createAuthLostWatcher({
    onThresholdReached: () => {
      handle.abort('auth_lost_threshold');
    },
  });

  // ZAP doesn't tag stderr lines with "AUTH_LOST status=N url=U" today; the
  // watcher stays dormant until the AF passive-scan rule (v2.1b) emits them.
  // When it does, the line shape will be tab-separated and easy to parse here.
  const handle = spawnExternal({
    command: '/zap/zap.sh',
    args: ['-cmd', '-autorun', yamlPath],
    timeoutMs: inputs.scanTimeoutMinutes * 60_000,
    spawnImpl: inputs.spawnImpl,
    onStderr: (chunk) => {
      // Forward stderr to our process for ops visibility, redacted.
      process.stderr.write(`[zap-af] ${redactCredentials(chunk)}`);
      const m = /AUTH_LOST\s+status=(\d+)\s+url=(\S+)/.exec(chunk);
      if (m) watcher.recordHit(parseInt(m[1], 10), m[2]);
      if (/AUTH_OK\b/.test(chunk)) watcher.recordIndicatorClear();
    },
  });

  // Cancellation + heartbeat poll. Runs concurrently with the spawn promise;
  // when cancellation is observed, we abort the handle. The timer is cleared
  // in the finally block so a fast spawn-error path doesn't have to wait for
  // the next poll tick.
  let pollDone = false;
  let pollTimer: NodeJS.Timeout | null = null;
  async function pollOnce(): Promise<void> {
    if (pollDone) return;
    try {
      await options.onHeartbeat();
    } catch {
      /* non-fatal */
    }
    if (pollDone) return;
    let cancelled = false;
    try {
      cancelled = await options.isCancelled();
    } catch {
      cancelled = false;
    }
    if (pollDone) return;
    if (cancelled) {
      handle.abort('cancellation_requested');
      return;
    }
    pollTimer = setTimeout(pollOnce, options.pollIntervalMs);
    pollTimer.unref?.();
  }
  pollTimer = setTimeout(pollOnce, options.pollIntervalMs);
  pollTimer.unref?.();

  let result;
  try {
    result = await handle.done;
  } finally {
    pollDone = true;
    if (pollTimer) clearTimeout(pollTimer);
    // YAML can contain plaintext form credentials — drop it now even on abort.
    try {
      fs.unlinkSync(yamlPath);
    } catch {
      /* noop */
    }
  }

  // The temp dir (YAML already unlinked, but the partial report and the dir
  // itself remain) must be removed on EVERY exit path — including the abort
  // throws below, which previously leaked it. A single finally covers all.
  try {
    // ZAP exit codes 0/1/2 are normal completions (with or without findings).
    // 3+, null (signal-killed), or any abort with no clean exit are runner-level
    // failures. An auth-lost-triggered abort is not a runner failure — pipeline
    // upstream marks the job as auth_failed and we still parse partial findings.
    if (
      !result.aborted &&
      result.exitCode !== 0 &&
      result.exitCode !== 1 &&
      result.exitCode !== 2
    ) {
      // The ZAP stderr tail can carry credentials that pattern-based redaction
      // misses. Per project rule "never surface raw backend errors to users",
      // log the (redacted) tail to console only and store a generic message in
      // the UI-visible scan_jobs.error column.
      const tail = result.stderr.slice(-2_000);
      console.error(
        `[dast-pipeline] ZAP AF crashed (exit=${result.exitCode}, signal=${result.signal}). stderr tail: ${redactCredentials(tail)}`,
      );
      throw new DastPipelineAbortError(
        'engine_crash',
        { exit_code: result.exitCode, signal: result.signal },
        'DAST engine crashed during the scan',
      );
    }

    // Cancellation aborts always surface up — never collect findings.
    if (result.aborted && result.abortReason === 'cancellation_requested') {
      throw new DastPipelineAbortError(
        'unknown',
        { aborted_reason: 'cancellation_requested' },
        'DAST scan cancelled by user',
      );
    }
    if (result.aborted && result.abortReason === 'scan_timeout') {
      throw new DastPipelineAbortError(
        'timeout',
        { aborted_reason: 'scan_timeout', timeout_minutes: inputs.scanTimeoutMinutes },
        `DAST scan exceeded scan_timeout_minutes=${inputs.scanTimeoutMinutes}`,
      );
    }

    // Auth-lost abort: still parse the partial report so findings collected
    // before the trip ship.
    let findings: DastFindingRaw[] = [];
    if (fs.existsSync(reportPath)) {
      const reportText = fs.readFileSync(reportPath, 'utf-8');
      if (reportText.trim().length > 0) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let report: any;
        try {
          report = JSON.parse(reportText);
        } catch (e) {
          // A non-empty but unparseable report means ZAP wrote a truncated /
          // corrupt file. Silently shipping findings_count=0 would be
          // indistinguishable from a clean target — fail the job instead.
          console.error(
            `[dast-pipeline] ZAP report JSON is corrupt/truncated: ${(e as Error).message}`,
          );
          throw new DastPipelineAbortError(
            'engine_crash',
            { stage: 'parse_report', reason: 'corrupt_report_json' },
            'DAST engine produced a corrupt report',
          );
        }
        findings = parseZapReport(report);
      }
      // An empty report file is a legitimate clean-target / zero-findings
      // result, so we leave `findings` as [].
    }

    return {
      findings,
      durationMs: result.durationMs,
      exitCode: result.exitCode,
      aborted: result.aborted,
      authLostState: watcher.state(),
      attachAbort: () => undefined,
    };
  } finally {
    // Remove the whole temp dir (partial report + dir) on success AND on every
    // throw path above. force:true so a missing dir/file doesn't mask the
    // original error.
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Engine dispatch (v2.1c)
// ---------------------------------------------------------------------------

/**
 * Map a scan_jobs.type to the DAST engine. 'dast_nuclei' → Nuclei; 'dast' (the
 * legacy v2.1a alias) and 'dast_zap' → ZAP.
 */
export function resolveEngine(jobType: string): 'zap' | 'nuclei' {
  return jobType === 'dast_nuclei' ? 'nuclei' : 'zap';
}

/**
 * Build the cross_link_metadata payload for an inserted finding. Nuclei
 * findings get a `nuclei.cve_ids` array merged in — confirm_pdvs_from_dast_run
 * reads exactly that JSON path. ZAP findings pass the base metadata through.
 */
export function buildEngineCrossLinkMetadata(
  engine: 'zap' | 'nuclei',
  baseMetadata: Record<string, unknown>,
  cveIds: string[],
): Record<string, unknown> {
  if (engine !== 'nuclei') return baseMetadata;
  return { ...baseMetadata, nuclei: { cve_ids: cveIds } };
}

// ---------------------------------------------------------------------------
// Nuclei engine wrapper (v2.1c)
// ---------------------------------------------------------------------------

interface ScanControlOptions {
  onHeartbeat: () => Promise<void>;
  isCancelled: () => Promise<boolean>;
  pollIntervalMs: number;
}

interface NucleiRunInputs {
  targetUrl: string;
  authHeaders?: Record<string, string>;
  scanTimeoutMinutes: number;
  spawnImpl?: typeof import('child_process').spawn;
}

/**
 * Run a Nuclei scan and translate its abort/exit outcomes into the same
 * DastPipelineAbortError vocabulary the ZAP wrapper uses, so the pipeline
 * branches identically regardless of engine.
 */
async function runNucleiWithControlPlane(
  inputs: NucleiRunInputs,
  options: ScanControlOptions,
): Promise<{ findings: DastFindingRaw[]; durationMs: number }> {
  const result = await runNuclei(
    {
      targetUrl: inputs.targetUrl,
      authHeaders: inputs.authHeaders,
      scanTimeoutMinutes: inputs.scanTimeoutMinutes,
      spawnImpl: inputs.spawnImpl,
    },
    options,
  );

  if (result.aborted && result.abortReason === 'cancellation_requested') {
    throw new DastPipelineAbortError(
      'unknown',
      { aborted_reason: 'cancellation_requested' },
      'DAST scan cancelled by user',
    );
  }
  if (result.aborted && result.abortReason === 'scan_timeout') {
    throw new DastPipelineAbortError(
      'timeout',
      { aborted_reason: 'scan_timeout', timeout_minutes: inputs.scanTimeoutMinutes },
      `DAST scan exceeded scan_timeout_minutes=${inputs.scanTimeoutMinutes}`,
    );
  }
  // Nuclei exits 0 on a clean run with or without findings; a non-zero exit
  // that was not an abort is an engine crash.
  if (!result.aborted && result.exitCode !== 0 && result.exitCode !== null) {
    throw new DastPipelineAbortError(
      'engine_crash',
      { exit_code: result.exitCode },
      `Nuclei exited with code ${result.exitCode}`,
    );
  }

  return { findings: result.findings, durationMs: result.durationMs };
}

// ---------------------------------------------------------------------------
// Atomic-commit + finalization
// ---------------------------------------------------------------------------

async function insertFindings(
  supabase: Storage,
  rows: DastFindingInsert[],
): Promise<void> {
  if (rows.length === 0) return;
  const CHUNK_SIZE = 200;
  for (let i = 0; i < rows.length; i += CHUNK_SIZE) {
    const chunk = rows.slice(i, i + CHUNK_SIZE);
    const { error } = await supabase.from('project_dast_findings').insert(chunk);
    if (error) {
      throw new Error(`Failed to insert DAST findings (batch ${i / CHUNK_SIZE}): ${error.message}`);
    }
  }
}

async function commitDastTargetRun(
  supabase: Storage,
  targetId: string,
  dastRunId: string,
): Promise<void> {
  const { error } = await supabase.rpc('commit_dast_target_run', {
    p_target_id: targetId,
    p_dast_run_id: dastRunId,
  });
  if (error) {
    throw new Error(`commit_dast_target_run failed: ${error.message}`);
  }
}

async function finalizeJob(
  supabase: Storage,
  jobId: string,
  findingsCount: number,
  durationSeconds: number,
): Promise<void> {
  const { error } = await supabase
    .from('scan_jobs')
    .update({
      status: 'completed',
      findings_count: findingsCount,
      duration_seconds: durationSeconds,
      completed_at: new Date().toISOString(),
    })
    .eq('id', jobId);
  if (error) {
    throw new Error(`Failed to finalize DAST scan_jobs row: ${error.message}`);
  }
}

async function recordJobError(
  supabase: Storage,
  jobId: string,
  category: DastErrorCategory,
  payload: Record<string, unknown> | null,
  message: string,
): Promise<void> {
  const { error } = await supabase
    .from('scan_jobs')
    .update({
      status: 'failed',
      error: message,
      error_category: category,
      error_payload: payload,
      completed_at: new Date().toISOString(),
    })
    .eq('id', jobId);
  if (error) {
    console.error(`[dast-${jobId}] Failed to record error_category=${category}: ${error.message}`);
  }
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

const DEFAULT_CANCELLATION_POLL_MS = 5_000;

export async function runDastPipeline(
  job: ExtractionJobRow,
  supabase: Storage,
  options: RunDastPipelineOptions = {},
): Promise<DastPipelineResult> {
  const startedAt = Date.now();
  const tag = `[dast-${job.id}]`;
  const payload = job.payload as DastJobPayload;

  const scanProfile: DastScanProfile = payload.scan_profile ?? 'auto';
  const timeoutMinutes = payload.scan_timeout_minutes ?? Math.round(ZAP_DEFAULT_TIMEOUT_MS / 60_000);
  const zapWorkDir = options.zapWorkDir ?? process.env.DAST_WORK_DIR ?? '/zap/wrk';

  // Step 1: tenant-guard load (no decrypt yet).
  let guard;
  try {
    guard = await loadTenantGuardRows(supabase, job.id, job.organization_id);
  } catch (e) {
    if (e instanceof DastPipelineAbortError) {
      console.error(`${tag} aborted at tenant guard: ${e.errorCategory}`);
      await recordJobError(supabase, job.id, e.errorCategory, e.errorPayload, e.message);
      throw e;
    }
    throw e;
  }
  const { scanJob, target } = guard;

  console.log(
    `${tag} target ${target.id} (${target.target_url}) runtime=${target.detected_runtime} profile=${scanProfile}`,
  );

  // Step 2: credential load. Throws DastPipelineAbortError on missing/stale/rotated.
  let cred: LoadedCredential | null = null;
  try {
    cred = await loadCredentialOrAbort(supabase, scanJob, target);
  } catch (e) {
    if (e instanceof DastPipelineAbortError) {
      console.error(`${tag} aborted at cred load: ${e.errorCategory}`);
      await recordJobError(supabase, job.id, e.errorCategory, e.errorPayload, e.message);
      throw e;
    }
    throw e;
  }

  // Step 3a: load project_dast_config.scope_config and convert to ScopeConfig.
  // The route layer (PUT /dast/config) already validated this shape — we
  // re-shape DB-side snake_case to the yaml-builder's camelCase here. Without
  // this load, every customer's include/exclude paths and header rules were
  // silently ignored (regression caught in v2.1a critical review).
  const scope = await loadScopeConfig(supabase, job.project_id, target.target_url);

  // Step 3b: cross-link prerequisites. Loaded BEFORE the scan so we don't add
  // wallclock to the credentialed window.
  const extractionRunId = await getActiveExtractionRunId(supabase, job.project_id);
  let entryPoints: EntryPointRow[] = [];
  let flows: ReachableFlowRow[] = [];
  let pdvByPurl = new Map<string, PdvRow[]>();
  let projectDependencyByPurl = new Map<string, ProjectDependencyRow>();
  if (extractionRunId) {
    [entryPoints, flows, { pdvByPurl, projectDependencyByPurl }] = await Promise.all([
      loadEntryPoints(supabase, job.project_id, extractionRunId),
      loadReachableFlows(supabase, job.project_id, extractionRunId),
      loadPdvsForProject(supabase, job.project_id),
    ]);
  } else {
    console.warn(`${tag} no active_extraction_run_id — skipping cross-link`);
  }

  // Step 3c: scan-time SSRF revalidation. The route layer SSRF-checked
  // target_url at create time, but a hostname that resolved to a benign
  // public IP then can DNS-rebind to 169.254.169.254 / RFC1918 / Fly 6PN by
  // the time the worker actually scans it. Re-resolve and re-check the host
  // here, immediately before spawning the engine, the same way the container
  // scanner does. Abort with a distinct `ssrf_blocked` category on failure.
  let scanHostname: string;
  try {
    scanHostname = new URL(target.target_url).hostname;
  } catch {
    const abort = new DastPipelineAbortError(
      'ssrf_blocked',
      { stage: 'parse_target_url' },
      'DAST target URL is malformed',
    );
    console.error(`${tag} aborted: target_url not a valid URL`);
    await recordJobError(supabase, job.id, abort.errorCategory, abort.errorPayload, abort.message);
    throw abort;
  }
  const hostCheck = await validateScanTimeHost(scanHostname, 'host');
  if (!hostCheck.valid) {
    const abort = new DastPipelineAbortError(
      'ssrf_blocked',
      { stage: 'scan_time_host_revalidation' },
      'DAST target host failed scan-time SSRF revalidation',
    );
    // Log the specific reason for ops; never put it in scan_jobs.error.
    console.error(`${tag} aborted: scan-time SSRF revalidation failed: ${hostCheck.reason}`);
    await recordJobError(supabase, job.id, abort.errorCategory, abort.errorPayload, abort.message);
    throw abort;
  }

  // Step 4: run the selected DAST engine. job.type='dast_nuclei' → Nuclei,
  // everything else ('dast' legacy alias, 'dast_zap') → ZAP. Both engines
  // share the cancellation-poll + heartbeat control loop.
  const engine = resolveEngine(job.type);
  const afProfile: AfScanProfile = scanProfile === 'api' ? 'auto' : (scanProfile as AfScanProfile);

  const control: ScanControlOptions = {
    onHeartbeat: async () => {
      try {
        await sendHeartbeat(supabase, job.id);
      } catch {
        /* non-fatal */
      }
    },
    isCancelled: async () => {
      try {
        return await isJobCancelled(supabase, job.id);
      } catch {
        return false;
      }
    },
    pollIntervalMs: options.cancellationPollMs ?? DEFAULT_CANCELLATION_POLL_MS,
  };

  let scanFindings: DastFindingRaw[];
  let scanDurationMs: number;
  let authLostState: ZapRunOutputs['authLostState'] | null = null;
  try {
    if (engine === 'nuclei') {
      // Reduce the credential to flat headers. form / recorded auth cannot be
      // expressed as static headers — abort rather than scan anonymous (the
      // never-fall-back-to-anonymous invariant).
      let authHeaders: Record<string, string> | undefined;
      if (cred) {
        try {
          authHeaders = buildNucleiAuthHeaders(cred.credentialRow.auth_strategy, cred.payload);
        } catch (e) {
          throw new DastPipelineAbortError(
            'auth_failed',
            { strategy: cred.credentialRow.auth_strategy },
            e instanceof UnsupportedAuthStrategyError
              ? `Nuclei engine cannot use '${cred.credentialRow.auth_strategy}' auth — re-run this target with the ZAP engine`
              : (e as Error).message,
          );
        }
      }
      const nucleiResult = await runNucleiWithControlPlane(
        {
          targetUrl: target.target_url,
          authHeaders,
          scanTimeoutMinutes: timeoutMinutes,
          spawnImpl: options.spawnImpl,
        },
        control,
      );
      scanFindings = nucleiResult.findings;
      scanDurationMs = nucleiResult.durationMs;
    } else {
      const zapResult = await runZapWithControlPlane(
        {
          targetUrl: target.target_url,
          scanProfile: afProfile,
          detectedRuntime: target.detected_runtime,
          scope,
          authStrategy: cred?.credentialRow.auth_strategy,
          authPayload: cred?.payload,
          loggedInIndicator: cred?.credentialRow.logged_in_indicator ?? undefined,
          loggedOutIndicator: cred?.credentialRow.logged_out_indicator ?? undefined,
          scanTimeoutMinutes: timeoutMinutes,
          zapWorkDir,
          spawnImpl: options.spawnImpl,
        },
        control,
      );
      scanFindings = zapResult.findings;
      scanDurationMs = zapResult.durationMs;
      authLostState = zapResult.authLostState;
    }
  } catch (e) {
    if (e instanceof DastPipelineAbortError) {
      console.error(`${tag} aborted during scan: ${e.errorCategory}`);
      await recordJobError(supabase, job.id, e.errorCategory, e.errorPayload, e.message);
    }
    throw e;
  }
  // Plaintext lifetime is GC-bound: V8 strings holding the decrypted
  // password/token/cookies are unreferenced once the engine wrapper returns
  // and any temp file is unlinked. Fly machine isolation (one tenant per scan,
  // machine destroyed at end) is the load-bearing safety property here.

  console.log(`${tag} ${engine} returned ${scanFindings.length} findings in ${scanDurationMs}ms`);

  // Step 5: build inserts with auth_state per finding.
  const dastRunId = `dast_${randomUUID()}`;
  const authLostThresholdHit = authLostState != null && authLostState.consecutiveLostCount >= 4;
  const baseAuthState: DastAuthState = cred ? 'authenticated' : 'anonymous';
  // Auth-lost is ZAP-only; the watcher trip marks ALL findings
  // 'authentication_lost' since the report carries no per-finding timestamps.
  const findingAuthState: DastAuthState = authLostThresholdHit ? 'authentication_lost' : baseAuthState;

  let crossLinkedCount = 0;
  let cveSignalCount = 0;
  const inserts: DastFindingInsert[] = scanFindings.map((f) => {
    const link = crossLinkFinding({ finding: f, entryPoints, flows, pdvByPurl, projectDependencyByPurl });
    if (link.linked_sca_osv_id) crossLinkedCount++;
    // Nuclei findings carry their CVE ids in cross_link_metadata.nuclei.cve_ids
    // — confirm_pdvs_from_dast_run reads exactly that JSON path.
    const cveIds = engine === 'nuclei' ? f.cve_ids ?? [] : [];
    if (cveIds.length > 0) cveSignalCount++;
    const crossLinkMetadata = buildEngineCrossLinkMetadata(engine, link.cross_link_metadata, cveIds);
    return {
      project_id: job.project_id,
      organization_id: job.organization_id,
      target_id: target.id,
      dast_run_id: dastRunId,
      endpoint_url: f.endpoint_url,
      http_method: f.http_method,
      vulnerability_type: f.vulnerability_type,
      severity: f.severity,
      cwe_id: f.cwe_id,
      owasp_top10_ref: f.owasp_top10_ref,
      rule_id: f.rule_id,
      message: f.message,
      payload_redacted: f.payload_redacted,
      response_evidence_redacted: f.response_evidence_redacted,
      confidence: f.confidence,
      handler_file_path: link.handler_file_path,
      handler_function_name: link.handler_function_name,
      handler_line: link.handler_line,
      linked_sca_osv_id: link.linked_sca_osv_id,
      linked_sca_project_dependency_id: link.linked_sca_project_dependency_id,
      cross_link_metadata: crossLinkMetadata,
      auth_state: findingAuthState,
      engine,
      kev: f.kev ?? false,
      status: 'open',
    };
  });

  // Dedupe non-cross-linked findings against the partial unique index.
  const seen = new Set<string>();
  const dedupedInserts: DastFindingInsert[] = [];
  for (const row of inserts) {
    if (row.handler_file_path !== null) {
      dedupedInserts.push(row);
      continue;
    }
    const key = `${row.rule_id ?? ''}|${row.endpoint_url}|${row.http_method}|${row.vulnerability_type}`;
    if (seen.has(key)) continue;
    seen.add(key);
    dedupedInserts.push(row);
  }

  await insertFindings(supabase, dedupedInserts);

  // Step 6: atomic-commit via the target-scoped RPC.
  await commitDastTargetRun(supabase, target.id, dastRunId);

  // Step 6.5: Nuclei runtime-confirmation cross-link batch. Only runs when the
  // engine is Nuclei and at least one inserted finding carried CVE ids; flips
  // matching PDV rows to reachability_level='confirmed'. Best-effort — a
  // failure is logged inside confirmPdvsFromDastRun, never fails the job.
  let runtimeConfirmedCount = 0;
  if (engine === 'nuclei' && cveSignalCount > 0) {
    const confirmResult = await confirmPdvsFromDastRun(
      supabase,
      job.organization_id,
      job.project_id,
      dastRunId,
    );
    runtimeConfirmedCount = confirmResult.confirmed_count;
  }

  // Step 7: finalize. Auth-lost trip → record as a JOB STATE (not a synthetic
  // finding row); findings collected during the run still ship.
  const durationSeconds = Math.round((Date.now() - startedAt) / 1000);
  if (authLostThresholdHit && authLostState) {
    await recordJobError(
      supabase,
      job.id,
      'auth_failed',
      {
        consecutive_lost_count: authLostState.consecutiveLostCount,
        last_logged_out_url: authLostState.lastLoggedOutUrl,
        last_logged_out_at: authLostState.lastLoggedOutAt,
        findings_count: dedupedInserts.length,
      },
      'DAST authentication lost mid-scan',
    );
  } else {
    await finalizeJob(supabase, job.id, dedupedInserts.length, durationSeconds);
  }

  console.log(
    `${tag} DAST scan completed: ${dedupedInserts.length} findings, ${durationSeconds}s` +
      (engine === 'nuclei' ? `, runtime_confirmed=${runtimeConfirmedCount}` : ''),
  );

  return {
    dast_run_id: dastRunId,
    findings_count: dedupedInserts.length,
    duration_seconds: durationSeconds,
    cross_linked_count: crossLinkedCount,
    auth_state_summary: findingAuthState,
    runtime_confirmed_count: runtimeConfirmedCount,
  };
}

// Re-exports kept for back-compat with existing tests/callers that imported
// crossLinkFinding from pipeline.ts.
export { crossLinkFinding } from './cross-link';

// Internal exports used by the pipeline test harness in Task 9.
export { loadTenantGuardRows as __test_loadTenantGuardRows };
export { loadCredentialOrAbort as __test_loadCredentialOrAbort };
export { loadScopeConfig as __test_loadScopeConfig };
