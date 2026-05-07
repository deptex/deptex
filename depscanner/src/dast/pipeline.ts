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
} from './encryption';
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
  engine: 'zap';
  status: 'open';
}

export type DastErrorCategory =
  | 'tenant_drift_detected'
  | 'dast_credential_key_missing'
  | 'dast_credential_key_stale'
  | 'dast_credential_rotated'
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
  const yamlText = buildAutomationYaml({
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

  const tmpDir = fs.mkdtempSync(path.join(inputs.zapWorkDir, 'deptex-dast-af-'));
  const yamlPath = path.join(tmpDir, 'automation.yaml');
  const reportPath = path.join(tmpDir, 'zap-report.json');
  fs.writeFileSync(yamlPath, yamlText, 'utf-8');

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
    const tail = result.stderr.slice(-2_000);
    throw new DastPipelineAbortError(
      'engine_crash',
      { exit_code: result.exitCode, signal: result.signal },
      `ZAP AF exited with code ${result.exitCode}. stderr tail: ${redactCredentials(tail)}`,
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
    try {
      const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
      findings = parseZapReport(report);
    } catch {
      // Partial report — surface zero findings rather than crash the pipeline.
    }
    try {
      fs.unlinkSync(reportPath);
    } catch {
      /* noop */
    }
  }
  try {
    fs.rmdirSync(tmpDir);
  } catch {
    /* noop */
  }

  return {
    findings,
    durationMs: result.durationMs,
    exitCode: result.exitCode,
    aborted: result.aborted,
    authLostState: watcher.state(),
    attachAbort: () => undefined,
  };
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

  // Step 3: cross-link prerequisites. Loaded BEFORE the scan so we don't add
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

  // Step 4: spawn ZAP via control-plane. The plaintext buffer is alive until
  // buildAutomationYaml runs INSIDE runZapWithControlPlane → write to disk →
  // we wipe immediately after.
  const afProfile: AfScanProfile = scanProfile === 'api' ? 'auto' : (scanProfile as AfScanProfile);
  let zapResult;
  try {
    zapResult = await runZapWithControlPlane(
      {
        targetUrl: target.target_url,
        scanProfile: afProfile,
        detectedRuntime: target.detected_runtime,
        authStrategy: cred?.credentialRow.auth_strategy,
        authPayload: cred?.payload,
        loggedInIndicator: cred?.credentialRow.logged_in_indicator ?? undefined,
        loggedOutIndicator: cred?.credentialRow.logged_out_indicator ?? undefined,
        scanTimeoutMinutes: timeoutMinutes,
        zapWorkDir,
        spawnImpl: options.spawnImpl,
      },
      {
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
      },
    );
  } catch (e) {
    if (e instanceof DastPipelineAbortError) {
      console.error(`${tag} aborted during scan: ${e.errorCategory}`);
      await recordJobError(supabase, job.id, e.errorCategory, e.errorPayload, e.message);
    }
    throw e;
  }
  // Plaintext lifetime is GC-bound: V8 strings holding the decrypted
  // password/token/cookies are unreferenced once runZapWithControlPlane
  // returns and the YAML temp file is unlinked. Fly machine isolation
  // (one tenant per scan, machine destroyed at end) is the load-bearing
  // safety property here, not buffer scrubbing.

  console.log(
    `${tag} ZAP returned ${zapResult.findings.length} findings in ${zapResult.durationMs}ms (auth_lost=${zapResult.authLostState.consecutiveLostCount})`,
  );

  // Step 5: build inserts with auth_state per finding.
  const dastRunId = `dast_${randomUUID()}`;
  const authLostThresholdHit = zapResult.aborted && zapResult.authLostState.consecutiveLostCount >= 4;
  const baseAuthState: DastAuthState = cred ? 'authenticated' : 'anonymous';
  // Findings collected after the trip carry 'authentication_lost'; we mark
  // ALL findings 'authentication_lost' if the watcher tripped, since we don't
  // get per-finding timestamps from the report. This is the same simplification
  // the plan §"auth_state state machine" calls out — rule_state stays a
  // run-level summary in v2.1a.
  const findingAuthState: DastAuthState = authLostThresholdHit ? 'authentication_lost' : baseAuthState;

  let crossLinkedCount = 0;
  const inserts: DastFindingInsert[] = zapResult.findings.map((f) => {
    const link = crossLinkFinding({ finding: f, entryPoints, flows, pdvByPurl, projectDependencyByPurl });
    if (link.linked_sca_osv_id) crossLinkedCount++;
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
      cross_link_metadata: link.cross_link_metadata,
      auth_state: findingAuthState,
      engine: 'zap',
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

  // Step 6: atomic-commit via the new target-scoped RPC.
  await commitDastTargetRun(supabase, target.id, dastRunId);

  // Step 7: finalize. Auth-lost trip → record as a JOB STATE (not a synthetic
  // finding row); findings collected during the run still ship.
  const durationSeconds = Math.round((Date.now() - startedAt) / 1000);
  if (authLostThresholdHit) {
    await recordJobError(
      supabase,
      job.id,
      'auth_failed',
      {
        consecutive_lost_count: zapResult.authLostState.consecutiveLostCount,
        last_logged_out_url: zapResult.authLostState.lastLoggedOutUrl,
        last_logged_out_at: zapResult.authLostState.lastLoggedOutAt,
        findings_count: dedupedInserts.length,
      },
      'DAST authentication lost mid-scan',
    );
  } else {
    await finalizeJob(supabase, job.id, dedupedInserts.length, durationSeconds);
  }

  console.log(`${tag} DAST scan completed: ${dedupedInserts.length} findings, ${durationSeconds}s`);

  return {
    dast_run_id: dastRunId,
    findings_count: dedupedInserts.length,
    duration_seconds: durationSeconds,
    cross_linked_count: crossLinkedCount,
    auth_state_summary: findingAuthState,
  };
}

// Re-exports kept for back-compat with existing tests/callers that imported
// crossLinkFinding from pipeline.ts.
export { crossLinkFinding } from './cross-link';

// Internal exports used by the pipeline test harness in Task 9.
export { loadTenantGuardRows as __test_loadTenantGuardRows };
export { loadCredentialOrAbort as __test_loadCredentialOrAbort };
