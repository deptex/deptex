// DAST DTOs shared between routes and (eventually) the frontend.
// Phase 23b shipped single-target DAST. Phase 24a (v2.1a) introduces
// multi-target scanning with per-target encrypted credentials.

export type ScanJobStatus = 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled';
// v2.1a widens trigger_source + adds dast_zap / dast_nuclei subtypes.
export type ScanJobType = 'extraction' | 'dast' | 'dast_zap' | 'dast_nuclei';

export type DastTriggerSource = 'manual' | 'webhook' | 'recovery' | 'scheduled' | 'on_deploy' | 'aegis';
export type DastScanProfile = 'auto' | 'quick' | 'full' | 'api';
export type DastSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DastFindingStatus = 'open' | 'suppressed' | 'risk_accepted' | 'fixed';
export type DastConfidence = 'confirmed' | 'high' | 'medium' | 'low';

// v2.1a inserted form|jwt|cookie. v2.1d adds 'recorded' (HAR-style step replay
// via ZAP's browser-based AF auth method). The DB CHECK already lists all four
// (phase24a_dast_v2_engine_additive.sql:136-137).
export type DastAuthStrategy = 'form' | 'jwt' | 'cookie' | 'recorded';
export type DastDetectedRuntime = 'unknown' | 'classic' | 'spa';
export type DastAuthState = 'anonymous' | 'authenticated' | 'authentication_lost';
// v2.1a inserts 'zap' only; v2.1c adds 'nuclei' as a second engine.
export type DastEngine = 'zap' | 'nuclei';

// ---------------------------------------------------------------------------
// v2.1d — Recorded login (browser-based AF auth)
// ---------------------------------------------------------------------------

/**
 * Step action types — map 1:1 to ZAP's browser auth `steps[].type`.
 * - `goto` is special: only valid as steps[0]; the value collapses into the
 *   AF context's `loginPageUrl` parameter (ZAP has no native mid-flow goto;
 *   intermediate navigation must use `click`).
 * - `type_custom` accepts a literal `value`; treated as potentially-secret
 *   (REDACTED in summaries, logs, and the test-result envelope).
 */
export type RecordedStepAction =
  | 'goto'
  | 'click'
  | 'type_username'
  | 'type_password'
  | 'type_totp'
  | 'type_custom'
  | 'wait'
  | 'return'
  | 'escape';

export interface RecordedStep {
  action: RecordedStepAction;
  selector?: string;
  selector_kind?: 'css' | 'xpath';
  value?: string;
  timeout_ms?: number;
  wait_ms?: number;
}

/**
 * Decrypted recorded-login payload. Stored AES-256-GCM-encrypted in
 * project_dast_credentials.encrypted_payload. The plaintext NEVER appears in
 * scan_jobs.payload, error_payload, worker stderr, or QStash bodies.
 */
export interface RecordedCredentialPayload {
  kind: 'recorded';
  login_page_url: string;
  steps: RecordedStep[];
  username: string;
  password: string;
  totp_secret?: string;
  login_page_wait_ms?: number;
  step_delay_ms?: number;
  /** Human-readable target label, surfaced in the credentials list (≤80 chars). */
  label?: string;
  /**
   * Optional origins the auth phase may navigate to (e.g. SSO IdP). Pre-baked
   * forward-compat for M0 Spike-2 yellow outcome; if Spike-2 returns green,
   * this field stays unused.
   */
  sso_origins?: string[];
}

// Phase 35 (v1.1) — OpenAPI spec source enum + per-target spec_config DTO.
// 'upload' is reserved for v1.2 (no backend code path accepts it in v1.1).
export type DastSpecSource = 'synthesized' | 'url' | 'none';

/**
 * Canonical list of error code strings returned by the spec routes
 * (PATCH /spec, GET /spec/download) + the scan-route guard. Duplicated
 * verbatim in `frontend/src/lib/dast-error-codes.ts`; CI runs
 * `scripts/check-dast-error-codes-match.sh` to fail PRs on drift.
 *
 * Adding a code: add here, add to the frontend file, update
 * friendlySpecErrorMessage on the frontend side.
 */
export const SPEC_ERROR_CODES = [
  'invalid_spec_source',
  'spec_url_required',
  'spec_url_invalid',
  'spec_url_unreachable',
  'spec_parse_failed',
  'spec_too_large',
  'spec_unavailable',
  'target_not_found',
  'unsupported_openapi_on_nuclei',
] as const;
export type SpecErrorCode = typeof SPEC_ERROR_CODES[number];

export interface DastSpecConfigDTO {
  api_spec_source: DastSpecSource;
  api_spec_url: string | null;
  last_synthesized_at: string | null;
  last_synthesis_endpoint_count: number | null;
  /**
   * null = never synthesized (target created before any scan ran).
   * true = last spec resolution + scan succeeded.
   * false = last spec resolution failed (no entries / URL fetch fail /
   *         URL parse fail / storage write fail). The frontend infers the
   *         specific cause from `api_spec_source` + `last_synthesized_at`
   *         + `last_synthesis_endpoint_count`.
   */
  last_synthesis_ok: boolean | null;
}

export interface DastTargetDTO {
  id: string;
  target_url: string;
  label: string | null;
  enabled: boolean;
  detected_runtime: DastDetectedRuntime;
  detected_runtime_at: string | null;
  detected_runtime_ttl_at: string | null;
  has_credentials: boolean;
  auth_strategy: DastAuthStrategy | null;
  active_dast_run_id: string | null;
  last_scanned_at: string | null;
  created_at: string;
  // Phase 35 (v1.1) — OpenAPI spec config + last-synthesis stats.
  spec_config: DastSpecConfigDTO;
}

export interface DastScopeHeaderRule {
  name: string;
  value: string;
  scope: 'all' | 'requests' | 'responses';
}

export interface DastScopeConfig {
  include_patterns?: string[];
  exclude_patterns?: string[];
  header_rules?: DastScopeHeaderRule[];
}

export interface DastConfigDTO {
  enabled: boolean;
  scan_profile: DastScanProfile;
  scan_timeout_minutes: number;
  scope_config?: DastScopeConfig;
  targets?: DastTargetDTO[];
}

// Redaction caps locked per multi-tenant-design-auditor-f4/r2-f11 P1:
//   token_prefix: first 8 chars + '…' (NOT 12 — JWT prefix 'eyJhbGciOi' is 10 and reveals algorithm)
//   username_masked: first char + '***@<domain>' truncated to 24 chars total
//   cookie_names: capped at 10 items, each name truncated to 32 chars
//   last_step_url: scheme + host only (NEVER path/query/fragment)
export type DastCredentialPayloadSummary =
  | { kind: 'form'; username_masked: string }
  | { kind: 'jwt'; token_prefix: string; token_length: number; expires_in_minutes: number }
  | { kind: 'cookie'; cookie_count: number; cookie_names: string[] }
  /**
   * v2.1d: recorded login summary. Host only (NEVER path/query/fragment) per
   * the same multi-tenant redaction posture as the other variants. Selectors
   * and step values are NOT echoed (they may leak the app's internal URL
   * structure / form names).
   */
  | { kind: 'recorded'; step_count: number; has_totp: boolean; login_page_url_host: string; label?: string };

export interface DastCredentialSummaryDTO {
  auth_strategy: DastAuthStrategy;
  payload_summary: DastCredentialPayloadSummary;
  logged_in_indicator: string | null;
  logged_out_indicator: string | null;
  updated_at: string;
}

export type DastCredentialUpsertPayload =
  | {
      kind: 'form';
      login_url: string;
      username_field: string;
      password_field: string;
      username: string;
      password: string;
    }
  | { kind: 'jwt'; token: string }
  | {
      kind: 'cookie';
      cookies: { name: string; value: string; domain?: string; path?: string }[];
    }
  | RecordedCredentialPayload;

export interface DastCredentialUpsertDTO {
  auth_strategy: DastAuthStrategy;
  payload: DastCredentialUpsertPayload;
  logged_in_indicator?: string;
  logged_out_indicator?: string;
}

export interface DastJobDTO {
  id: string;
  status: ScanJobStatus;
  trigger_source: DastTriggerSource | null;
  target_id?: string | null;
  target_url: string | null;
  scan_profile: DastScanProfile | null;
  findings_count: number | null;
  duration_seconds: number | null;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  error_category: string | null;
  attempts: number;
  created_at: string;
  /**
   * v2.1d — discriminated union surfacing recorded-login outcomes (test_result
   * variant for dry-run completions; pre_flight_failed for real-scan auth
   * failure; session_loss for mid-scan session-expiry exhaustion). FE
   * renderers MUST switch on `kind` — using `error_category` alone is
   * insufficient because dry-run successes also populate this column.
   */
  error_payload: DastJobErrorPayload | null;
}

/**
 * v2.1d — response from POST /api/projects/:projectId/dast/targets/:targetId/credentials/test.
 * Client polls GET /dast/jobs?id=<test_job_id> until status is terminal and
 * reads error_payload.test_result for the outcome.
 */
export interface DastLoginTestResponse {
  test_job_id: string;
  status: 'queued';
}

/**
 * v2.1d — response from POST /api/projects/:projectId/dast/jobs/:jobId/cancel.
 * 200 on successful cancellation. 409 when the job is not cancellable
 * (already completed/failed/cancelled). 404 cross-org or missing.
 */
export interface DastJobCancelResponse {
  job_id: string;
  status: 'cancelled';
}

export interface DastFindingDTO {
  id: string;
  target_id?: string | null;
  auth_state?: DastAuthState | null;
  engine?: DastEngine | null;
  endpoint_url: string;
  http_method: string;
  vulnerability_type: string;
  severity: DastSeverity;
  cwe_id: string | null;
  owasp_top10_ref: string | null;
  rule_id: string | null;
  message: string | null;
  payload_redacted: string | null;
  response_evidence_redacted: string | null;
  confidence: DastConfidence;
  handler_file_path: string | null;
  handler_function_name: string | null;
  handler_line: number | null;
  linked_sca_osv_id: string | null;
  linked_sca_project_dependency_id: string | null;
  linked_sast_finding_id?: string | null;
  cross_link_methods?: string[] | null;
  confirmed_exploitable: boolean;
  /** CISA Known-Exploited flag — true only for KEV-tagged Nuclei findings. */
  kev: boolean;
  status: DastFindingStatus;
  risk_accepted_reason: string | null;
  created_at: string;
}

// v2.1c: runtime-confirmation fields on an SCA (PDV) finding — populated when
// a Nuclei scan independently observed the vulnerability at runtime.
export interface SCARuntimeConfirmation {
  runtime_confirmed_at: string | null;
  runtime_confirmed_dast_finding_id: string | null;
  runtime_confirmed_prior_level: string | null;
}

// ---------------------------------------------------------------------------
// v2.1d — scan_jobs.error_payload discriminated union + login-test result
// ---------------------------------------------------------------------------

/**
 * Structured failure metadata for a recorded login replay step. step_index is
 * in UI coordinates (0-indexed against payload.steps as the user authored
 * them) — NOT against ZAP's collapsed step array. The auth-config layer holds
 * an `internalIndexToZapIndex[]` mapping that translates between the two.
 *
 * `dom_excerpt` is reserved in v2.1d for a future Aegis "Suggest selector
 * fix" assistant. Parser populates best-effort (≤1KB, redacted) when the
 * diagnostic log carries surrounding HTML for a selector_not_visible failure.
 * Unused in v1 UI; never required.
 */
export interface FailedAtStep {
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

/**
 * Result envelope written into scan_jobs.error_payload (under
 * `{kind:'test_result', test_result:…}`) on dry-run completion (success OR
 * failure — both end as status='completed', error_category=NULL).
 */
export interface DastLoginTestResult {
  success: boolean;
  duration_ms: number;
  steps_run: number;
  step_index?: number;
  failed_at_step?: FailedAtStep;
  /**
   * Fallback raw diagnostic excerpt for unstructured Spike-3 outcomes — only
   * populated when the parser couldn't map to a structured reason. Always
   * redacted of credentials before storage.
   */
  raw_log?: string;
}

/**
 * Discriminated union for scan_jobs.error_payload. Replaces the previously-
 * overloaded JSONB shape under error_category='auth_failed' (which carried
 * `{consecutive_lost_count, last_logged_out_url, last_logged_out_at}` only).
 *
 * Variants:
 * - `session_loss` — existing form-strategy mid-scan session expiration.
 * - `pre_flight_failed` — v2.1d: recorded-strategy pre-flight probe failed
 *   on a real scan; spider/active-scan never ran.
 * - `test_result` — v2.1d: dry-run job (payload.dry_run=true) completion.
 *   This is the ONLY variant where status='completed' with non-null
 *   error_payload (and error_category is NULL).
 *
 * Frontend renderers MUST switch on `kind`; using `error_category` alone is
 * insufficient now that the payload column carries success envelopes too.
 */
export type DastJobErrorPayload =
  | {
      kind: 'session_loss';
      consecutive_lost_count: number;
      last_logged_out_url?: string;
      last_logged_out_at?: string;
    }
  | {
      kind: 'pre_flight_failed';
      failed_at_step: FailedAtStep;
      consecutive_lost_count: 0;
    }
  | {
      kind: 'test_result';
      test_result: DastLoginTestResult;
    };

/**
 * Validated shape for scan_jobs.payload. Lives next to the type because it
 * crosses the API boundary (route inserts) and the worker boundary (pipeline
 * reads). Validating in both places defends against typos like `dryRun` or
 * `dry-run` silently taking the wrong branch in runDastPipeline.
 *
 * `validateDastJobPayload` (in `backend/src/lib/dast-credential-validate.ts`)
 * enforces the shape; on the worker side, pipeline.ts re-validates after
 * loading the row.
 */
export interface DastJobPayloadSchema {
  target_url?: string;
  scan_profile?: DastScanProfile;
  scan_timeout_minutes?: number;
  detected_runtime?: DastDetectedRuntime;
  source?:
    | 'manual_dast_scan'
    | 'credential_test'
    | 'webhook'
    | 'scheduled'
    | 'on_deploy'
    | 'aegis';
  /**
   * v2.1d: when true, runDastPipeline branches at the top into the recorded-
   * login probe ONLY — no spider, no active-scan, no findings inserted, no
   * PDV mutation, no populateDependencies. Result written to
   * scan_jobs.error_payload under `{kind:'test_result', test_result:…}`.
   */
  dry_run?: boolean;
  engine?: DastEngine;
}
