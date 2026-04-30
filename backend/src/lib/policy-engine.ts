/**
 * Policy-as-Code Execution Engine.
 *
 * Sandboxed policy evaluation using isolated-vm with controlled fetch(),
 * helper functions, and strict return-shape validation.
 *
 * Sandbox model: fresh `Isolate` per call, hydrated from a process-wide
 * V8 startup snapshot. No pooling — each call gets a clean heap.
 * Caps: 32MB memory, 30s CPU (5s for validation), 256KB return value (enforced
 * inside the isolate via JSON.stringify-then-slice), plus a 200ms post-execution
 * copy timeout as defense-in-depth against hung result transfers.
 *
 * Fail-closed at module load: if isolated-vm isn't available the process refuses
 * to boot rather than silently degrading to a Function()-based fallback.
 */

import { Isolate, Reference, ExternalCopy } from 'isolated-vm';
import { supabase } from '../lib/supabase';
import { createActivity } from './activities';
import { getActiveExtractionId, NO_ACTIVE_RUN } from './active-extraction';
import * as dns from 'dns';
import * as net from 'net';

// ─── Types ───

export interface PolicyDependencyContext {
  name: string;
  version: string;
  license: string | null;
  openSsfScore: number | null;
  weeklyDownloads: number | null;
  lastPublishedAt: string | null;
  releasesLast12Months: number | null;
  dependencyScore: number | null;
  maliciousIndicator: { source?: string; confidence?: number; reason?: string } | null;
  slsaLevel: number | null;
}

export interface PolicyTierContext {
  name: string;
  rank: number;
  multiplier: number;
}

export interface PackagePolicyResult {
  allowed: boolean;
  reasons: string[];
}

/** Optional enrichment for preflight (registry + OpenSSF + SLSA + score). When provided, used instead of DB lookup. */
export interface PreflightEnrichedInput {
  license: string | null;
  openSsfScore: number | null;
  dependencyScore: number | null;
  slsaLevel: number | null;
  weeklyDownloads: number | null;
  releasesLast12Months: number;
  lastPublishedAt: string | null;
}

export interface ProjectStatusResult {
  status: string;
  violations: string[];
}

/** Result from pullRequestCheck: pass or block the PR. */
export interface PRCheckResult {
  passed: boolean;
  violations: string[];
}

export interface PolicyValidationResult {
  syntaxPass: boolean;
  syntaxError?: string;
  shapePass: boolean;
  shapeError?: string;
  fetchResiliencePass: boolean;
  fetchResilienceError?: string;
  allPassed: boolean;
}

// ─── SSRF Protection ───

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^fc00:/i,
  /^fd/i,
  /^fe80:/i,
];

function isPrivateIP(ip: string): boolean {
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

async function resolveAndCheckSSRF(urlStr: string): Promise<void> {
  const parsed = new URL(urlStr);
  const hostname = parsed.hostname;

  if (net.isIP(hostname)) {
    if (isPrivateIP(hostname)) {
      throw new Error(`fetch() blocked: cannot connect to private/internal network address (${hostname})`);
    }
    return;
  }

  return new Promise((resolve, reject) => {
    dns.resolve4(hostname, (err, addresses) => {
      if (err) {
        reject(new Error(`fetch() failed: DNS resolution error for ${hostname}`));
        return;
      }
      for (const addr of addresses) {
        if (isPrivateIP(addr)) {
          reject(new Error(`fetch() blocked: cannot connect to private/internal network address (${addr})`));
          return;
        }
      }
      resolve();
    });
  });
}

// ─── Controlled fetch() ───

async function controlledFetch(
  urlStr: string,
  organizationId?: string,
  codeType?: string,
): Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }> {
  await resolveAndCheckSSRF(urlStr);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  const start = Date.now();
  try {
    const response = await fetch(urlStr, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Deptex-Policy-Engine/1.0' },
    });

    const duration = Date.now() - start;

    if (organizationId) {
      const redactedUrl = new URL(urlStr);
      redactedUrl.search = '';
      createActivity({
        organization_id: organizationId,
        activity_type: 'policy_fetch',
        description: `Policy fetch to ${redactedUrl.origin}${redactedUrl.pathname}`,
        metadata: {
          url: `${redactedUrl.origin}${redactedUrl.pathname}`,
          status: response.status,
          duration_ms: duration,
          code_type: codeType,
        },
      }).catch(() => {});
    }

    const bodyText = await response.text();
    return {
      ok: response.ok,
      status: response.status,
      json: async () => JSON.parse(bodyText),
      text: async () => bodyText,
    };
  } finally {
    clearTimeout(timeout);
  }
}

// ─── Helper functions injected into sandbox ───

function isLicenseAllowed(license: string | null, allowList: string[]): boolean {
  if (!license) return true;
  const norm = license.toLowerCase().replace(/[-_]/g, ' ').trim();
  return allowList.some((a) => {
    const aNorm = a.toLowerCase().replace(/[-_]/g, ' ').trim();
    return norm.includes(aNorm) || aNorm.includes(norm);
  });
}

function isLicenseBanned(license: string | null, banList: string[]): boolean {
  if (!license) return false;
  const norm = license.toLowerCase().replace(/[-_]/g, ' ').trim();
  return banList.some((b) => {
    const bNorm = b.toLowerCase().replace(/[-_]/g, ' ').trim();
    return norm.includes(bNorm) || bNorm.includes(norm);
  });
}

function semverGt(a: string, b: string): boolean {
  try {
    const semver = require('semver');
    return semver.gt(a, b);
  } catch {
    return a > b;
  }
}

function semverLt(a: string, b: string): boolean {
  try {
    const semver = require('semver');
    return semver.lt(a, b);
  } catch {
    return a < b;
  }
}

function daysSince(dateString: string): number {
  const then = new Date(dateString).getTime();
  if (isNaN(then)) return Infinity;
  return Math.floor((Date.now() - then) / (1000 * 60 * 60 * 24));
}

// ─── Sandbox execution (isolated-vm with snapshot-warm-restore) ───

const EXECUTION_TIMEOUT_MS = 30_000;
const VALIDATION_TIMEOUT_MS = 5_000;
const MEMORY_LIMIT_MB = 32;
const RETURN_CAP_BYTES = 256 * 1024; // 256KB
const RESULT_COPY_TIMEOUT_MS = 200;
const MAX_FETCHES_PER_EXECUTION = 10;

// Process-wide V8 startup snapshot. Built once at module load; reused for every
// per-call isolate so V8 doesn't pay heap-init cost on the hot path.
//
// `runPackagePolicy` runs per-dependency in `evaluateProjectPolicies` (100–1500
// deps for typical → large monorepos). Without this snapshot, a 1500-dep sweep
// adds ~75s to extraction time; with it, ~1–2s. See plan M0 acceptance gate.
let BOOTSTRAP_SNAPSHOT: ExternalCopy<ArrayBuffer> | null = null;

function ensureSnapshot(): ExternalCopy<ArrayBuffer> {
  if (BOOTSTRAP_SNAPSHOT) return BOOTSTRAP_SNAPSHOT;
  // Empty snapshot is enough — we just want V8 startup state pre-baked.
  // Helpers can't live in the snapshot (host references aren't serializable);
  // they're attached per-call to the fresh isolate's context.
  BOOTSTRAP_SNAPSHOT = Isolate.createSnapshot([{ code: 'void 0;' }]);
  return BOOTSTRAP_SNAPSHOT;
}

// Fail-closed at module load. If isolated-vm can't build the snapshot the
// process refuses to start — no Function() fallback at any tier.
try {
  ensureSnapshot();
} catch (err) {
  // eslint-disable-next-line no-console
  console.error('[policy-engine] Failed to initialize isolated-vm snapshot:', err);
  throw new Error('isolated-vm unavailable; refusing to start policy engine');
}

export interface ExecuteOptions {
  code: string;
  functionName: string;
  context: Record<string, unknown>;
  timeoutMs?: number;
  organizationId?: string;
  codeType?: string;
  mockFetch?: (url: string) => Promise<unknown>;
}

/**
 * Run user-supplied JS in the per-call isolated-vm sandbox.
 *
 * Exposed for `flow-code/sandbox.ts` to reuse the same hardened engine. New
 * call sites should NOT invoke this directly — wrap it in a contract-aware
 * helper so return-shape validation lives next to the caller's expectations.
 */
export async function executePolicyFunction(opts: ExecuteOptions): Promise<unknown> {
  const {
    code,
    functionName,
    context,
    timeoutMs = EXECUTION_TIMEOUT_MS,
    organizationId,
    codeType,
    mockFetch,
  } = opts;

  let fetchCount = 0;
  const rawFetch = mockFetch
    ? mockFetch
    : (urlStr: string) => controlledFetch(urlStr, organizationId, codeType);

  // Host-side fetch helper: returns plain serializable data. The legacy `json()`
  // / `text()` methods are synthesized inside the isolate from the cached body,
  // since functions can't cross the isolate boundary.
  const fetchHostFn = async (
    urlStr: string,
  ): Promise<{ ok: boolean; status: number; bodyText: string }> => {
    if (++fetchCount > MAX_FETCHES_PER_EXECUTION) {
      throw new Error(
        `fetch() limit exceeded: maximum ${MAX_FETCHES_PER_EXECUTION} requests per policy execution`,
      );
    }
    const resp = (await rawFetch(urlStr)) as {
      ok?: boolean;
      status?: number;
      text?: () => Promise<string>;
    };
    const bodyText = typeof resp?.text === 'function' ? await resp.text() : '';
    return {
      ok: !!resp?.ok,
      status: typeof resp?.status === 'number' ? resp.status : 0,
      bodyText,
    };
  };

  const isolate = new Isolate({
    memoryLimit: MEMORY_LIMIT_MB,
    snapshot: ensureSnapshot(),
  });

  try {
    const ctx = isolate.createContextSync();
    const jail = ctx.global;
    jail.setSync('global', jail.derefInto());

    // Install host references. applySync/copy used inside the isolate to call back.
    jail.setSync('__fetchRef', new Reference(fetchHostFn));
    jail.setSync('__isLicenseAllowedRef', new Reference(isLicenseAllowed));
    jail.setSync('__isLicenseBannedRef', new Reference(isLicenseBanned));
    jail.setSync('__semverGtRef', new Reference(semverGt));
    jail.setSync('__semverLtRef', new Reference(semverLt));
    jail.setSync('__daysSinceRef', new Reference(daysSince));

    // Inject context as a structured-cloned copy. release: true frees the source buffer.
    jail.setSync(
      '__context',
      new ExternalCopy(context).copyInto({ release: true }),
    );

    // The wrapper (a) declares helper proxies that bridge to host references,
    // (b) runs the user's code (function declaration is hoisted),
    // (c) calls the policy function with helpers merged into context (legacy parity),
    // (d) JSON.stringifies the result and enforces the return-size cap inside the isolate.
    const wrapped = `
'use strict';

const fetch = async (urlStr) => {
  const raw = await __fetchRef.apply(undefined, [urlStr], {
    arguments: { copy: true },
    result: { promise: true, copy: true },
  });
  return {
    ok: raw.ok,
    status: raw.status,
    json: async () => JSON.parse(raw.bodyText),
    text: async () => raw.bodyText,
  };
};

const isLicenseAllowed = (license, list) =>
  __isLicenseAllowedRef.applySync(undefined, [license, list], { arguments: { copy: true }, result: { copy: true } });
const isLicenseBanned = (license, list) =>
  __isLicenseBannedRef.applySync(undefined, [license, list], { arguments: { copy: true }, result: { copy: true } });
const semverGt = (a, b) =>
  __semverGtRef.applySync(undefined, [a, b], { arguments: { copy: true }, result: { copy: true } });
const semverLt = (a, b) =>
  __semverLtRef.applySync(undefined, [a, b], { arguments: { copy: true }, result: { copy: true } });
const daysSince = (d) =>
  __daysSinceRef.applySync(undefined, [d], { arguments: { copy: true }, result: { copy: true } });

${code}

if (typeof ${functionName} !== 'function') {
  throw new Error('Expected function \`${functionName}\` to be defined.');
}

const __ctxWithHelpers = Object.assign({}, __context, {
  fetch, isLicenseAllowed, isLicenseBanned, semverGt, semverLt, daysSince,
});

(async () => {
  const result = await ${functionName}(__ctxWithHelpers);
  if (result === undefined) return undefined;
  const json = JSON.stringify(result);
  if (typeof json === 'string' && json.length > ${RETURN_CAP_BYTES}) {
    throw new Error('Policy return value exceeds ' + ${RETURN_CAP_BYTES / 1024} + 'KB cap');
  }
  return json;
})()
`;

    const script = isolate.compileScriptSync(wrapped);

    // script.run with promise: true awaits the inner async IIFE.
    // result: { reference: true } returns a Reference (no implicit copy) so we can
    // race the explicit copy() against the 200ms post-execution timeout.
    const refResult = (await script.run(ctx, {
      timeout: timeoutMs,
      promise: true,
      reference: true,
    })) as Reference<string | undefined>;

    let copyTimer: NodeJS.Timeout | undefined;
    try {
      const json = await Promise.race([
        refResult.copy(),
        new Promise<never>((_, reject) => {
          copyTimer = setTimeout(() => {
            reject(
              new Error(
                `Policy result copy exceeded ${RESULT_COPY_TIMEOUT_MS}ms post-execution`,
              ),
            );
          }, RESULT_COPY_TIMEOUT_MS);
        }),
      ]);
      if (typeof json !== 'string') return undefined;
      return JSON.parse(json);
    } finally {
      if (copyTimer) clearTimeout(copyTimer);
      try { refResult.release(); } catch { /* already released */ }
    }
  } finally {
    if (!isolate.isDisposed) {
      try { isolate.dispose(); } catch { /* already disposed */ }
    }
  }
}

// ─── Public API ───

/**
 * Run packagePolicy() against a single dependency.
 */
export async function runPackagePolicy(
  code: string,
  dependency: PolicyDependencyContext,
  tier: PolicyTierContext,
  organizationId?: string,
): Promise<PackagePolicyResult> {
  try {
    const result = await executePolicyFunction({
      code,
      functionName: 'packagePolicy',
      context: { dependency, tier },
      organizationId,
      codeType: 'package_policy',
    });

    return validatePackagePolicyResult(result);
  } catch (err: any) {
    return {
      allowed: false,
      reasons: [`Policy execution error: ${err.message}`],
    };
  }
}

/**
 * Run projectStatus() against project data.
 */
export async function runProjectStatus(
  code: string,
  projectContext: Record<string, unknown>,
  organizationId?: string,
): Promise<ProjectStatusResult> {
  try {
    const result = await executePolicyFunction({
      code,
      functionName: 'projectStatus',
      context: projectContext,
      organizationId,
      codeType: 'project_status',
    });

    return validateProjectStatusResult(result);
  } catch (err: any) {
    return {
      status: 'Non-Compliant',
      violations: [`Policy execution error: ${err.message}`],
    };
  }
}

/**
 * Run pullRequestCheck() against PR diff data.
 * Policy must return { passed: boolean, violations: string[] }. passed: true allows the merge, passed: false blocks it.
 */
export async function runPRCheck(
  code: string,
  prContext: Record<string, unknown>,
  organizationId?: string,
): Promise<PRCheckResult> {
  try {
    const result = await executePolicyFunction({
      code,
      functionName: 'pullRequestCheck',
      context: prContext,
      organizationId,
      codeType: 'pr_check',
    });

    const { passed, violations } = validatePRCheckResult(result);
    return { passed, violations };
  } catch (err: any) {
    return {
      passed: false,
      violations: [`Policy execution error: ${err.message}`],
    };
  }
}

// ─── Validation ───

function validatePackagePolicyResult(result: unknown): PackagePolicyResult {
  if (!result || typeof result !== 'object') {
    throw new Error('packagePolicy must return an object');
  }
  const r = result as Record<string, unknown>;

  if (typeof r.allowed !== 'boolean') {
    throw new Error('packagePolicy must return { allowed: boolean, reasons: string[] }. `allowed` is not a boolean.');
  }

  if (!Array.isArray(r.reasons)) {
    throw new Error('Expected `reasons` to be string[], got ' + typeof r.reasons);
  }

  for (const reason of r.reasons) {
    if (typeof reason !== 'string') {
      throw new Error('Expected all items in `reasons` to be strings');
    }
  }

  return { allowed: r.allowed, reasons: r.reasons as string[] };
}

function validateProjectStatusResult(result: unknown): ProjectStatusResult {
  if (!result || typeof result !== 'object') {
    throw new Error('Function must return an object');
  }
  const r = result as Record<string, unknown>;

  if (typeof r.status !== 'string' || !r.status.trim()) {
    throw new Error('Function must return { status: string, violations: string[] }. `status` is not a non-empty string.');
  }

  if (!Array.isArray(r.violations)) {
    throw new Error('Expected `violations` to be string[], got ' + typeof r.violations);
  }

  return { status: r.status, violations: r.violations as string[] };
}

/** Validates pullRequestCheck return: must be { passed: boolean, violations: string[] }. */
function validatePRCheckResult(result: unknown): { passed: boolean; violations: string[] } {
  if (!result || typeof result !== 'object') {
    throw new Error('pullRequestCheck must return an object');
  }
  const r = result as Record<string, unknown>;

  if (typeof r.passed !== 'boolean') {
    throw new Error('pullRequestCheck must return { passed: boolean, violations: string[] }. `passed` must be a boolean.');
  }

  if (!Array.isArray(r.violations)) {
    throw new Error('pullRequestCheck must return { passed: boolean, violations: string[] }. `violations` must be a string array.');
  }
  for (const v of r.violations) {
    if (typeof v !== 'string') {
      throw new Error('Expected all items in `violations` to be strings');
    }
  }

  return { passed: r.passed, violations: r.violations as string[] };
}

/**
 * 3-step policy code validation (blocks save on failure).
 */
export async function validatePolicyCode(
  code: string,
  codeType: 'package_policy' | 'project_status' | 'pr_check',
  organizationId: string,
): Promise<PolicyValidationResult> {
  const result: PolicyValidationResult = {
    syntaxPass: false,
    shapePass: false,
    fetchResiliencePass: true,
    allPassed: false,
  };

  if (!code || !code.trim()) {
    result.syntaxError = 'Policy code cannot be empty';
    return result;
  }

  if (code.length > 50_000) {
    result.syntaxError = 'Policy code exceeds 50KB limit';
    return result;
  }

  const functionName = codeType === 'package_policy' ? 'packagePolicy'
    : codeType === 'project_status' ? 'projectStatus'
    : 'pullRequestCheck';

  // Check 1: Syntax — parse-only via isolated-vm. compileScript validates the
  // script in V8 without executing; the probe isolate is disposed immediately.
  try {
    const probe = new Isolate({ memoryLimit: 8, snapshot: ensureSnapshot() });
    try {
      probe.compileScriptSync(code);
    } finally {
      probe.dispose();
    }
    result.syntaxPass = true;
  } catch (err: any) {
    result.syntaxError = `SyntaxError: ${err.message}`;
    return result;
  }

  // Check 2: Shape validation with sample data
  const sampleContext = buildSampleContext(codeType, organizationId);
  try {
    const testResult = await executePolicyFunction({
      code,
      functionName,
      context: sampleContext,
      timeoutMs: VALIDATION_TIMEOUT_MS,
    });

    if (codeType === 'package_policy') {
      validatePackagePolicyResult(testResult);
    } else if (codeType === 'pr_check') {
      validatePRCheckResult(testResult);
    } else {
      validateProjectStatusResult(testResult);
    }
    result.shapePass = true;
  } catch (err: any) {
    let shapeError = err.message;
    if (codeType === 'package_policy' && /dependencies.*not iterable|not iterable.*dependencies/i.test(shapeError)) {
      shapeError += ' Hint: packagePolicy receives context.dependency (one object) per call, not context.dependencies.';
    }
    result.shapeError = shapeError;
    return result;
  }

  // Check 3: Fetch resilience (only if code contains fetch())
  if (code.includes('fetch(')) {
    try {
      await executePolicyFunction({
        code,
        functionName,
        context: sampleContext,
        timeoutMs: VALIDATION_TIMEOUT_MS,
        mockFetch: async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '' }),
      });
    } catch (err: any) {
      result.fetchResilienceError = `Code crashes when fetch succeeds: ${err.message}`;
      result.fetchResiliencePass = false;
      return result;
    }

    try {
      const failResult = await executePolicyFunction({
        code,
        functionName,
        context: sampleContext,
        timeoutMs: VALIDATION_TIMEOUT_MS,
        mockFetch: async () => { throw new Error('Network request failed'); },
      });

      if (codeType === 'package_policy') {
        validatePackagePolicyResult(failResult);
      } else if (codeType === 'pr_check') {
        validatePRCheckResult(failResult);
      } else {
        validateProjectStatusResult(failResult);
      }
      result.fetchResiliencePass = true;
    } catch (err: any) {
      result.fetchResiliencePass = false;
      result.fetchResilienceError = `Code crashes when fetch() fails. Wrap fetch calls in try/catch with a fallback return value. Error: ${err.message}`;
      return result;
    }
  }

  result.allPassed = result.syntaxPass && result.shapePass && result.fetchResiliencePass;
  return result;
}

// ─── Sample context builders for validation ───

function buildSampleContext(
  codeType: 'package_policy' | 'project_status' | 'pr_check',
  _organizationId: string,
): Record<string, unknown> {
  if (codeType === 'package_policy') {
    return {
      dependency: {
        name: 'test-pkg',
        version: '1.0.0',
        license: 'MIT',
        openSsfScore: 7.5,
        weeklyDownloads: 100000,
        lastPublishedAt: new Date().toISOString(),
        releasesLast12Months: 12,
        dependencyScore: 75,
        maliciousIndicator: null,
        slsaLevel: 0,
      },
      tier: { name: 'Internal', rank: 3, multiplier: 1.0 },
    };
  }

  const sampleDeps = [
    {
      name: 'safe-pkg',
      version: '2.0.0',
      license: 'MIT',
      dependencyScore: 85,
      policyResult: { allowed: true, reasons: [] },
      isDirect: true,
      isDevDependency: false,
      filesImportingCount: 5,
      isOutdated: false,
      versionsBehind: 0,
      vulnerabilities: [],
    },
    {
      name: 'risky-pkg',
      version: '0.1.0',
      license: 'AGPL-3.0',
      dependencyScore: 25,
      policyResult: { allowed: false, reasons: ['AGPL not allowed'] },
      isDirect: true,
      isDevDependency: false,
      filesImportingCount: 2,
      isOutdated: true,
      versionsBehind: 3,
      vulnerabilities: [
        {
          osvId: 'GHSA-test-0001',
          severity: 'high',
          cvssScore: 7.5,
          epssScore: 0.02,
          depscore: 55,
          isReachable: false,
          cisaKev: false,
          fixedVersions: ['0.2.0'],
          summary: 'Test vulnerability',
        },
      ],
    },
  ];

  if (codeType === 'project_status') {
    return {
      project: { name: 'test-project', tier: { name: 'Internal', rank: 3, multiplier: 1.0 }, teamName: 'Test Team' },
      dependencies: sampleDeps,
      statuses: ['Compliant', 'Non-Compliant'],
    };
  }

  // pr_check (richer context: ecosystem, changed_files, per-dep license, vulnerability_counts, is_direct)
  return {
    project: { name: 'test-project', id: 'test-project-id', asset_tier: 'Internal', tier: { name: 'Internal', rank: 3, multiplier: 1.0 } },
    ecosystem: 'npm',
    changed_files: ['package.json', 'package-lock.json'],
    added: [
      {
        ...sampleDeps[0],
        license: 'MIT',
        is_direct: true,
        vulnerability_counts: { critical: 0, high: 0, medium: 0, low: 0 },
      },
    ],
    updated: [],
    removed: [],
    statuses: ['Compliant', 'Non-Compliant'],
  };
}

// ─── Full policy evaluation chain ───

/**
 * Run the full policy chain for a project:
 * 1. Load tier + policy code
 * 2. Run packagePolicy per dep -> store policy_result
 * 3. Run projectStatus -> update projects.status_id + violations
 */
export async function evaluateProjectPolicies(
  projectId: string,
  organizationId: string,
): Promise<{ statusName: string; violations: string[]; depResults: number }> {
  // Load project's tier + active extraction run id (Phase 19 soft-switch).
  // Policy evaluation reads the project's CURRENT findings — not stale rows
  // from prior extractions still living in the DB until reaped.
  const activeRunId = (await getActiveExtractionId(supabase, projectId)) ?? NO_ACTIVE_RUN;

  const { data: project } = await supabase
    .from('projects')
    .select('id, name, asset_tier_id, effective_package_policy_code, effective_project_status_code')
    .eq('id', projectId)
    .single();

  if (!project) throw new Error(`Project ${projectId} not found`);

  let tier: PolicyTierContext = { name: 'Internal', rank: 3, multiplier: 1.0 };
  if (project.asset_tier_id) {
    const { data: tierData } = await supabase
      .from('organization_asset_tiers')
      .select('name, rank, environmental_multiplier')
      .eq('id', project.asset_tier_id)
      .single();

    if (tierData) {
      tier = { name: tierData.name, rank: tierData.rank, multiplier: Number(tierData.environmental_multiplier) };
    }
  }

  // Load package policy code
  let packagePolicyCode: string | null = project.effective_package_policy_code;
  if (!packagePolicyCode) {
    const { data: orgPolicy } = await supabase
      .from('organization_package_policies')
      .select('package_policy_code')
      .eq('organization_id', organizationId)
      .single();
    packagePolicyCode = orgPolicy?.package_policy_code || null;
  }

  // Load deps (exclude soft-deleted from prior extractions)
  const { data: deps } = await supabase
    .from('project_dependencies')
    .select(`
      id, dependency_id, is_direct, is_dev_dependency, files_importing_count,
      is_outdated, versions_behind,
      dependencies!inner(name, version, license, openssf_score, weekly_downloads,
        last_published_at, releases_last_12_months, score, ecosystem),
      dependency_versions!inner(malicious_indicator, slsa_level)
    `)
    .eq('project_id', projectId)
    .is('removed_at', null);

  const projectDeps = deps ?? [];

  // Run packagePolicy on each dep when org/project has policy code; otherwise set default "allowed"
  // so the UI has an explicit policy_result and doesn't fall back to empty accepted_licenses.
  if (projectDeps.length > 0) {
    const defaultResult = { allowed: true as const, reasons: [] as string[] };
    for (const dep of projectDeps) {
      if (packagePolicyCode) {
        const depData = (dep as any).dependencies;
        const versionData = (dep as any).dependency_versions;

        const depContext: PolicyDependencyContext = {
          name: depData?.name ?? '',
          version: depData?.version ?? '',
          license: depData?.license ?? null,
          openSsfScore: depData?.openssf_score ?? null,
          weeklyDownloads: depData?.weekly_downloads ?? null,
          lastPublishedAt: depData?.last_published_at ?? null,
          releasesLast12Months: depData?.releases_last_12_months ?? null,
          dependencyScore: depData?.score ?? null,
          maliciousIndicator: versionData?.malicious_indicator ?? null,
          slsaLevel: versionData?.slsa_level ?? null,
        };

        const policyResult = await runPackagePolicy(packagePolicyCode, depContext, tier, organizationId);

        await supabase
          .from('project_dependencies')
          .update({ policy_result: policyResult })
          .eq('id', dep.id);
      } else {
        await supabase
          .from('project_dependencies')
          .update({ policy_result: defaultResult })
          .eq('id', dep.id);
      }
    }
  }

  // Load project status code
  let statusCode: string | null = project.effective_project_status_code;
  if (!statusCode) {
    const { data: orgStatus } = await supabase
      .from('organization_status_codes')
      .select('project_status_code')
      .eq('organization_id', organizationId)
      .single();
    statusCode = orgStatus?.project_status_code || null;
  }

  // Get org statuses for context
  const { data: orgStatuses } = await supabase
    .from('organization_statuses')
    .select('name, rank, is_passing')
    .eq('organization_id', organizationId)
    .order('rank', { ascending: true });

  const statusNames = (orgStatuses ?? []).map((s: any) => s.name);

  // Re-load deps with policy_result for projectStatus context (exclude soft-deleted)
  const { data: enrichedDeps } = await supabase
    .from('project_dependencies')
    .select(`
      id, dependency_id, is_direct, is_dev_dependency, files_importing_count,
      is_outdated, versions_behind, policy_result,
      dependencies!inner(name, version, license, score)
    `)
    .eq('project_id', projectId)
    .is('removed_at', null);

  // Load vulns per dep — only the active extraction run's findings.
  const depContextForStatus = await Promise.all(
    (enrichedDeps ?? []).map(async (dep: any) => {
      const { data: vulns } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('osv_id, severity, cvss_score, epss_score, depscore, is_reachable, cisa_kev, fixed_versions, summary')
        .eq('project_dependency_id', dep.id)
        .eq('extraction_run_id', activeRunId);

      return {
        name: dep.dependencies?.name ?? '',
        version: dep.dependencies?.version ?? '',
        license: dep.dependencies?.license ?? null,
        dependencyScore: dep.dependencies?.score ?? null,
        policyResult: dep.policy_result ?? { allowed: true, reasons: [] },
        isDirect: dep.is_direct ?? true,
        isDevDependency: dep.is_dev_dependency ?? false,
        filesImportingCount: dep.files_importing_count ?? 0,
        isOutdated: dep.is_outdated ?? false,
        versionsBehind: dep.versions_behind ?? 0,
        vulnerabilities: (vulns ?? []).map((v: any) => ({
          osvId: v.osv_id,
          severity: v.severity,
          cvssScore: v.cvss_score,
          epssScore: v.epss_score,
          depscore: v.depscore,
          isReachable: v.is_reachable ?? false,
          cisaKev: v.cisa_kev ?? false,
          fixedVersions: v.fixed_versions ?? [],
          summary: v.summary ?? '',
        })),
      };
    }),
  );

  // Default: "Compliant" if no status code
  let statusResult: ProjectStatusResult = { status: 'Compliant', violations: [] };

  if (statusCode) {
    const projectStatusContext = {
      project: { name: project.name, tier, teamName: '' },
      dependencies: depContextForStatus,
      statuses: statusNames,
    };

    statusResult = await runProjectStatus(statusCode, projectStatusContext, organizationId);
  } else {
    const hasDisallowed = depContextForStatus.some((d) => d.policyResult && !d.policyResult.allowed);
    if (hasDisallowed) {
      statusResult = { status: 'Non-Compliant', violations: ['Disallowed dependencies found'] };
    }
  }

  // Map status name to status_id
  const matchedStatus = (orgStatuses ?? []).find(
    (s: any) => s.name.toLowerCase() === statusResult.status.toLowerCase(),
  );

  if (matchedStatus) {
    await supabase
      .from('projects')
      .update({
        status_id: (matchedStatus as any).id,
        status_violations: statusResult.violations,
        policy_evaluated_at: new Date().toISOString(),
        is_compliant: (matchedStatus as any).is_passing,
      })
      .eq('id', projectId);
  } else {
    const nonCompliant = (orgStatuses ?? []).find((s: any) => s.name === 'Non-Compliant');
    await supabase
      .from('projects')
      .update({
        status_id: nonCompliant ? (nonCompliant as any).id : null,
        status_violations: [`Policy returned unknown status '${statusResult.status}'`],
        policy_evaluated_at: new Date().toISOString(),
        is_compliant: false,
      })
      .eq('id', projectId);
  }

  return {
    statusName: statusResult.status,
    violations: statusResult.violations,
    depResults: projectDeps.length,
  };
}

/**
 * Run preflight check on a single hypothetical dependency.
 * Uses the project's (or org's) package policy code in the same sandbox as evaluateProjectPolicies.
 * When enriched is provided (e.g. from enrichPackageForPreflight), uses it for context and return values; otherwise uses DB lookup.
 */
export async function preflightCheck(
  organizationId: string,
  projectId: string,
  packageName: string,
  packageVersion: string,
  enriched?: PreflightEnrichedInput | null,
): Promise<
  PackagePolicyResult & {
    tierName: string;
    license: string | null;
    dependencyScore: number | null;
    openSsfScore: number | null;
    slsaLevel: number | null;
  }
> {
  const { data: project } = await supabase
    .from('projects')
    .select('asset_tier_id, effective_package_policy_code')
    .eq('id', projectId)
    .single();

  let tier: PolicyTierContext = { name: 'Internal', rank: 3, multiplier: 1.0 };
  if (project?.asset_tier_id) {
    const { data: tierData } = await supabase
      .from('organization_asset_tiers')
      .select('name, rank, environmental_multiplier')
      .eq('id', project.asset_tier_id)
      .single();
    if (tierData) {
      tier = { name: tierData.name, rank: tierData.rank, multiplier: Number(tierData.environmental_multiplier) };
    }
  }

  let packagePolicyCode = project?.effective_package_policy_code;
  if (!packagePolicyCode) {
    const { data: orgPolicy } = await supabase
      .from('organization_package_policies')
      .select('package_policy_code')
      .eq('organization_id', organizationId)
      .single();
    packagePolicyCode = orgPolicy?.package_policy_code;
  }

  if (!packagePolicyCode) {
    return { allowed: true, reasons: [], tierName: tier.name, license: null, dependencyScore: null, openSsfScore: null, slsaLevel: null };
  }

  let license: string | null = null;
  let openSsfScore: number | null = null;
  let dependencyScore: number | null = null;
  let slsaLevel: number | null = null;
  let weeklyDownloads: number | null = null;
  let lastPublishedAt: string | null = null;
  let releasesLast12Months: number = 0;

  if (enriched) {
    license = enriched.license;
    openSsfScore = enriched.openSsfScore;
    dependencyScore = enriched.dependencyScore;
    slsaLevel = enriched.slsaLevel;
    weeklyDownloads = enriched.weeklyDownloads;
    lastPublishedAt = enriched.lastPublishedAt;
    releasesLast12Months = enriched.releasesLast12Months;
  } else {
    const { data: existingDep } = await supabase
      .from('dependencies')
      .select('id, name, license, openssf_score, weekly_downloads, last_published_at, releases_last_12_months, score')
      .eq('name', packageName)
      .single();
    if (existingDep) {
      license = existingDep.license ?? null;
      openSsfScore = existingDep.openssf_score ?? null;
      dependencyScore = existingDep.score ?? null;
      weeklyDownloads = existingDep.weekly_downloads ?? null;
      lastPublishedAt = existingDep.last_published_at ?? null;
      releasesLast12Months = existingDep.releases_last_12_months ?? 0;
      if (existingDep.id) {
        const { data: versionRow } = await supabase
          .from('dependency_versions')
          .select('slsa_level')
          .eq('dependency_id', existingDep.id)
          .eq('version', packageVersion)
          .maybeSingle();
        if (versionRow?.slsa_level != null) slsaLevel = versionRow.slsa_level;
      }
    }
  }

  const depContext: PolicyDependencyContext = {
    name: packageName,
    version: packageVersion,
    license,
    openSsfScore,
    weeklyDownloads,
    lastPublishedAt,
    releasesLast12Months,
    dependencyScore,
    maliciousIndicator: null,
    slsaLevel,
  };

  const result = await runPackagePolicy(packagePolicyCode, depContext, tier, organizationId);
  return {
    ...result,
    tierName: tier.name,
    license,
    dependencyScore,
    openSsfScore,
    slsaLevel,
  };
}
