/**
 * Phase 9: Notification trigger code validation and execution.
 *
 * Replicates the policy-engine.ts sandbox pattern with notification-specific
 * adjustments: shorter timeout, lower fetch limit, and notification-shaped
 * return values.
 */

import * as dns from 'dns';
import * as net from 'net';

// ─── Types ───

export interface NotificationValidationResult {
  passed: boolean;
  checks: Array<{ name: string; pass: boolean; error?: string }>;
}

interface NormalizedTriggerResult {
  notify: boolean;
  message?: string;
  title?: string;
  priority?: string;
}

// ─── SSRF Protection (mirrors policy-engine.ts) ───

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

// ─── Controlled fetch for notification triggers ───

const EXECUTION_TIMEOUT_MS = 10_000;
const VALIDATION_TIMEOUT_MS = 5_000;
const MAX_FETCHES_PER_EXECUTION = 5;

async function controlledFetch(
  urlStr: string,
  organizationId?: string,
): Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }> {
  await resolveAndCheckSSRF(urlStr);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const response = await fetch(urlStr, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Deptex-Notification-Engine/1.0' },
    });

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

// ─── Sandbox Execution ───

interface ExecuteOptions {
  code: string;
  context: Record<string, unknown>;
  timeoutMs?: number;
  organizationId?: string;
  mockFetch?: (url: string) => Promise<unknown>;
}

async function executeTriggerFunction(opts: ExecuteOptions): Promise<unknown> {
  const {
    code,
    context,
    timeoutMs = EXECUTION_TIMEOUT_MS,
    organizationId,
    mockFetch,
  } = opts;

  let fetchCount = 0;

  const rawFetch = mockFetch
    ? mockFetch
    : (urlStr: string) => controlledFetch(urlStr, organizationId);

  const fetchFn = (urlStr: string) => {
    if (++fetchCount > MAX_FETCHES_PER_EXECUTION) {
      throw new Error(`fetch() limit exceeded: maximum ${MAX_FETCHES_PER_EXECUTION} requests per notification trigger execution`);
    }
    return rawFetch(urlStr);
  };

  // AI assistant and docs use a function *body* with `context` in scope (no wrapper).
  // Legacy code may define `function notificationTrigger(context) { ... }` — support both.
  const hasLegacyNotificationTrigger =
    /\bfunction\s+notificationTrigger\s*\(/.test(code) ||
    /\bnotificationTrigger\s*=\s*(?:async\s*)?function\s*\(/.test(code);

  const wrappedCode = hasLegacyNotificationTrigger
    ? `
    ${code}

    if (typeof notificationTrigger !== 'function') {
      throw new Error('Expected function \`notificationTrigger\` to be defined.');
    }

    return (async () => notificationTrigger(__context))();
  `
    : `
    // Body-style trigger: context is the first parameter (same object the dispatcher passes).
    return (async function(context) {
      ${code}
    })(__context);
  `;

  const asyncFn = new Function(
    '__context',
    'fetch',
    wrappedCode,
  );

  return new Promise(async (resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Notification trigger execution timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    try {
      const result = await asyncFn({ ...context, fetch: fetchFn }, fetchFn);
      clearTimeout(timer);
      resolve(result);
    } catch (err) {
      clearTimeout(timer);
      reject(err);
    }
  });
}

// ─── Return value normalization ───

function normalizeReturn(result: any): NormalizedTriggerResult {
  if (typeof result === 'boolean') return { notify: result };
  if (result && typeof result === 'object' && 'notify' in result) return result;
  if (result) return { notify: true };
  return { notify: false };
}

// ─── Sample contexts for validation ───

const SAMPLE_CONTEXTS: Record<string, Record<string, unknown>> = {
  vulnerability_discovered: {
    event: { type: 'vulnerability_discovered', priority: 'high' },
    project: { name: 'my-app', tier: 'Internal', framework: 'react' },
    dependency: { name: 'lodash', version: '4.17.20', isDirect: true },
    vulnerability: {
      osvId: 'GHSA-test-0001',
      severity: 'high',
      cvssScore: 7.5,
      epssScore: 0.02,
      cisaKev: false,
      fixedVersions: ['4.17.21'],
      summary: 'Prototype Pollution in lodash',
      isReachable: true,
      reachabilityLevel: 'function',
      depscore: 62,
    },
    batch: { totalVulns: 1 },
  },

  dependency_added: {
    event: { type: 'dependency_added', priority: 'normal' },
    project: { name: 'my-app', tier: 'Internal', framework: 'react' },
    dependency: { name: 'new-package', version: '1.0.0', isDirect: true, license: 'MIT', score: 75 },
    batch: { totalAdded: 1 },
  },

  status_changed: {
    event: { type: 'status_changed', priority: 'normal' },
    project: { name: 'my-app', tier: 'Internal', framework: 'react' },
    previous: { status: 'Compliant' },
    batch: { totalChanged: 1 },
  },

  extraction_completed: {
    event: { type: 'extraction_completed', priority: 'low' },
    project: { name: 'my-app', tier: 'Internal', framework: 'react' },
    batch: {
      totalDependencies: 42,
      totalVulnerabilities: 3,
      durationMs: 85_000,
    },
  },

  pr_check_completed: {
    event: { type: 'pr_check_completed', priority: 'normal' },
    project: { name: 'my-app', tier: 'Internal', framework: 'react' },
    pr: {
      number: 123,
      title: 'Bump lodash to 4.17.21',
      status: 'completed',
      checkResult: 'pass',
      depsAdded: 0,
      depsUpdated: 1,
      depsRemoved: 0,
    },
    batch: { totalPRs: 1 },
  },

  malicious_package_detected: {
    event: { type: 'malicious_package_detected', priority: 'critical' },
    project: { name: 'my-app', tier: 'Crown Jewels', framework: 'react' },
    dependency: {
      name: 'evil-package',
      version: '1.0.0',
      isDirect: true,
      maliciousIndicator: { source: 'socket.dev', confidence: 0.95, reason: 'Install script downloads remote payload' },
    },
    batch: { totalMalicious: 1 },
  },
};

// ─── Public API ───

/**
 * Three-step validation that blocks save on failure:
 * 1. Syntax — can the code be parsed?
 * 2. Shape — does it return boolean or { notify, message?, title?, priority? }?
 * 3. Fetch resilience — if it uses fetch(), does it handle failures gracefully?
 */
export async function validateNotificationTriggerCode(
  code: string,
): Promise<NotificationValidationResult> {
  const checks: Array<{ name: string; pass: boolean; error?: string }> = [];

  if (!code || !code.trim()) {
    checks.push({ name: 'syntax', pass: false, error: 'Trigger code cannot be empty' });
    return { passed: false, checks };
  }

  if (code.length > 50_000) {
    checks.push({ name: 'syntax', pass: false, error: 'Trigger code exceeds 50KB limit' });
    return { passed: false, checks };
  }

  // Check 1: Syntax
  try {
    const wrappedForSyntax = `(function() {\n${code}\n})`;
    new Function(wrappedForSyntax);
    checks.push({ name: 'syntax', pass: true });
  } catch (err: any) {
    checks.push({ name: 'syntax', pass: false, error: `SyntaxError: ${err.message}` });
    return { passed: false, checks };
  }

  // Check 2: Shape — run against 3 representative sample contexts
  const shapeTestTypes = ['vulnerability_discovered', 'dependency_added', 'status_changed'];
  let shapePass = true;
  let shapeError: string | undefined;

  for (const eventType of shapeTestTypes) {
    const sampleCtx = SAMPLE_CONTEXTS[eventType];
    try {
      const raw = await executeTriggerFunction({
        code,
        context: sampleCtx,
        timeoutMs: VALIDATION_TIMEOUT_MS,
        mockFetch: async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '' }),
      });

      if (raw === undefined) {
        shapePass = false;
        shapeError = `notificationTrigger() returned undefined for "${eventType}" context. Did you forget a return statement?`;
        break;
      }

      const normalized = normalizeReturn(raw);
      if (typeof normalized.notify !== 'boolean') {
        shapePass = false;
        shapeError = `notificationTrigger() must return a boolean or { notify: boolean }. Got type "${typeof normalized.notify}" for "${eventType}".`;
        break;
      }
    } catch (err: any) {
      shapePass = false;
      shapeError = `Execution error for "${eventType}" context: ${err.message}`;
      break;
    }
  }

  checks.push({ name: 'shape', pass: shapePass, error: shapeError });
  if (!shapePass) {
    return { passed: false, checks };
  }

  // Check 3: Fetch resilience (only when code uses fetch)
  if (code.includes('fetch(')) {
    let fetchPass = true;
    let fetchError: string | undefined;

    const sampleCtx = SAMPLE_CONTEXTS['vulnerability_discovered'];

    // Pass 1: mock fetch succeeds
    try {
      await executeTriggerFunction({
        code,
        context: sampleCtx,
        timeoutMs: VALIDATION_TIMEOUT_MS,
        mockFetch: async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '' }),
      });
    } catch (err: any) {
      fetchPass = false;
      fetchError = `Code crashes when fetch succeeds: ${err.message}`;
    }

    // Pass 2: mock fetch fails
    if (fetchPass) {
      try {
        const failResult = await executeTriggerFunction({
          code,
          context: sampleCtx,
          timeoutMs: VALIDATION_TIMEOUT_MS,
          mockFetch: async () => { throw new Error('Network request failed'); },
        });

        const normalized = normalizeReturn(failResult);
        if (typeof normalized.notify !== 'boolean') {
          fetchPass = false;
          fetchError = 'Code returns invalid shape when fetch fails. Wrap fetch calls in try/catch with a fallback return value.';
        }
      } catch (err: any) {
        fetchPass = false;
        fetchError = `Code crashes when fetch() fails. Wrap fetch calls in try/catch with a fallback return value. Error: ${err.message}`;
      }
    }

    checks.push({ name: 'fetch_resilience', pass: fetchPass, error: fetchError });
    if (!fetchPass) {
      return { passed: false, checks };
    }
  }

  return {
    passed: checks.every((c) => c.pass),
    checks,
  };
}

/**
 * Execute a notification trigger against a live event context.
 * Uses SSRF-protected fetch with per-execution limits.
 */
export async function executeNotificationTrigger(
  code: string,
  context: Record<string, any>,
  organizationId?: string,
): Promise<NormalizedTriggerResult> {
  try {
    const raw = await executeTriggerFunction({
      code,
      context,
      timeoutMs: EXECUTION_TIMEOUT_MS,
      organizationId,
    });

    return normalizeReturn(raw);
  } catch (err: any) {
    console.error(JSON.stringify({
      component: 'notification-validator',
      message: 'Trigger execution failed',
      error: err.message,
      organizationId,
    }));
    return { notify: false };
  }
}
