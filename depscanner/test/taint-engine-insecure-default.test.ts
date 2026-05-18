/**
 * Tests for Phase 3.3 — insecure-default detector.
 *
 * Coverage:
 *   A. Forbidden-value mode (e.g. requests Session(verify=False)) — fire on
 *      presence + matching literal, stay silent on absence.
 *   B. Absence mode (e.g. flask session_cookie_secure missing) — fire when
 *      the kwarg is missing, stay silent when present.
 *   C. Pattern matching — wildcard receiver + bare-segment fallback all
 *      flow through `matchesCallPattern`, same as the taint sink matcher.
 *   D. Dedup — same (file, line, column, pattern) emits one finding even
 *      across multiple specs declaring the same rule.
 *
 * Run: npx tsx test/taint-engine-insecure-default.test.ts
 */

import { detectInsecureDefaults } from '../src/taint-engine/insecure-default-detector';
import type { CallSite } from '../src/taint-engine/non-taint-detector';
import type { FrameworkSpec } from '../src/taint-engine/spec';

let failures = 0;
let passes = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passes++;
  }
}

const requestsSpec: FrameworkSpec = {
  framework: 'requests',
  version: '*',
  language: 'python',
  sources: [],
  sinks: [],
  sanitizers: [],
  insecure_defaults: [
    {
      pattern: 'requests.Session(*)',
      argument_name: 'verify',
      forbidden_value_shapes: ['False'],
      vuln_class: 'weak_crypto',
      description: 'requests.Session(verify=False) disables TLS verification (CVE-2024-35195)',
    },
  ],
};

const flaskSpec: FrameworkSpec = {
  framework: 'flask',
  version: '*',
  language: 'python',
  sources: [],
  sinks: [],
  sanitizers: [],
  insecure_defaults: [
    {
      pattern: '*.config.update(*)',
      argument_name: 'SESSION_COOKIE_SECURE',
      // No forbidden_value_shapes — absence is itself the unsafe default.
      vuln_class: 'weak_crypto',
      description: 'flask SESSION_COOKIE_SECURE defaults to False (CVE-2023-30861)',
    },
  ],
};

function cs(opts: {
  callee: string;
  argTexts?: string[];
  kwargNames?: string[];
  kwargValues?: Record<string, string>;
  filePath?: string;
  line?: number;
  column?: number;
}): CallSite {
  return {
    calleeText: opts.callee,
    argTexts: opts.argTexts ?? [],
    kwargNames: opts.kwargNames ?? [],
    kwargValues: opts.kwargValues,
    filePath: opts.filePath ?? '/fixtures/app.py',
    line: opts.line ?? 1,
    column: opts.column ?? 1,
  };
}

// ---------- A. Forbidden-value mode ----------
console.log('\n[A] Forbidden-value mode — requests.Session(verify=False)');

const verifyFalse = detectInsecureDefaults({
  specs: [requestsSpec],
  callsites: [
    cs({
      callee: 'requests.Session',
      kwargNames: ['verify'],
      kwargValues: { verify: 'False' },
      filePath: '/fixtures/vuln.py',
      line: 5,
      column: 1,
    }),
  ],
});
assert(verifyFalse.length === 1, `expected 1 finding for verify=False, got ${verifyFalse.length}`);
assert(verifyFalse[0]?.trigger.reason === 'forbidden_value', 'reason is forbidden_value');
assert(verifyFalse[0]?.trigger.observed_literal === 'False', 'observed literal carried through');
assert(verifyFalse[0]?.framework === 'requests', 'attributed to requests spec');
assert(verifyFalse[0]?.vuln_class === 'weak_crypto', 'vuln_class carried from entry');

const verifyTrue = detectInsecureDefaults({
  specs: [requestsSpec],
  callsites: [
    cs({ callee: 'requests.Session', kwargNames: ['verify'], kwargValues: { verify: 'True' } }),
  ],
});
assert(verifyTrue.length === 0, `expected 0 findings for verify=True, got ${verifyTrue.length}`);

const verifyAbsent = detectInsecureDefaults({
  specs: [requestsSpec],
  callsites: [cs({ callee: 'requests.Session' })],
});
assert(
  verifyAbsent.length === 0,
  `expected 0 findings on absence when forbidden_value_shapes is set, got ${verifyAbsent.length}`,
);

// ---------- B. Absence mode ----------
console.log('\n[B] Absence mode — flask SESSION_COOKIE_SECURE');

const cookieAbsent = detectInsecureDefaults({
  specs: [flaskSpec],
  callsites: [cs({ callee: 'app.config.update', kwargNames: ['DEBUG'] })],
});
assert(cookieAbsent.length === 1, `expected 1 finding on absence, got ${cookieAbsent.length}`);
assert(cookieAbsent[0]?.trigger.reason === 'absent', 'reason is absent');

const cookiePresent = detectInsecureDefaults({
  specs: [flaskSpec],
  callsites: [
    cs({
      callee: 'app.config.update',
      kwargNames: ['SESSION_COOKIE_SECURE'],
      kwargValues: { SESSION_COOKIE_SECURE: 'True' },
    }),
  ],
});
assert(
  cookiePresent.length === 0,
  `expected 0 findings when kwarg present (any value), got ${cookiePresent.length}`,
);

// ---------- C. Pattern matching ----------
console.log('\n[C] Pattern matching — wildcard receiver + bare segment');

const wildcardMatch = detectInsecureDefaults({
  specs: [flaskSpec],
  callsites: [
    cs({ callee: 'other_app.config.update', kwargNames: [], filePath: '/fixtures/a.py', line: 1 }),
    cs({ callee: 'flask_app.config.update', kwargNames: [], filePath: '/fixtures/b.py', line: 1 }),
  ],
});
assert(wildcardMatch.length === 2, `expected wildcard receiver to match both, got ${wildcardMatch.length}`);

const noPatternMatch = detectInsecureDefaults({
  specs: [requestsSpec],
  callsites: [cs({ callee: 'httpx.Client', kwargNames: ['verify'], kwargValues: { verify: 'False' } })],
});
assert(noPatternMatch.length === 0, 'unrelated callee does not match pattern');

// ---------- D. Dedup across specs ----------
console.log('\n[D] Dedup — same (file, line, col, pattern) collapses');

const dupSpec: FrameworkSpec = { ...requestsSpec, framework: 'requests-alias' };
const dedup = detectInsecureDefaults({
  specs: [requestsSpec, dupSpec],
  callsites: [
    cs({
      callee: 'requests.Session',
      kwargNames: ['verify'],
      kwargValues: { verify: 'False' },
      filePath: '/fixtures/dedup.py',
      line: 7,
      column: 3,
    }),
  ],
});
assert(dedup.length === 1, `expected 1 finding after dedup, got ${dedup.length}`);

// ---------- E. Empty / undefined entries ----------
console.log('\n[E] Empty / undefined — silent');

const emptyEntries: FrameworkSpec = { ...requestsSpec, insecure_defaults: [] };
const undefEntries: FrameworkSpec = { ...requestsSpec, insecure_defaults: undefined };

const e1 = detectInsecureDefaults({
  specs: [emptyEntries],
  callsites: [cs({ callee: 'requests.Session' })],
});
assert(e1.length === 0, 'empty insecure_defaults emits nothing');

const e2 = detectInsecureDefaults({
  specs: [undefEntries],
  callsites: [cs({ callee: 'requests.Session' })],
});
assert(e2.length === 0, 'undefined insecure_defaults emits nothing');

console.log(`\n=== ${passes} passed, ${failures} failed ===`);
if (failures > 0) process.exit(1);
