/**
 * Tests for Phase 3.2 — regex-literal detector.
 *
 * Three layers of coverage:
 *   A. Substring detection fires on known-unsafe regex literal embedded
 *      in a JS RegExp constructor / `/.../` literal / Python re.compile.
 *   B. Detector stays quiet on files where the unsafe pattern doesn't
 *      appear (the precision side — over-firing here makes the detector
 *      worthless once it's wired into the pipeline).
 *   C. Multi-file dedup — the same (file, regex) pair emits ONE finding
 *      even when the regex appears multiple times in the same file.
 *
 * Run: npx tsx test/taint-engine-regex-literal.test.ts
 */

import { detectUnsafeRegexLiterals } from '../src/taint-engine/regex-literal-detector';
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

// Mock spec exercising both AI-shape and bundled-shape pattern entries.
const debugSpec: FrameworkSpec = {
  framework: 'debug',
  version: '*',
  language: 'js',
  sources: [],
  sinks: [{ pattern: 'debug(*)', vuln_class: 'redos', argument_indices: [], description: 'debug call' }],
  sanitizers: [],
  unsafe_regex_patterns: [
    { regex: '%[oOdisfc%]', description: 'debug coloring regex ReDoS (CVE-2017-16137)' },
  ],
};

const jinjaSpec: FrameworkSpec = {
  framework: 'jinja2',
  version: '*',
  language: 'python',
  sources: [],
  sinks: [{ pattern: 'urlize(*)', vuln_class: 'redos', argument_indices: [0], description: 'jinja urlize' }],
  sanitizers: [],
  unsafe_regex_patterns: [
    { regex: '(\\.\\.[\\\\\\/]|[\\\\\\/]\\.\\.)', description: 'jinja2 urlize backtracking (CVE-2020-28493)' },
  ],
};

// ---------- A. Positive: detector fires when literal appears in source ----------
console.log('\n[A] Positive — substring detection');

const debugVuln = {
  filePath: '/fixtures/debug-vuln/index.js',
  content: `
    const debug = require('debug');
    const log = debug('myapp');
    const COLORING = /%[oOdisfc%]/g;  // matches the CVE-2017-16137 unsafe regex literal
    log('format %o', userInput);
  `,
};

const debugSafe = {
  filePath: '/fixtures/debug-safe/index.js',
  content: `
    const debug = require('debug');
    const log = debug('myapp');
    log('safe', userInput);
  `,
};

const findingsA = detectUnsafeRegexLiterals({ specs: [debugSpec], files: [debugVuln, debugSafe] });
assert(findingsA.length === 1, `expected exactly 1 finding, got ${findingsA.length}`);
assert(findingsA[0]?.filePath === debugVuln.filePath, 'finding is on the vuln file');
assert(findingsA[0]?.regex === '%[oOdisfc%]', 'finding records the matched regex literal');
assert(findingsA[0]?.framework === 'debug', 'finding attributes to debug framework');
assert(typeof findingsA[0]?.line === 'number' && findingsA[0].line >= 1, 'finding has a 1-based line number');

// ---------- B. Negative: empty / mismatched specs ----------
console.log('\n[B] Negative — quiet when regex not present');

const safeOnly = detectUnsafeRegexLiterals({ specs: [debugSpec], files: [debugSafe] });
assert(safeOnly.length === 0, `expected 0 findings on safe file alone, got ${safeOnly.length}`);

const emptyPatterns: FrameworkSpec = { ...debugSpec, unsafe_regex_patterns: [] };
const emptyResult = detectUnsafeRegexLiterals({ specs: [emptyPatterns], files: [debugVuln] });
assert(emptyResult.length === 0, `expected 0 findings when unsafe_regex_patterns is empty, got ${emptyResult.length}`);

const noPatterns: FrameworkSpec = { ...debugSpec, unsafe_regex_patterns: undefined };
const undefResult = detectUnsafeRegexLiterals({ specs: [noPatterns], files: [debugVuln] });
assert(undefResult.length === 0, `expected 0 findings when unsafe_regex_patterns is undefined, got ${undefResult.length}`);

// ---------- C. Dedup: same (file, regex) emits ONE finding ----------
console.log('\n[C] Dedup — multiple matches in same file collapse');

const doubled = {
  filePath: '/fixtures/debug-doubled/index.js',
  content: `
    // first occurrence
    const COLORING_A = /%[oOdisfc%]/g;
    // second occurrence (same literal):
    const COLORING_B = /%[oOdisfc%]/i;
  `,
};
const dedupResult = detectUnsafeRegexLiterals({ specs: [debugSpec], files: [doubled] });
assert(dedupResult.length === 1, `expected 1 finding after dedup, got ${dedupResult.length}`);
assert(dedupResult[0]?.line === 3, `expected first-occurrence line=3, got line=${dedupResult[0]?.line}`);

// ---------- D. Multi-spec dispatch ----------
console.log('\n[D] Multi-spec dispatch — each spec contributes its patterns');

const pythonVuln = {
  filePath: '/fixtures/jinja-vuln/app.py',
  content: `
    import re
    PATH_RE = re.compile(r'(\\.\\.[\\\\\\/]|[\\\\\\/]\\.\\.)')
  `,
};
const multiResult = detectUnsafeRegexLiterals({
  specs: [debugSpec, jinjaSpec],
  files: [debugVuln, pythonVuln, debugSafe],
});
assert(multiResult.length === 2, `expected 2 findings (one per spec/file), got ${multiResult.length}`);
const frameworks = multiResult.map((f) => f.framework).sort();
assert(frameworks.includes('debug') && frameworks.includes('jinja2'), 'both frameworks contribute a finding');

console.log(`\n=== ${passes} passed, ${failures} failed ===`);
if (failures > 0) process.exit(1);
