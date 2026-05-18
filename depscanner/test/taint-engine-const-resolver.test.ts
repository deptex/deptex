/**
 * Tests for Phase 2a — JS single-assignment const resolver.
 *
 * Three layers of coverage:
 *   A. Lowerer populates IrFunction.localOrigins from `const x = { ... }` and
 *      `const x = [ ... ]` declarations, excluding multi-assigned locals.
 *   B. extractCallSitesFromIr resolves bare-identifier argTexts through
 *      fn.localOrigins so the F4 detector sees hoisted option-bag props.
 *   C. End-to-end: detectSanitizerAbsence fires on a hoisted-const
 *      jsonwebtoken-style shape and stays quiet when algorithms is present.
 *
 * Run: npx tsx test/taint-engine-const-resolver.test.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as ts from 'typescript';
import { lowerFunction } from '../src/taint-engine/ir';
import type { IrFunction } from '../src/taint-engine/ir';
import {
  detectSanitizerAbsence,
  extractCallSitesFromIr,
} from '../src/taint-engine/non-taint-detector';
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

function assertEqual<T>(actual: T, expected: T, msg: string): void {
  if (actual === expected) {
    console.log(`  ok: ${msg}`);
    passes++;
  } else {
    console.error(`  FAIL: ${msg} (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`);
    failures++;
  }
}

function lowerSrc(src: string): IrFunction {
  // Write src to a tempfile + parse it to get a SourceFile + TypeChecker so
  // lowerFunction can resolve callee symbols. Module-level so the SourceFile
  // itself becomes the function we lower.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-'));
  const file = path.join(dir, 'fixture.ts');
  fs.writeFileSync(file, src, 'utf8');
  const program = ts.createProgram([file], {
    target: ts.ScriptTarget.ES2020,
    module: ts.ModuleKind.CommonJS,
    allowJs: true,
    skipLibCheck: true,
    noEmit: true,
  });
  const sourceFile = program.getSourceFile(file)!;
  const checker = program.getTypeChecker();
  return lowerFunction(
    'mod' as IrFunction['id'],
    sourceFile,
    {
      filePath: file,
      sourceFile,
      checker,
      declarationToNodeId: new Map(),
      pickFunctionDecl: () => undefined,
    },
  );
}

// ============================================================================
// A. Lowerer populates localOrigins
// ============================================================================

function testLowererCapturesObjectLiteral(): void {
  console.log('\n[A1] const x = { ... } captured into localOrigins');
  const ir = lowerSrc(`
const opts = { algorithms: ['HS256'], maxAge: '1h' };
jwt.verify(token, key, opts);
  `);
  assert(ir.localOrigins, 'localOrigins map populated');
  const entry = ir.localOrigins?.get('opts');
  assert(entry !== undefined, "localOrigins has 'opts'");
  if (entry) {
    assert(entry.includes('algorithms'), 'literal text contains algorithms');
    assert(entry.includes('HS256'), 'literal text preserves enum members');
  }
}

function testLowererCapturesArrayLiteral(): void {
  console.log('\n[A2] const x = [ ... ] captured');
  const ir = lowerSrc(`
const flags = ['safe', 'fast'];
someApi(flags);
  `);
  const entry = ir.localOrigins?.get('flags');
  assert(entry !== undefined, "localOrigins has 'flags'");
  if (entry) assert(entry.startsWith('['), 'array literal text preserved');
}

function testLowererSkipsMultiAssigned(): void {
  console.log('\n[A3] re-assigned local is NOT in localOrigins');
  const ir = lowerSrc(`
let opts = { algorithms: ['HS256'] };
opts = req.body;
opts = { algorithms: ['none'] };
jwt.verify(token, key, opts);
  `);
  // The re-assignment to req.body creates a source step; the assignment to
  // another object literal creates per-property recursion that also targets
  // opts. So writeCount >= 2 → filter drops it.
  const entry = ir.localOrigins?.get('opts');
  assert(entry === undefined, 'multi-assigned opts filtered out');
}

function testLowererSkipsNonLiteralInit(): void {
  console.log('\n[A4] const x = call(...) is NOT in localOrigins');
  const ir = lowerSrc(`
const opts = makeOptions();
jwt.verify(token, key, opts);
  `);
  const entry = ir.localOrigins?.get('opts');
  assert(entry === undefined, 'call-init opts not captured');
}

function testLowererEmptyMap(): void {
  console.log('\n[A5] function with no literal inits → localOrigins absent or empty');
  const ir = lowerSrc(`
jwt.verify(token, key);
  `);
  assert(!ir.localOrigins || ir.localOrigins.size === 0, 'no spurious entries');
}

// ============================================================================
// B. extractCallSitesFromIr resolves bare-identifier argTexts
// ============================================================================

function testExtractResolvesHoistedConst(): void {
  console.log('\n[B1] bare-identifier argText resolved through localOrigins');
  const ir: IrFunction = {
    id: 'handler' as IrFunction['id'],
    params: [],
    steps: [
      {
        kind: 'call',
        target: null,
        callee: { kind: 'external', calleeText: 'jwt.verify' },
        args: ['token', 'key', 'opts'],
        argTexts: ['token', 'key', 'opts'],
        loc: { filePath: 'h.js', line: 5, column: 4 },
      },
    ],
    localOrigins: new Map([['opts', "{ algorithms: ['HS256'], maxAge: '1h' }"]]),
  };
  const sites = extractCallSitesFromIr([ir], 'js');
  assert(sites.length === 1, 'one callsite');
  const cs = sites[0];
  assert(cs.kwargNames.includes('algorithms'), 'algorithms resolved via const');
  assert(cs.kwargNames.includes('maxAge'), 'maxAge also resolved');
}

function testExtractInlineLiteralStillWorks(): void {
  console.log('\n[B2] inline object literal still works without localOrigins');
  const ir: IrFunction = {
    id: 'handler' as IrFunction['id'],
    params: [],
    steps: [
      {
        kind: 'call',
        target: null,
        callee: { kind: 'external', calleeText: 'jwt.verify' },
        args: ['token', 'key', null],
        argTexts: ['token', 'key', "{ algorithms: ['HS256'] }"],
        loc: { filePath: 'h.js', line: 6, column: 4 },
      },
    ],
  };
  const sites = extractCallSitesFromIr([ir], 'js');
  assert(sites[0].kwargNames.includes('algorithms'), 'inline still parsed');
}

function testExtractDoesNotResolveUnknownIdentifier(): void {
  console.log('\n[B3] identifier not in localOrigins → no resolution');
  const ir: IrFunction = {
    id: 'handler' as IrFunction['id'],
    params: [],
    steps: [
      {
        kind: 'call',
        target: null,
        callee: { kind: 'external', calleeText: 'jwt.verify' },
        args: ['token', 'key', 'other'],
        argTexts: ['token', 'key', 'other'],
        loc: { filePath: 'h.js', line: 7, column: 4 },
      },
    ],
    localOrigins: new Map([['opts', "{ algorithms: ['HS256'] }"]]),
  };
  const sites = extractCallSitesFromIr([ir], 'js');
  assert(!sites[0].kwargNames.includes('algorithms'), 'no false coupling on unrelated identifier');
}

// ============================================================================
// C. End-to-end: F4 detector + hoisted-const shape
// ============================================================================

const JWT_VERIFY_SPEC: FrameworkSpec = {
  framework: 'jsonwebtoken',
  version: '*',
  language: 'javascript',
  sources: [],
  sinks: [
    {
      pattern: 'jwt.verify(*)',
      vuln_class: 'auth_bypass',
      argument_indices: [],
      description: 'jwt.verify hoisted const algorithms check',
      required_arguments: [{ name: 'algorithms', match_mode: 'required' }],
    },
  ],
  sanitizers: [],
};

function testEndToEndHoistedAbsentFires(): void {
  console.log('\n[C1] hoisted const WITHOUT algorithms → finding fires');
  const ir = lowerSrc(`
const opts = { maxAge: '1h' };
jwt.verify(token, key, opts);
  `);
  const sites = extractCallSitesFromIr([ir], 'js');
  const findings = detectSanitizerAbsence(JWT_VERIFY_SPEC, sites);
  assert(findings.length >= 1, 'at least one finding emitted');
  if (findings[0]) {
    assertEqual(findings[0].trigger.argument_name, 'algorithms', 'finding trigger name');
    assertEqual(findings[0].vuln_class, 'auth_bypass', 'finding vuln_class');
  }
}

function testEndToEndHoistedPresentSuppresses(): void {
  console.log('\n[C2] hoisted const WITH algorithms → no finding');
  const ir = lowerSrc(`
const opts = { algorithms: ['HS256'], maxAge: '1h' };
jwt.verify(token, key, opts);
  `);
  const sites = extractCallSitesFromIr([ir], 'js');
  const findings = detectSanitizerAbsence(JWT_VERIFY_SPEC, sites);
  assertEqual(findings.length, 0, 'finding suppressed by hoisted algorithms');
}

function testEndToEndInlinePresentSuppresses(): void {
  console.log('\n[C3] inline call WITH algorithms → no finding (regression)');
  const ir = lowerSrc(`
jwt.verify(token, key, { algorithms: ['HS256'] });
  `);
  const sites = extractCallSitesFromIr([ir], 'js');
  const findings = detectSanitizerAbsence(JWT_VERIFY_SPEC, sites);
  assertEqual(findings.length, 0, 'inline algorithms still suppresses');
}

function testEndToEndPlainCallFires(): void {
  console.log('\n[C4] plain jwt.verify(token, key) → finding fires (regression)');
  const ir = lowerSrc(`
jwt.verify(token, key);
  `);
  const sites = extractCallSitesFromIr([ir], 'js');
  const findings = detectSanitizerAbsence(JWT_VERIFY_SPEC, sites);
  assert(findings.length >= 1, 'plain call still flagged');
}

// ============================================================================
// Run all
// ============================================================================

try {
  testLowererCapturesObjectLiteral();
  testLowererCapturesArrayLiteral();
  testLowererSkipsMultiAssigned();
  testLowererSkipsNonLiteralInit();
  testLowererEmptyMap();
  testExtractResolvesHoistedConst();
  testExtractInlineLiteralStillWorks();
  testExtractDoesNotResolveUnknownIdentifier();
  testEndToEndHoistedAbsentFires();
  testEndToEndHoistedPresentSuppresses();
  testEndToEndInlinePresentSuppresses();
  testEndToEndPlainCallFires();
} catch (err) {
  console.error(`\nFATAL: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
}

console.log(`\n=== ${passes} passed, ${failures} failed ===`);
process.exit(failures > 0 ? 1 : 0);
