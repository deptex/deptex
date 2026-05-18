/**
 * Tests for the Phase 1.2 diagnostic surface — DropReason / DropRecord
 * emission, serializeTrace shape, and the NDJSON writer round-trip.
 *
 * Run: npx tsx test/taint-engine-diag.test.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  KNOWN_DROP_REASONS,
  serializeTrace,
  type DropRecord,
  type TaintTrace,
} from '../src/taint-engine/flow';
import {
  buildCallersByCallee,
  runWorklistAndAggregate,
  type FunctionState,
} from '../src/taint-engine/propagate-core';
import type { IrFunction, SourceLocation } from '../src/taint-engine/ir';
import type { FrameworkSpec } from '../src/taint-engine/spec';
import type { FunctionId, FunctionNode } from '../src/taint-engine/types';
import {
  createNdjsonDiagWriter,
  readNdjsonDiagFile,
} from '../src/taint-engine/diag-writer';

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

function loc(filePath: string, line: number, column = 0): SourceLocation {
  return { filePath, line, column };
}

// ============================================================================
// A. serializeTrace shape
// ============================================================================

function testSerializeTrace(): void {
  console.log('\n[A] serializeTrace shape preservation');

  const trace: TaintTrace = {
    taint_kind: 'http_input',
    source: {
      pattern: 'req.query.*',
      description: 'Express query param',
      taint_kind: 'http_input',
    },
    path: [
      { filePath: 'app.js', line: 1, column: 0, label: 'req.query.x', kind: 'source' },
      { filePath: 'app.js', line: 2, column: 0, label: 'tmp = req.query.x', kind: 'assign' },
    ],
  };

  const serialised = serializeTrace(trace);
  assertEqual(serialised.taint_kind, 'http_input', 'taint_kind preserved');
  assertEqual(serialised.source_pattern, 'req.query.*', 'source_pattern lifted from source.pattern');
  assertEqual(serialised.source_description, 'Express query param', 'source_description lifted');
  assertEqual(serialised.path.length, 2, 'path nodes preserved');
  assertEqual(serialised.path[0].label, 'req.query.x', 'first node label');

  // No FrameworkSource leaks into the dump (so we don't bloat NDJSON with all
  // 50+ source entries when only one fired).
  assert(!('source' in serialised), 'no FrameworkSource bleed into serialised form');
}

// ============================================================================
// B. KNOWN_DROP_REASONS exhaustiveness — every emitDrop literal in
// propagate-core.ts must be a member of KNOWN_DROP_REASONS.
// ============================================================================

function testDropReasonExhaustiveness(): void {
  console.log('\n[B] DropReason vocabulary stays stable');

  const propCoreSrc = fs.readFileSync(
    path.resolve(__dirname, '..', 'src/taint-engine/propagate-core.ts'),
    'utf8',
  );
  // Match emitDrop(diagSink, state, step, '<reason-literal>', ...)
  // Match emitDrop(diagSink, state, step, "<reason-literal>", ...) too
  const re = /emitDrop\([^,]+,[^,]+,[^,]+,\s*['"]([\w-]+)['"]/g;
  const found = new Set<string>();
  for (const m of propCoreSrc.matchAll(re)) {
    found.add(m[1]);
  }
  assert(found.size > 0, 'found at least one emitDrop literal');

  const known = new Set<string>(KNOWN_DROP_REASONS);
  for (const reason of found) {
    assert(known.has(reason), `'${reason}' is documented in KNOWN_DROP_REASONS`);
  }
  for (const known_reason of KNOWN_DROP_REASONS) {
    assert(found.has(known_reason), `KNOWN_DROP_REASONS entry '${known_reason}' is actually emitted`);
  }
}

// ============================================================================
// C. Engine integration — running the worklist with a diagSink captures drops
// ============================================================================

function makeFunc(name: string): FunctionNode {
  return {
    id: name as FunctionId,
    name,
    filePath: 'fix.ts',
    range: { start: { line: 1, column: 0 }, end: { line: 10, column: 0 } },
    isAsync: false,
    isExported: false,
    isMethod: false,
    paramNames: [],
  };
}

function makeIR(name: string, paramNames: string[], steps: IrFunction['steps']): IrFunction {
  return { funcId: name as FunctionId, params: paramNames, steps };
}

function makeState(funcNode: FunctionNode, ir: IrFunction): FunctionState {
  return {
    funcNode,
    ir,
    paramTaints: new Map(),
    returnTaint: null,
    sinkHits: [],
    analyzed: false,
  };
}

function testDiagSinkEmitsOnDrop(): void {
  console.log('\n[C] diagSink captures drops during worklist run');

  const spec: FrameworkSpec = {
    framework: 'test',
    version: 'test',
    language: 'javascript',
    sources: [
      { pattern: 'req.query.*', description: 'test query', taint_kind: 'http_input' },
    ],
    sinks: [
      {
        pattern: 'sink(*)',
        description: 'test sink',
        argument_indices: [0],
        vuln_class: 'xss',
      },
    ],
    sanitizers: [],
  };

  // Function with:
  //  1. source step matching a spec — assigns trace to `t`
  //  2. assign step `u = unknown_local` — `unknown_local` is NOT tainted, so
  //     this should emit an `assign-from-untainted` drop record (because the
  //     existing engine semantics still delete `u` if previously tainted; we
  //     pretarget `u` by setting it via a synthetic source first).
  //  3. assign step `v = u` after `u` was deleted — should also drop.
  // Actually the engine only emits a drop record when the engine WOULD have
  // deleted a previously-tainted target. To keep this test small we set up
  // a path where `u` is taint-seeded by a successful source step, then
  // assigned from an untainted local, triggering the drop emission.
  const fn = makeFunc('handler');
  const ir = makeIR('handler', [], [
    {
      kind: 'source',
      target: 't',
      sourceText: 'req.query.x',
      loc: loc('fix.ts', 1),
    },
    // Now `t` is tainted. Assign `t = nothing` to force a drop.
    {
      kind: 'assign',
      target: 't',
      from: 'nothing_tainted',
      loc: loc('fix.ts', 2),
    },
  ]);
  const state = makeState(fn, ir);

  const drops: DropRecord[] = [];
  const result = runWorklistAndAggregate({
    stateById: new Map([[fn.id, state]]),
    callersByCallee: buildCallersByCallee([]),
    specs: [spec],
    diagSink: (r) => drops.push(r),
  });

  assert(result.iterations > 0, 'worklist ran');
  const assignDrops = drops.filter((d) => d.reason === 'assign-from-untainted');
  assert(assignDrops.length >= 1, 'assign-from-untainted drop emitted');
  if (assignDrops[0]) {
    assertEqual(assignDrops[0].step_kind, 'assign', 'drop carries step_kind=assign');
    assertEqual(assignDrops[0].step_text, 't = nothing_tainted', 'drop carries step_text');
    assertEqual(assignDrops[0].function_name, 'handler', 'drop carries function_name');
  }
}

function testDiagSinkUndefinedIsZeroOverhead(): void {
  console.log('\n[D] diagSink=undefined is a no-op');

  const spec: FrameworkSpec = {
    framework: 'test',
    version: 'test',
    language: 'javascript',
    sources: [],
    sinks: [],
    sanitizers: [],
  };

  const fn = makeFunc('h');
  const ir = makeIR('h', [], [
    { kind: 'assign', target: 'x', from: 'y', loc: loc('a.ts', 1) },
  ]);
  const state = makeState(fn, ir);

  // No diagSink in options — just ensure the run completes without throwing.
  const result = runWorklistAndAggregate({
    stateById: new Map([[fn.id, state]]),
    callersByCallee: buildCallersByCallee([]),
    specs: [spec],
  });
  assert(result.iterations > 0, 'engine runs cleanly with diagSink undefined');
}

// ============================================================================
// E. NDJSON writer round-trip
// ============================================================================

function testNdjsonWriterRoundTrip(): void {
  console.log('\n[E] NDJSON writer round-trip');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'diag-test-'));
  const file = path.join(dir, 'sub', 'records.ndjson');
  const w = createNdjsonDiagWriter(file);

  const rec1: DropRecord = {
    reason: 'assign-from-untainted',
    step_kind: 'assign',
    step_loc: { filePath: 'a.ts', line: 1, column: 0 },
    step_text: 'x = y',
    function_id: 'fn1',
    function_name: 'fn1',
    trace_at_drop: null,
  };
  const rec2: DropRecord = {
    reason: 'sink-loaded-no-tainted-arg',
    step_kind: 'call',
    step_loc: { filePath: 'a.ts', line: 5, column: 4 },
    step_text: 'res.send',
    function_id: 'fn1',
    function_name: 'fn1',
    trace_at_drop: null,
    sink_pattern: '*.send(*)',
  };
  w.sink(rec1);
  w.sink(rec2);
  w.close();

  // Re-read via readNdjsonDiagFile
  const read = readNdjsonDiagFile(file);
  assertEqual(read.length, 2, 'two records round-trip');
  assertEqual(read[0].reason, 'assign-from-untainted', 'first record reason');
  assertEqual(read[1].reason, 'sink-loaded-no-tainted-arg', 'second record reason');
  assertEqual(read[1].sink_pattern, '*.send(*)', 'sink_pattern preserved');

  // In-memory mirror keeps records after close (the file is closed; the
  // captured array survives so callers can still summarise without re-reading
  // the NDJSON file). This is intentional.
  assertEqual(w.records().length, 2, 'in-memory mirror retained after close');

  // Closing twice is safe
  w.close();

  // Cleanup
  fs.rmSync(dir, { recursive: true, force: true });
}

function testNdjsonReadMissingFile(): void {
  console.log('\n[F] readNdjsonDiagFile handles missing file');

  const missing = path.join(os.tmpdir(), `does-not-exist-${Date.now()}.ndjson`);
  const result = readNdjsonDiagFile(missing);
  assertEqual(result.length, 0, 'missing file yields empty array');
}

// ============================================================================
// Run all tests
// ============================================================================

try {
  testSerializeTrace();
  testDropReasonExhaustiveness();
  testDiagSinkEmitsOnDrop();
  testDiagSinkUndefinedIsZeroOverhead();
  testNdjsonWriterRoundTrip();
  testNdjsonReadMissingFile();
} catch (err) {
  console.error(`\nFATAL: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
}

console.log(`\n=== ${passes} passed, ${failures} failed ===`);
process.exit(failures > 0 ? 1 : 0);
