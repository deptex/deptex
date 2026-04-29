/**
 * Engine-level invariant tests for the cross-file taint engine.
 *
 * These tests pin down behaviors that the existing per-language fixture
 * tests only validate transitively. If any of these regress, every
 * language substrate breaks silently — so they live in their own file
 * that runs fast (no callgraph build, no real workspace) on every test
 * matrix run.
 *
 * Sections:
 *   A. receiverRoot() pattern parsing across language sigils
 *   B. Receiver-as-args[0] convention (sink argument_indices semantics)
 *   C. Source-step receiver-fallback (extends taint when source pattern misses)
 *   D. Worklist termination + runaway safety net
 *   E. Per-grammar IR workarounds — PHP $-stripping, C# var-decl flatten,
 *      Rust call_expression-with-field_expression reroute
 *
 * Run: npx tsx test/taint-engine-invariants.test.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  buildCallersByCallee,
  matchesCallPattern,
  receiverRoot,
  runWorklistAndAggregate,
  type FunctionState,
} from '../src/taint-engine/propagate-core';
import type { FrameworkSpec } from '../src/taint-engine/spec';
import type { IrFunction, SourceLocation } from '../src/taint-engine/ir';
import type { FunctionId, FunctionNode } from '../src/taint-engine/types';
import { propagatePhp } from '../src/taint-engine/php/propagate';
import { propagateCSharp } from '../src/taint-engine/csharp/propagate';
import { propagateRust } from '../src/taint-engine/rust/propagate';

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

// ---------------------------------------------------------------------------
// Helpers — hand-rolled IR scaffolding
// ---------------------------------------------------------------------------

const FILE = 'src/test.ts';

function loc(line: number, column = 1): SourceLocation {
  return { filePath: FILE, line, column };
}

function makeFuncNode(name: string, line: number): FunctionNode {
  return {
    id: `${FILE}:${line}:1:${name}`,
    name,
    kind: 'function_declaration',
    filePath: FILE,
    startLine: line,
    startColumn: 1,
    endLine: line + 5,
    endColumn: 1,
    isFullyTyped: true,
    containingClass: null,
    isModuleInitializer: false,
  };
}

function makeState(node: FunctionNode, ir: IrFunction): FunctionState {
  return {
    funcNode: node,
    ir,
    paramTaints: new Map(),
    returnTaint: null,
    sinkHits: [],
    analyzed: false,
  };
}

const TEST_SPEC: FrameworkSpec = {
  framework: 'invariants-test',
  version: '*',
  sources: [
    { pattern: 'req.body.*', taint_kind: 'http_input', description: 'request body' },
    { pattern: 'req.query.*', taint_kind: 'http_input', description: 'request query' },
  ],
  sinks: [
    {
      pattern: 'db.query(*)',
      vuln_class: 'sql_injection',
      argument_indices: [0],
      description: 'sql query (argument_indices=[0])',
    },
    {
      pattern: '*.exec(*)',
      vuln_class: 'command_injection',
      argument_indices: [1],
      description: 'method-call exec; argument_indices=[1] picks first user arg, not receiver',
    },
  ],
  sanitizers: [],
};

// ---------------------------------------------------------------------------
// SECTION A — receiverRoot() pattern parsing
// ---------------------------------------------------------------------------

function sectionA_receiverRoot() {
  console.log('\n[A] receiverRoot() pattern parsing across language sigils');

  // JS / TS / Python / Java / Go / C# / Ruby — `.` field access
  assertEqual(receiverRoot('q.name'), 'q', 'JS/TS/Python/etc: q.name → q');
  assertEqual(receiverRoot('user.profile.email'), 'user', 'deeply chained: user.profile.email → user');
  assertEqual(receiverRoot('req.body.x'), 'req', 'request body access: req.body.x → req');

  // JS array / index access
  assertEqual(receiverRoot('q[0]'), 'q', 'JS index: q[0] → q');
  assertEqual(receiverRoot('data[i]'), 'data', 'JS index var: data[i] → data');

  // Call form (when source step text is a callExpr)
  assertEqual(receiverRoot('q(x)'), 'q', 'call form: q(x) → q');

  // PHP `->` arrow
  assertEqual(receiverRoot('request->input'), 'request', 'PHP arrow: request->input → request');
  assertEqual(receiverRoot('user->name'), 'user', 'PHP arrow: user->name → user');

  // Ruby / C++ / Rust `::` scope (only when used as access, not type qualifier)
  assertEqual(receiverRoot('Foo::field'), 'Foo', 'scope op: Foo::field → Foo');

  // Plain identifier — no field/index/call → null. This is correct: a
  // source-step text of just `q` with no match should clear the target,
  // not inherit the (possibly tainted) `q` itself.
  assertEqual(receiverRoot('q'), null, 'plain identifier → null (no inheritance)');
  assertEqual(receiverRoot('userInput'), null, 'plain identifier → null');

  // Numeric / odd starts shouldn't match
  assertEqual(receiverRoot('123.foo'), null, 'numeric prefix → null');
  assertEqual(receiverRoot(''), null, 'empty string → null');
  assertEqual(receiverRoot('.foo'), null, 'leading dot → null');

  // Underscore identifiers
  assertEqual(receiverRoot('_q.name'), '_q', 'underscore identifier: _q.name → _q');
  assertEqual(receiverRoot('q1.field'), 'q1', 'identifier with digit: q1.field → q1');

  // Note: the `$var` PHP form is handled by stripLeadingDollar() in php/ir.ts
  // BEFORE reaching propagate-core. The receiver root should never see a
  // leading `$`. If it ever does, it should not match (no inheritance) —
  // which is the safe behavior.
  assertEqual(receiverRoot('$q->name'), null, 'PHP raw text with $ → null (must be stripped upstream)');
}

// ---------------------------------------------------------------------------
// SECTION B — Receiver-as-args[0] convention
//
// The IR convention: for method-call call steps, args[0] is the RECEIVER
// (the object the method is called on), and args[1..] are the user-supplied
// arguments. So for a sink pattern `*.exec(*)` to match the first USER arg,
// it must use `argument_indices: [1]`. This protects every spec author —
// if propagate-core silently changes this convention, every method-call
// sink across 23 specs breaks.
// ---------------------------------------------------------------------------

function sectionB_receiverArgsConvention() {
  console.log('\n[B] receiver-as-args[0] convention for method-call sinks');

  // Test 1: argument_indices=[1] (the sink as defined in TEST_SPEC) flags
  // a flow when the FIRST USER ARG is tainted, even though receiver is not.
  {
    const handlerNode = makeFuncNode('handler', 10);
    const ir: IrFunction = {
      id: handlerNode.id,
      params: ['req'],
      steps: [
        // const cmd = req.body.cmd  → source matches, taints `cmd`
        { kind: 'source', target: 'cmd', sourceText: 'req.body.cmd', loc: loc(11) },
        // proc.exec(cmd) — args[0]=proc (receiver, untainted),
        //                 args[1]=cmd  (user arg, tainted)
        {
          kind: 'call',
          target: null,
          callee: { kind: 'external', calleeText: 'proc.exec' },
          args: ['proc', 'cmd'],
          argTexts: ['proc', 'cmd'],
          loc: loc(12),
        },
      ],
    };
    const stateById = new Map<FunctionId, FunctionState>([
      [handlerNode.id, makeState(handlerNode, ir)],
    ]);
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: buildCallersByCallee([]),
      specs: [TEST_SPEC],
    });
    assert(
      result.flows.length === 1,
      `argument_indices=[1] catches tainted user arg (got ${result.flows.length} flows)`,
    );
    assertEqual(
      result.flows[0]?.vuln_class,
      'command_injection',
      'flow vuln_class = command_injection',
    );
  }

  // Test 2: receiver tainted but user arg untainted → NO flow (because
  // argument_indices=[1], not [0]). This pins the convention: spec authors
  // who write `argument_indices: [0]` for `*.method(*)` patterns are
  // matching the RECEIVER, not the first user arg.
  {
    const handlerNode = makeFuncNode('handler', 20);
    const ir: IrFunction = {
      id: handlerNode.id,
      params: ['req'],
      steps: [
        // const proc = req.body.proc  → taints `proc` (the receiver)
        { kind: 'source', target: 'proc', sourceText: 'req.body.proc', loc: loc(21) },
        // proc.exec("ls") — args[0]=proc (tainted), args[1]="ls" (untainted)
        {
          kind: 'call',
          target: null,
          callee: { kind: 'external', calleeText: 'proc.exec' },
          args: ['proc', null], // null = literal
          argTexts: ['proc', '"ls"'],
          loc: loc(22),
        },
      ],
    };
    const stateById = new Map<FunctionId, FunctionState>([
      [handlerNode.id, makeState(handlerNode, ir)],
    ]);
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: buildCallersByCallee([]),
      specs: [TEST_SPEC],
    });
    assert(
      result.flows.length === 0,
      `argument_indices=[1] ignores tainted receiver at args[0] (got ${result.flows.length} flows)`,
    );
  }

  // Test 3: with argument_indices=[0] (the db.query sink), the SAME
  // function-call shape WOULD flag a tainted receiver. Pins the inverse —
  // free-function sinks like db.query() correctly use [0] because there's
  // no receiver to skip.
  {
    const handlerNode = makeFuncNode('handler', 30);
    const ir: IrFunction = {
      id: handlerNode.id,
      params: ['req'],
      steps: [
        { kind: 'source', target: 'sql', sourceText: 'req.body.sql', loc: loc(31) },
        // db.query(sql) — free function call, args[0]=sql (tainted)
        {
          kind: 'call',
          target: null,
          callee: { kind: 'external', calleeText: 'db.query' },
          args: ['sql'],
          argTexts: ['sql'],
          loc: loc(32),
        },
      ],
    };
    const stateById = new Map<FunctionId, FunctionState>([
      [handlerNode.id, makeState(handlerNode, ir)],
    ]);
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: buildCallersByCallee([]),
      specs: [TEST_SPEC],
    });
    assert(
      result.flows.length === 1,
      `argument_indices=[0] catches free-function sink (got ${result.flows.length} flows)`,
    );
    assertEqual(result.flows[0]?.vuln_class, 'sql_injection', 'flow vuln_class = sql_injection');
  }
}

// ---------------------------------------------------------------------------
// SECTION C — Source-step receiver-fallback
//
// When a source step's pattern doesn't match any framework spec, but the
// source-text is a field/index access on a known-tainted local
// (e.g. `q.name` where `q` was previously tainted), propagate-core
// extends the taint to the new target. This protects handlers that bind
// an extractor to a local then read fields off it — without it, idiomatic
// Rust `query.into_inner()` followed by `q.name` would clear taint.
// ---------------------------------------------------------------------------

function sectionC_sourceReceiverFallback() {
  console.log('\n[C] source-step receiver-fallback');

  // Test 1: q is tainted, q.name reads a field → target inherits taint.
  {
    const handlerNode = makeFuncNode('handler', 40);
    const ir: IrFunction = {
      id: handlerNode.id,
      params: ['req'],
      steps: [
        // q = req.body  → q tainted via wildcard suffix match
        { kind: 'source', target: 'q', sourceText: 'req.body', loc: loc(41) },
        // name = q.name  → no spec matches `q.name`, BUT `q` is in local
        //                  → fallback extends q's taint to `name`
        { kind: 'source', target: 'name', sourceText: 'q.name', loc: loc(42) },
        // db.query(name)  → flow should fire because `name` carries q's taint
        {
          kind: 'call',
          target: null,
          callee: { kind: 'external', calleeText: 'db.query' },
          args: ['name'],
          argTexts: ['name'],
          loc: loc(43),
        },
      ],
    };
    const stateById = new Map<FunctionId, FunctionState>([
      [handlerNode.id, makeState(handlerNode, ir)],
    ]);
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: buildCallersByCallee([]),
      specs: [TEST_SPEC],
    });
    assert(
      result.flows.length === 1,
      `receiver-fallback extends taint via field access (got ${result.flows.length})`,
    );
  }

  // Test 2: receiver NOT tainted, source pattern doesn't match → target cleared.
  // The fallback must not invent taint from nothing.
  {
    const handlerNode = makeFuncNode('handler', 50);
    const ir: IrFunction = {
      id: handlerNode.id,
      params: ['req'],
      steps: [
        // No prior source — `q` is just a plain (untainted) local.
        // name = q.name  → q not in local → name cleared
        { kind: 'source', target: 'name', sourceText: 'q.name', loc: loc(51) },
        {
          kind: 'call',
          target: null,
          callee: { kind: 'external', calleeText: 'db.query' },
          args: ['name'],
          argTexts: ['name'],
          loc: loc(52),
        },
      ],
    };
    const stateById = new Map<FunctionId, FunctionState>([
      [handlerNode.id, makeState(handlerNode, ir)],
    ]);
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: buildCallersByCallee([]),
      specs: [TEST_SPEC],
    });
    assert(
      result.flows.length === 0,
      `receiver-fallback doesn't invent taint when receiver is clean (got ${result.flows.length})`,
    );
  }

  // Test 3: source-text is a plain identifier, not a field/index → cleared.
  // (receiverRoot returns null for plain identifiers, which means the
  // fallback does not fire — this is correct: `name = q` should be modeled
  // as 'assign', not 'source'. If it ever shows up as 'source' in IR, that's
  // a lowerer bug; the engine treats it conservatively as untainted.)
  {
    const handlerNode = makeFuncNode('handler', 60);
    const ir: IrFunction = {
      id: handlerNode.id,
      params: ['req'],
      steps: [
        { kind: 'source', target: 'q', sourceText: 'req.body', loc: loc(61) },
        // name = q  → plain identifier; receiverRoot returns null → name cleared.
        { kind: 'source', target: 'name', sourceText: 'q', loc: loc(62) },
        {
          kind: 'call',
          target: null,
          callee: { kind: 'external', calleeText: 'db.query' },
          args: ['name'],
          argTexts: ['name'],
          loc: loc(63),
        },
      ],
    };
    const stateById = new Map<FunctionId, FunctionState>([
      [handlerNode.id, makeState(handlerNode, ir)],
    ]);
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: buildCallersByCallee([]),
      specs: [TEST_SPEC],
    });
    assert(
      result.flows.length === 0,
      `plain-identifier source-step does not trigger fallback (got ${result.flows.length})`,
    );
  }
}

// ---------------------------------------------------------------------------
// SECTION D — Worklist termination + runaway safety net
// ---------------------------------------------------------------------------

function sectionD_worklistTermination() {
  console.log('\n[D] worklist termination + runaway safety net');

  // Test 1: Cycle of 4 functions where taint flows around the loop. State
  // is monotonically growing but bounded: each function's paramTaints grows
  // once, returnTaint grows once, then convergence. Should NOT hit
  // maxIterations.
  {
    const a = makeFuncNode('a', 100);
    const b = makeFuncNode('b', 110);
    const c = makeFuncNode('c', 120);
    const d = makeFuncNode('d', 130);

    // a(req): t = req.body.x; return b(t)
    const irA: IrFunction = {
      id: a.id,
      params: ['req'],
      steps: [
        { kind: 'source', target: 't', sourceText: 'req.body.x', loc: loc(101) },
        {
          kind: 'call',
          target: 'r',
          callee: { kind: 'internal', functionId: b.id, calleeText: 'b' },
          args: ['t'],
          argTexts: ['t'],
          loc: loc(102),
        },
        { kind: 'return', from: 'r', loc: loc(103) },
      ],
    };
    // b(x): return c(x)
    const irB: IrFunction = {
      id: b.id,
      params: ['x'],
      steps: [
        {
          kind: 'call',
          target: 'r',
          callee: { kind: 'internal', functionId: c.id, calleeText: 'c' },
          args: ['x'],
          argTexts: ['x'],
          loc: loc(111),
        },
        { kind: 'return', from: 'r', loc: loc(112) },
      ],
    };
    // c(x): return d(x)
    const irC: IrFunction = {
      id: c.id,
      params: ['x'],
      steps: [
        {
          kind: 'call',
          target: 'r',
          callee: { kind: 'internal', functionId: d.id, calleeText: 'd' },
          args: ['x'],
          argTexts: ['x'],
          loc: loc(121),
        },
        { kind: 'return', from: 'r', loc: loc(122) },
      ],
    };
    // d(x): db.query(x); return x  (sink hit + recursion-back to b via shared callgraph would loop, but here d returns to c only)
    const irD: IrFunction = {
      id: d.id,
      params: ['x'],
      steps: [
        {
          kind: 'call',
          target: null,
          callee: { kind: 'external', calleeText: 'db.query' },
          args: ['x'],
          argTexts: ['x'],
          loc: loc(131),
        },
        { kind: 'return', from: 'x', loc: loc(132) },
      ],
    };

    const stateById = new Map<FunctionId, FunctionState>([
      [a.id, makeState(a, irA)],
      [b.id, makeState(b, irB)],
      [c.id, makeState(c, irC)],
      [d.id, makeState(d, irD)],
    ]);
    const callers = buildCallersByCallee([
      { callerId: a.id, calleeId: b.id },
      { callerId: b.id, calleeId: c.id },
      { callerId: c.id, calleeId: d.id },
    ]);

    let warnCount = 0;
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: callers,
      specs: [TEST_SPEC],
      onWarn: () => {
        warnCount++;
      },
    });
    assert(!result.stoppedEarly, '4-function cross-file chain converges (no early stop)');
    assertEqual(warnCount, 0, '4-function cross-file chain does not warn');
    assert(result.flows.length === 1, `chain emits exactly 1 flow (got ${result.flows.length})`);
    assert(result.iterations < 1000, `chain converges in <1000 iterations (got ${result.iterations})`);
  }

  // Test 2: Force runaway by setting maxIterations=1. With 3 functions in
  // the worklist and any work to do, the loop should hit the cap, set
  // stoppedEarly=true, and emit two onWarn calls (one for the cap, one for
  // "engine output may be incomplete due to early stop").
  {
    const a = makeFuncNode('a', 200);
    const b = makeFuncNode('b', 210);
    const c = makeFuncNode('c', 220);
    const ir = (id: FunctionId): IrFunction => ({ id, params: ['x'], steps: [] });
    const stateById = new Map<FunctionId, FunctionState>([
      [a.id, makeState(a, ir(a.id))],
      [b.id, makeState(b, ir(b.id))],
      [c.id, makeState(c, ir(c.id))],
    ]);
    const warnings: string[] = [];
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: buildCallersByCallee([]),
      specs: [TEST_SPEC],
      maxIterations: 1,
      onWarn: (m) => warnings.push(m),
    });
    assert(result.stoppedEarly, 'maxIterations=1 trips stoppedEarly');
    assert(
      warnings.some((w) => w.includes('maxIterations=1')),
      'first warning identifies the cap value',
    );
    assert(
      warnings.some((w) => w.includes('engine output may be incomplete')),
      'second warning surfaces output-may-be-incomplete',
    );
    assertEqual(warnings.length, 2, 'exactly 2 warnings emitted on runaway');
    assertEqual(result.flows.length, 0, 'runaway emits no flows from empty IR');
  }

  // Test 3: Empty stateById (no functions) — terminates immediately.
  {
    const stateById = new Map<FunctionId, FunctionState>();
    const result = runWorklistAndAggregate({
      stateById,
      callersByCallee: buildCallersByCallee([]),
      specs: [TEST_SPEC],
    });
    assertEqual(result.iterations, 0, 'empty worklist does 0 iterations');
    assertEqual(result.flows.length, 0, 'empty worklist emits 0 flows');
    assert(!result.stoppedEarly, 'empty worklist not flagged stoppedEarly');
  }
}

// ---------------------------------------------------------------------------
// SECTION E — Per-grammar IR workarounds
//
// These exercise the per-language IR lowerers' known compatibility quirks
// against real source code through real tree-sitter grammars. If a grammar
// version bumps and the workaround stops applying, we want to fail in a
// dedicated test rather than discover it via fixture flakiness.
// ---------------------------------------------------------------------------

function makeWorkspace(name: string, files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `inv-${name}-`));
  for (const [rel, body] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body, 'utf8');
  }
  return root;
}

const PHP_SPEC: FrameworkSpec = {
  framework: 'php-test',
  version: '*',
  language: 'php',
  sources: [
    { pattern: 'request->input(*)', taint_kind: 'http_input', description: 'PHP request->input() — must match after $-strip' },
  ],
  sinks: [
    { pattern: 'DB::raw(*)', vuln_class: 'sql_injection', argument_indices: [0], description: 'PHP DB::raw' },
  ],
  sanitizers: [],
};

async function sectionE_phpDollarStrip() {
  console.log('\n[E.1] PHP stripLeadingDollar — $request->input(...) matches request->input(*)');
  const root = makeWorkspace('php-dollar', {
    'index.php': `<?php
function handler($request) {
  $val = $request->input('q');
  DB::raw($val);
}
`,
  });
  try {
    const result = await propagatePhp({ rootDir: root, specs: [PHP_SPEC] });
    assert(
      result.flows.length === 1,
      `PHP $-stripping enables source pattern match (got ${result.flows.length})`,
    );
    assertEqual(
      result.flows[0]?.vuln_class,
      'sql_injection',
      'PHP flow vuln_class = sql_injection',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

const CSHARP_SPEC: FrameworkSpec = {
  framework: 'csharp-test',
  version: '*',
  language: 'csharp',
  sources: [
    { pattern: 'Request.Query.*', taint_kind: 'http_input', description: 'ASP.NET request query' },
  ],
  sinks: [
    {
      pattern: 'SqlCommand(*)',
      vuln_class: 'sql_injection',
      argument_indices: [0],
      description: 'SqlCommand constructor',
    },
  ],
  sanitizers: [],
};

async function sectionE_csharpVarDeclFallback() {
  console.log('\n[E.2] C# var-decl second-named-child fallback (no equals_value_clause wrapper)');
  // tree-sitter-c-sharp flattens `var x = expr` so there is no
  // equals_value_clause wrapper around the initializer. The IR lowerer's
  // fallback walks namedChildren and picks the first non-name child.
  // This fixture exercises a `using (var x = ...)` block which is the form
  // that broke in the breadth-pass before the fallback was added.
  const root = makeWorkspace('csharp-vardecl', {
    'Test.cs': `
using System.Data.SqlClient;

public class Handler {
    public void DoWork(HttpRequest Request) {
        var q = Request.Query["q"];
        using (var cmd = new SqlCommand(q)) {
            cmd.ExecuteNonQuery();
        }
    }
}
`,
  });
  try {
    const result = await propagateCSharp({ rootDir: root, specs: [CSHARP_SPEC] });
    assert(
      result.flows.length >= 1,
      `C# using-block var-decl propagates taint (got ${result.flows.length})`,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

const RUST_SPEC: FrameworkSpec = {
  framework: 'rust-test',
  version: '*',
  language: 'rust',
  sources: [
    {
      pattern: '*.into_inner(*)',
      taint_kind: 'http_input',
      description: 'extractor unwrap',
    },
  ],
  sinks: [
    {
      pattern: '*.arg(*)',
      vuln_class: 'command_injection',
      argument_indices: [1],
      description: 'std::process::Command.arg(arg) — arg is at user position [1]',
    },
  ],
  sanitizers: [],
};

async function sectionE_rustFieldExpressionReroute() {
  console.log('\n[E.3] Rust field_expression-as-function reroute (call_expression → method-call IR)');
  // tree-sitter-rust ≥ 0.20 represents `obj.method(args)` as a
  // call_expression whose function child is a field_expression — there is
  // no method_call_expression node. The IR lowerer must detect this shape
  // and re-route to method-call lowering, otherwise `.arg(x)` chains never
  // emit sink-eligible call steps. This fixture pins that fix.
  const root = makeWorkspace('rust-field', {
    'Cargo.toml': `[package]
name = "rust-test"
version = "0.1.0"
edition = "2021"
`,
    'src/main.rs': `
use std::process::Command;

fn handler(query: actix_web::web::Query<()>) {
    let q = query.into_inner();
    Command::new("sh").arg(q.cmd);
}
`,
  });
  try {
    const result = await propagateRust({ rootDir: root, specs: [RUST_SPEC] });
    assert(
      result.flows.length >= 1,
      `Rust call_expression-with-field_expression lowers as method call (got ${result.flows.length})`,
    );
    assertEqual(
      result.flows[0]?.vuln_class,
      'command_injection',
      'Rust flow vuln_class = command_injection',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// SECTION F — matchesCallPattern wildcard-receiver semantics
//
// Languages emit calleeText with their native method separator: JS / Ruby /
// Python use `.`, PHP uses `->`, Rust path-call uses `::`. The matcher must
// honor whichever the YAML author wrote — `*.method`, `*->method`, `*::method`
// — so spec patterns like symfony's `*->executeQuery(*)` actually fire.
// Regression: until 2026-04-29 only `*.` was honored, leaving every PHP
// method-call sink (and every Rust path-call sink in the same shape) silently
// unmatched.
// ---------------------------------------------------------------------------

function sectionF_callPatternWildcards() {
  console.log('\n[F] matchesCallPattern wildcard-receiver semantics');

  // *.method — JS / Python / Ruby / etc.
  assert(matchesCallPattern('*.exec(*)', 'child.exec'), '*.exec matches child.exec');
  assert(matchesCallPattern('*.query(*)', 'pool.query'), '*.query matches pool.query');
  assert(!matchesCallPattern('*.exec(*)', 'execve'), '*.exec does not match execve (no separator)');

  // *->method — PHP. Until the 2026-04-29 fix this was silently treated as a
  // literal pattern and never matched any PHP call.
  assert(
    matchesCallPattern('*->executeQuery(*)', 'conn->executeQuery'),
    '*->executeQuery matches conn->executeQuery',
  );
  assert(
    matchesCallPattern('*->setContent(*)', 'resp->setContent'),
    '*->setContent matches resp->setContent',
  );
  assert(
    !matchesCallPattern('*->executeQuery(*)', 'conn.executeQuery'),
    '*->executeQuery does NOT match conn.executeQuery (wrong separator)',
  );

  // *::method — Rust associated-fn / PHP scoped-call form.
  assert(
    matchesCallPattern('*::query(*)', 'sqlx::query'),
    '*::query matches sqlx::query',
  );
  assert(
    !matchesCallPattern('*::query(*)', 'sqlx.query'),
    '*::query does NOT match sqlx.query (wrong separator)',
  );

  // Exact-match (non-wildcard) form still works.
  assert(matchesCallPattern('new Response(*)', 'new Response'), 'exact: new Response');
  assert(matchesCallPattern('DB::select(*)', 'DB::select'), 'exact: DB::select');
  assert(!matchesCallPattern('DB::select(*)', 'DB::selectOne'), 'exact does not partial-match');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('=== taint-engine invariant tests ===');
  sectionA_receiverRoot();
  sectionB_receiverArgsConvention();
  sectionC_sourceReceiverFallback();
  sectionD_worklistTermination();
  await sectionE_phpDollarStrip();
  await sectionE_csharpVarDeclFallback();
  await sectionE_rustFieldExpressionReroute();
  sectionF_callPatternWildcards();
  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('test run threw:', err);
  process.exit(2);
});
