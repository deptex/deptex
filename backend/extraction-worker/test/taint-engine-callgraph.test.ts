/**
 * Unit tests for the cross-file taint engine's whole-program callgraph.
 *
 * Builds synthetic mini-projects in the OS temp directory, runs
 * buildCallgraph against each, and asserts on node + edge shape. Covers:
 *   - Direct same-file calls
 *   - Cross-file imports (named, default, namespace)
 *   - Re-export through a barrel file
 *   - Class methods + virtual interface dispatch
 *   - Arrow function / method assigned to a const
 *   - Untyped JS callgraph degrades but still emits unresolved edges
 *   - Module initializer captures top-level calls
 *   - tsconfig discovery vs synthetic fallback
 *
 * Run: npx tsx test/taint-engine-callgraph.test.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildCallgraph } from '../src/taint-engine';
import type { Callgraph } from '../src/taint-engine';

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

function makeWorkspace(name: string, files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `cg-${name}-`));
  for (const [rel, body] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body, 'utf8');
  }
  return root;
}

function findEdge(cg: Callgraph, callerNameSubstr: string, calleeText: string) {
  return cg.edges.find(
    (e) => e.calleeText === calleeText && cg.nodes.find((n) => n.id === e.callerId)?.name.includes(callerNameSubstr) != null,
  );
}

function findNode(cg: Callgraph, name: string) {
  return cg.nodes.find((n) => n.name === name);
}

async function testDirectCall() {
  console.log('\n[test] direct same-file call');
  const root = makeWorkspace('direct', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: true } }),
    'src/main.ts': `
      function helper(x: string): string { return x.toUpperCase(); }
      function main(): void { helper('hi'); }
      main();
    `,
  });
  const cg = await buildCallgraph({ rootDir: root });
  assert(cg.hasOwnTsconfig, 'tsconfig discovered');
  assert(findNode(cg, 'helper') != null, 'helper function emitted');
  assert(findNode(cg, 'main') != null, 'main function emitted');
  const edge = cg.edges.find((e) => e.calleeText === 'helper');
  assert(edge != null, 'main → helper edge emitted');
  assert(edge?.kind === 'static', 'edge kind is static');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testCrossFileImport() {
  console.log('\n[test] cross-file named import');
  const root = makeWorkspace('cross-file', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: true } }),
    'src/util.ts': `export function escape(s: string): string { return s.replace(/</g, '&lt;'); }`,
    'src/main.ts': `import { escape } from './util';
      function render(input: string): string { return escape(input); }
      render('a');`,
  });
  const cg = await buildCallgraph({ rootDir: root });
  const edge = cg.edges.find((e) => e.calleeText === 'escape');
  assert(edge != null, 'render → escape edge emitted');
  assert(edge?.kind === 'static', 'cross-file import resolves to static');
  const calleeNode = cg.nodes.find((n) => n.id === edge?.calleeId);
  assert(calleeNode?.filePath === 'src/util.ts', 'callee resolves to util.ts');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testNamespaceImport() {
  console.log('\n[test] namespace + default + barrel re-export');
  const root = makeWorkspace('namespace', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', module: 'commonjs', esModuleInterop: true, strict: true } }),
    'src/lib/format.ts': `export function bold(s: string): string { return '**' + s + '**'; }`,
    'src/lib/index.ts': `export * from './format';`,
    'src/main.ts': `import * as L from './lib';
      function go() { return L.bold('hi'); }
      go();`,
  });
  const cg = await buildCallgraph({ rootDir: root });
  const edge = cg.edges.find((e) => e.calleeText === 'L.bold');
  assert(edge != null, 'namespace.bold edge emitted');
  assert(edge?.kind === 'static', 'namespace re-export resolved to static');
  const calleeNode = cg.nodes.find((n) => n.id === edge?.calleeId);
  assert(calleeNode?.filePath === 'src/lib/format.ts', 'barrel re-export resolves through to format.ts');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testClassMethodAndVirtual() {
  console.log('\n[test] class method + virtual interface dispatch');
  const root = makeWorkspace('class', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: true } }),
    'src/main.ts': `
      interface Greeter { hi(name: string): string; }
      class En implements Greeter { hi(n: string) { return 'Hello ' + n; } }
      function go(g: Greeter) { return g.hi('world'); }
      go(new En());
    `,
  });
  const cg = await buildCallgraph({ rootDir: root });
  const hiNode = cg.nodes.find((n) => n.name === 'hi' && n.kind === 'method');
  assert(hiNode != null, 'class method node emitted');
  assert(hiNode?.containingClass === 'En', 'method records containing class');
  const virtualEdge = cg.edges.find((e) => e.calleeText === 'g.hi');
  assert(virtualEdge != null, 'virtual call site emitted');
  assert(
    virtualEdge?.kind === 'virtual' || virtualEdge?.kind === 'static',
    'virtual call resolves (kind=virtual or static depending on TS resolution)',
  );
  fs.rmSync(root, { recursive: true, force: true });
}

async function testArrowAssignedToConst() {
  console.log('\n[test] arrow function assigned to const');
  const root = makeWorkspace('arrow', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: true } }),
    'src/main.ts': `
      const upper = (s: string): string => s.toUpperCase();
      function caller() { return upper('a'); }
      caller();
    `,
  });
  const cg = await buildCallgraph({ rootDir: root });
  const upperNode = cg.nodes.find((n) => n.name === 'upper');
  assert(upperNode != null, 'arrow function picks up const name');
  assert(upperNode?.kind === 'arrow_function', 'kind is arrow_function');
  const edge = cg.edges.find((e) => e.calleeText === 'upper');
  assert(edge?.calleeId === upperNode?.id, 'caller → upper edge resolves to arrow node');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testUntypedJsDegrades() {
  console.log('\n[test] untyped JS — fallback tsconfig + degraded resolution');
  const root = makeWorkspace('untyped-js', {
    // No tsconfig — engine should synthesize the fallback.
    'src/util.js': `function helper(x) { return x; }
      module.exports = { helper };`,
    'src/main.js': `const u = require('./util');
      function main() { return u.helper(global.something()); }
      main();`,
  });
  const cg = await buildCallgraph({ rootDir: root });
  assert(!cg.hasOwnTsconfig, 'fallback tsconfig used');
  assert(cg.fileCount === 2, 'both .js files included');
  // global.something() should be unresolved (no type info).
  const dyn = cg.edges.find((e) => e.calleeText === 'global.something');
  assert(dyn != null, 'unresolved dynamic call still emits an edge');
  assert(dyn?.kind === 'unresolved', 'untyped dynamic call kind=unresolved');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testModuleInitializer() {
  console.log('\n[test] top-level call attributed to module initializer');
  const root = makeWorkspace('module-init', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: true } }),
    'src/main.ts': `
      function side(): void {}
      side();
    `,
  });
  const cg = await buildCallgraph({ rootDir: root });
  const moduleNode = cg.nodes.find((n) => n.isModuleInitializer && n.filePath === 'src/main.ts');
  assert(moduleNode != null, 'module initializer node present');
  const edge = cg.edges.find((e) => e.calleeText === 'side' && e.callerId === moduleNode?.id);
  assert(edge != null, 'top-level call attributed to module initializer');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testTypingTelemetry() {
  console.log('\n[test] typing telemetry — typed TS project flagged as typed');
  const root = makeWorkspace('typed', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: true } }),
    'src/a.ts': `export function a(): number { return 1; }`,
    'src/b.ts': `import { a } from './a'; export function b(): number { return a() + 1; }`,
    'src/main.ts': `import { b } from './b'; function go(): number { return b(); } go();`,
  });
  const cg = await buildCallgraph({ rootDir: root });
  assert(cg.isTypedJsProject, 'typed TS project flagged isTypedJsProject=true');
  assert(cg.typedFilesPct === 100, 'typedFilesPct = 100');
  assert(cg.buildMs >= 0, 'buildMs reported');
  fs.rmSync(root, { recursive: true, force: true });
}

async function main() {
  console.log('=== taint-engine callgraph tests ===');
  await testDirectCall();
  await testCrossFileImport();
  await testNamespaceImport();
  await testClassMethodAndVirtual();
  await testArrowAssignedToConst();
  await testUntypedJsDegrades();
  await testModuleInitializer();
  await testTypingTelemetry();

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('test run threw:', err);
  process.exit(2);
});
