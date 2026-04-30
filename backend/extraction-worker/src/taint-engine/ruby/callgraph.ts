/**
 * Whole-program callgraph for a Ruby workspace, built on web-tree-sitter
 * (Ruby WASM grammar shipped via `@repomix/tree-sitter-wasms`). Mirrors the
 * shape returned by the TS / Python callgraphs so the same downstream
 * propagator-style worklist can consume it.
 *
 * Resolution strategy (best-effort, no full type system):
 *   - Walk every `*.rb` file under rootDir, collect `method` and
 *     `singleton_method` definitions, plus class context. Emit a synthetic
 *     `<module>` node per file for top-level code.
 *   - Track requires per file (`require './foo'`, `require_relative 'foo'`,
 *     `require 'foo'`) and resolve same-workspace targets to `.rb` paths.
 *   - For each call, attempt to map the callee's textual root
 *     (`foo(...)`, `Mod.foo(...)`, `obj.method(...)`, `self.method(...)`)
 *     to a function we've cataloged:
 *       - bare `foo(...)` → method on the enclosing class, OR top-level
 *         method in the same file
 *       - `Class.foo(...)` / `Class::foo(...)` → class method on `Class`
 *         in the same file (or, best-effort, anywhere in the workspace)
 *       - `self.method(...)` → method on the enclosing class
 *     Anything else gets emitted as `unresolved` with the textual callee.
 *
 * Known v1 limitations (documented for follow-up):
 *   - No metaprogramming / `define_method` / `method_missing` resolution.
 *   - No `Module#include` / mixin resolution beyond the same file.
 *   - Inheritance is best-effort within the same file; cross-file MRO is
 *     not modeled.
 *   - Block params (`do |x| ... end`) and yield are not taint-tracked
 *     across the block boundary (the IR lowerer walks the body but does
 *     not flow yields).
 *   - `*args` / `**kwargs` propagate as a single positional slot — taint
 *     entering via splat is over-approximated to all params.
 */

import * as fs from 'fs';
import * as path from 'path';
import { Language, Parser, type Node, type Tree } from 'web-tree-sitter';
import { loadLanguage, makeParser } from '../../tree-sitter-extractor/parser';
import type {
  Callgraph,
  CallEdge,
  CallEdgeKind,
  FileStats,
  FunctionId,
  FunctionKind,
  FunctionNode,
} from '../types';

export interface BuildRubyCallgraphOptions {
  rootDir: string;
  /** Optional cap on number of files (test perf). */
  maxFiles?: number;
  onWarn?: (msg: string) => void;
}

/** Directories to skip during traversal. */
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'vendor',
  '.bundle',
  'tmp',
  'log',
  'dist',
  'build',
  '.deptex',
]);

const RB_EXTENSION = '.rb';

interface FileTrees {
  filePath: string;
  absolutePath: string;
  source: string;
  tree: Tree;
}

interface FileImports {
  /** Resolved relative paths (POSIX) of files this file `require`s/`require_relative`s. */
  requiredFiles: Set<string>;
}

interface FileFunctions {
  /** name → FunctionId for top-level methods (defined outside any class). */
  topLevel: Map<string, FunctionId>;
  /** "ClassName.methodName" → FunctionId for class methods + instance methods. */
  methods: Map<string, FunctionId>;
  /** synthetic module initializer FunctionId. */
  moduleId: FunctionId;
}

/**
 * Public API: build the Callgraph for a Ruby workspace.
 */
export async function buildRubyCallgraph(
  rootDirOrOpts: string | BuildRubyCallgraphOptions,
): Promise<Callgraph> {
  const ctx = await buildRubyCallgraphContext(rootDirOrOpts);
  return ctx.callgraph;
}

/** Get the per-file tree info computed during build. Used by IR lowerer. */
export interface RubyFileContext {
  filePath: string;
  absolutePath: string;
  source: string;
  tree: Tree;
  imports: FileImports;
  functions: FileFunctions;
}

/**
 * Like buildRubyCallgraph but also returns the per-file parse trees +
 * resolution maps needed by the Ruby IR lowerer + propagator driver.
 */
export interface RubyCallgraphContext {
  callgraph: Callgraph;
  files: Map<string, RubyFileContext>;
  /** functionId → AST node (`method` / `singleton_method` / module root) */
  nodeIdToFunc: Map<FunctionId, Node>;
}

export async function buildRubyCallgraphContext(
  rootDirOrOpts: string | BuildRubyCallgraphOptions,
): Promise<RubyCallgraphContext> {
  const opts: BuildRubyCallgraphOptions =
    typeof rootDirOrOpts === 'string' ? { rootDir: rootDirOrOpts } : rootDirOrOpts;
  const start = Date.now();
  const absoluteRoot = path.resolve(opts.rootDir);

  const files = collectRubyFiles(absoluteRoot, opts.maxFiles);
  const language: Language = await loadLanguage('tree-sitter-ruby.wasm');

  const parsedFiles: FileTrees[] = [];
  for (const abs of files) {
    let source: string;
    try {
      source = fs.readFileSync(abs, 'utf8');
    } catch (err) {
      opts.onWarn?.(`failed to read ${abs}: ${(err as Error).message}`);
      continue;
    }
    const parser: Parser = await makeParser(language);
    const tree = parser.parse(source);
    if (!tree) {
      opts.onWarn?.(`tree-sitter returned null for ${abs}`);
      continue;
    }
    parsedFiles.push({
      filePath: toRelativePosix(abs, absoluteRoot),
      absolutePath: abs,
      source,
      tree,
    });
  }

  const nodes: FunctionNode[] = [];
  const fileFunctions = new Map<string, FileFunctions>();
  const nodeIdToFunc = new Map<FunctionId, Node>();

  // Pass 1: collect functions.
  for (const f of parsedFiles) {
    const ff = collectFunctionsForFile(f, nodes, nodeIdToFunc);
    fileFunctions.set(f.filePath, ff);
  }

  // Pass 2: collect requires.
  const knownFiles = new Set(parsedFiles.map((p) => p.filePath));
  const fileImports = new Map<string, FileImports>();
  for (const f of parsedFiles) {
    fileImports.set(f.filePath, collectImports(f, knownFiles));
  }

  // Pass 3: emit edges.
  const edges: CallEdge[] = [];
  const fileStats: FileStats[] = [];
  for (const f of parsedFiles) {
    const stats = collectCallEdges(f, fileFunctions, fileImports, edges);
    fileStats.push(stats);
  }

  const callgraph: Callgraph = {
    rootDir: absoluteRoot,
    hasOwnTsconfig: false,
    isTypedJsProject: false,
    typedFilesPct: 0,
    nodes,
    edges,
    fileStats,
    buildMs: Date.now() - start,
    fileCount: fileStats.length,
  };

  const filesContext = new Map<string, RubyFileContext>();
  for (const f of parsedFiles) {
    filesContext.set(f.filePath, {
      filePath: f.filePath,
      absolutePath: f.absolutePath,
      source: f.source,
      tree: f.tree,
      imports: fileImports.get(f.filePath) ?? { requiredFiles: new Set() },
      functions:
        fileFunctions.get(f.filePath) ?? {
          topLevel: new Map(),
          methods: new Map(),
          moduleId: makeFunctionId(f.filePath, 1, 1, '<module>'),
        },
    });
  }

  return { callgraph, files: filesContext, nodeIdToFunc };
}

function collectRubyFiles(absoluteRoot: string, maxFiles?: number): string[] {
  const out: string[] = [];
  const stack: string[] = [absoluteRoot];
  while (stack.length > 0) {
    if (maxFiles != null && out.length >= maxFiles) break;
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith('.') && entry.name !== '.') continue;
        stack.push(full);
      } else if (entry.isFile() && path.extname(entry.name).toLowerCase() === RB_EXTENSION) {
        out.push(full);
      }
    }
  }
  return out;
}

function toRelativePosix(absolute: string, absoluteRoot: string): string {
  return path.relative(absoluteRoot, absolute).split(path.sep).join('/');
}

export function makeFunctionId(filePath: string, line: number, column: number, name: string): FunctionId {
  return `${filePath}:${line}:${column}:${name}`;
}

function textOf(node: Node | null | undefined, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

/**
 * Walk a Ruby AST and find every `method` / `singleton_method` node, with
 * its enclosing class (if any). Tree-sitter-ruby uses:
 *   - `method` for `def foo ... end`
 *   - `singleton_method` for `def self.foo ... end` / `def Class.foo ... end`
 *   - `class` for class definitions
 *   - `module` for module definitions (we treat these like classes for
 *     method namespacing).
 */
function findMethodDefs(
  root: Node,
): Array<{ node: Node; isSingleton: boolean; enclosing: string | null }> {
  const out: Array<{ node: Node; isSingleton: boolean; enclosing: string | null }> = [];
  const visit = (node: Node, enclosing: string | null): void => {
    let nextEnclosing = enclosing;
    if (node.type === 'class' || node.type === 'module') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        // For nested constants (e.g. `class Foo::Bar`), grab the trailing piece.
        const text = nameNode.text ?? '';
        const last = text.split('::').pop()!.trim();
        nextEnclosing = last || nextEnclosing;
      }
    } else if (node.type === 'method' || node.type === 'singleton_method') {
      out.push({ node, isSingleton: node.type === 'singleton_method', enclosing });
      // Don't descend into method bodies looking for more method defs at the
      // class level — nested defs get the enclosing method's class as their
      // class context, which is fine for v1.
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child, nextEnclosing);
    }
  };
  visit(root, null);
  return out;
}

function collectFunctionsForFile(
  f: FileTrees,
  nodes: FunctionNode[],
  nodeIdToFunc: Map<FunctionId, Node>,
): FileFunctions {
  const root = f.tree.rootNode;
  const lastLine = root.endPosition.row + 1;

  // Module initializer.
  const moduleId = makeFunctionId(f.filePath, 1, 1, '<module>');
  nodes.push({
    id: moduleId,
    name: '<module>',
    kind: 'module_initializer',
    filePath: f.filePath,
    startLine: 1,
    startColumn: 1,
    endLine: Math.max(1, lastLine),
    endColumn: 1,
    isFullyTyped: false,
    containingClass: null,
    isModuleInitializer: true,
  });
  nodeIdToFunc.set(moduleId, root);

  const topLevel = new Map<string, FunctionId>();
  const methods = new Map<string, FunctionId>();

  for (const def of findMethodDefs(root)) {
    const nameNode = def.node.childForFieldName('name');
    const name = textOf(nameNode, f.source);
    if (!name) continue;
    const start = def.node.startPosition;
    const end = def.node.endPosition;
    const containingClass = def.enclosing;
    const kind: FunctionKind = containingClass ? 'method' : 'function_declaration';
    const id = makeFunctionId(f.filePath, start.row + 1, start.column + 1, name);
    nodes.push({
      id,
      name,
      kind,
      filePath: f.filePath,
      startLine: start.row + 1,
      startColumn: start.column + 1,
      endLine: end.row + 1,
      endColumn: end.column + 1,
      isFullyTyped: false,
      containingClass,
      isModuleInitializer: false,
    });
    nodeIdToFunc.set(id, def.node);
    if (containingClass) {
      methods.set(`${containingClass}.${name}`, id);
    } else {
      topLevel.set(name, id);
    }
  }

  return { topLevel, methods, moduleId };
}

/**
 * Collect `require`, `require_relative`, `load` calls and resolve them to
 * workspace-relative file paths when possible. Best-effort: bundler /
 * autoload / Rails magic isn't modeled.
 */
function collectImports(f: FileTrees, knownFiles: Set<string>): FileImports {
  const requiredFiles = new Set<string>();
  const fileDir = path.posix.dirname(f.filePath);

  const tryResolve = (raw: string, relative: boolean): void => {
    // Strip surrounding quotes if present in the raw text.
    let arg = raw.trim();
    if (
      (arg.startsWith('"') && arg.endsWith('"')) ||
      (arg.startsWith("'") && arg.endsWith("'"))
    ) {
      arg = arg.slice(1, -1);
    }
    if (!arg) return;
    // Drop trailing .rb if present; we'll add it back.
    const noExt = arg.endsWith('.rb') ? arg.slice(0, -3) : arg;

    const candidates: string[] = [];
    if (relative) {
      const joined = path.posix.normalize(path.posix.join(fileDir, noExt + '.rb'));
      candidates.push(joined);
    } else {
      // `require './foo'` style still possible without require_relative
      if (arg.startsWith('./') || arg.startsWith('../')) {
        candidates.push(path.posix.normalize(path.posix.join(fileDir, noExt + '.rb')));
      }
      // Treat as workspace-relative best-effort.
      candidates.push(noExt + '.rb');
    }
    for (const c of candidates) {
      if (knownFiles.has(c)) {
        requiredFiles.add(c);
        return;
      }
    }
  };

  const visit = (node: Node): void => {
    if (node.type === 'call') {
      const methodNode = node.childForFieldName('method');
      const recv = node.childForFieldName('receiver');
      const args = node.childForFieldName('arguments');
      const methodText = textOf(methodNode, f.source);
      // Only recognize bare `require '...'` / `require_relative '...'`
      // (no receiver or receiver = `Kernel`).
      if (
        (methodText === 'require' ||
          methodText === 'require_relative' ||
          methodText === 'load') &&
        (!recv || textOf(recv, f.source) === 'Kernel')
      ) {
        if (args && args.namedChildCount > 0) {
          const arg0 = args.namedChild(0);
          if (arg0) {
            const raw = stringLiteralValue(arg0, f.source);
            if (raw != null) {
              tryResolve(raw, methodText === 'require_relative');
            }
          }
        }
      }
    } else if (node.type === 'method_call' || node.type === 'identifier') {
      // Some tree-sitter-ruby versions expose bare `require 'x'` as a
      // method_call without receiver, or just an identifier followed by a
      // string literal sibling — handled by the generic walk below.
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child);
    }
  };
  visit(f.tree.rootNode);

  return { requiredFiles };
}

/**
 * If `node` is a string literal node, return its inner text content
 * (without quotes). Returns null otherwise.
 */
function stringLiteralValue(node: Node, source: string): string | null {
  if (node.type !== 'string' && node.type !== 'simple_symbol' && node.type !== 'bare_symbol') {
    return null;
  }
  // Look for a `string_content` child; otherwise fall back to slicing
  // off the leading/trailing quote chars.
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && child.type === 'string_content') {
      return textOf(child, source);
    }
  }
  const raw = textOf(node, source);
  if (
    (raw.startsWith('"') && raw.endsWith('"')) ||
    (raw.startsWith("'") && raw.endsWith("'"))
  ) {
    return raw.slice(1, -1);
  }
  return raw;
}

/**
 * Find the FunctionId that a call-site's callee text resolves to in the
 * file at `filePath`. Returns null if unresolved.
 */
export function resolveRubyCallee(
  calleeText: string,
  filePath: string,
  fileFunctions: Map<string, FileFunctions>,
  fileImports: Map<string, FileImports>,
  enclosingClass: string | null,
): { calleeId: FunctionId | null; kind: CallEdgeKind } {
  const ff = fileFunctions.get(filePath);
  if (!ff) return { calleeId: null, kind: 'unresolved' };

  // Normalize `Foo::bar` to `Foo.bar` for resolution purposes.
  const normalized = calleeText.replace(/::/g, '.');
  const parts = normalized.split('.');

  // bare name(...)
  if (parts.length === 1) {
    const name = parts[0];
    // Method on enclosing class?
    if (enclosingClass) {
      const m = ff.methods.get(`${enclosingClass}.${name}`);
      if (m) return { calleeId: m, kind: 'static' };
    }
    // Top-level method?
    const top = ff.topLevel.get(name);
    if (top) return { calleeId: top, kind: 'static' };
    // Cross-file, via required files.
    const imp = fileImports.get(filePath);
    if (imp) {
      for (const rf of imp.requiredFiles) {
        const otherFf = fileFunctions.get(rf);
        if (!otherFf) continue;
        const found = otherFf.topLevel.get(name);
        if (found) return { calleeId: found, kind: 'static' };
      }
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // self.method(...) / Class.method(...) (length 2)
  if (parts.length === 2) {
    const recv = parts[0];
    const method = parts[1];
    if (recv === 'self' && enclosingClass) {
      const m = ff.methods.get(`${enclosingClass}.${method}`);
      if (m) return { calleeId: m, kind: 'static' };
      return { calleeId: null, kind: 'unresolved' };
    }
    // Treat capitalized receiver as a class name.
    if (/^[A-Z]/.test(recv)) {
      const m = ff.methods.get(`${recv}.${method}`);
      if (m) return { calleeId: m, kind: 'static' };
      // Cross-file best-effort.
      const imp = fileImports.get(filePath);
      if (imp) {
        for (const rf of imp.requiredFiles) {
          const otherFf = fileFunctions.get(rf);
          if (!otherFf) continue;
          const found = otherFf.methods.get(`${recv}.${method}`);
          if (found) return { calleeId: found, kind: 'static' };
        }
      }
      // Last resort: any class.method with that exact key in any file.
      for (const [, otherFf] of fileFunctions) {
        const found = otherFf.methods.get(`${recv}.${method}`);
        if (found) return { calleeId: found, kind: 'static' };
      }
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  return { calleeId: null, kind: 'unresolved' };
}

function collectCallEdges(
  f: FileTrees,
  fileFunctions: Map<string, FileFunctions>,
  fileImports: Map<string, FileImports>,
  edges: CallEdge[],
): FileStats {
  let callExpressionCount = 0;
  let resolvedCallCount = 0;

  const visit = (node: Node, enclosingFnId: FunctionId, enclosingClassName: string | null): void => {
    let nextEnclosingFnId = enclosingFnId;
    let nextEnclosingClass = enclosingClassName;

    if (node.type === 'method' || node.type === 'singleton_method') {
      const nameNode = node.childForFieldName('name');
      const name = textOf(nameNode, f.source);
      const start = node.startPosition;
      const id = makeFunctionId(f.filePath, start.row + 1, start.column + 1, name);
      nextEnclosingFnId = id;
    } else if (node.type === 'class' || node.type === 'module') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const last = (nameNode.text ?? '').split('::').pop()!.trim();
        nextEnclosingClass = last || nextEnclosingClass;
      }
    } else if (node.type === 'call') {
      callExpressionCount++;
      const methodNode = node.childForFieldName('method');
      const recvNode = node.childForFieldName('receiver');
      const argList = node.childForFieldName('arguments');
      let calleeText: string;
      if (recvNode) {
        const recvText = textOf(recvNode, f.source);
        const methodText = textOf(methodNode, f.source);
        calleeText = `${recvText}.${methodText}`;
      } else {
        calleeText = textOf(methodNode, f.source);
      }
      let argumentCount = 0;
      if (argList) {
        for (let i = 0; i < argList.namedChildCount; i++) {
          const c = argList.namedChild(i);
          if (c && c.type !== 'comment') argumentCount++;
        }
      }
      const { calleeId, kind } = resolveRubyCallee(
        calleeText,
        f.filePath,
        fileFunctions,
        fileImports,
        enclosingClassName,
      );
      if (calleeId) resolvedCallCount++;
      const start = node.startPosition;
      edges.push({
        callerId: enclosingFnId,
        calleeId,
        kind,
        filePath: f.filePath,
        line: start.row + 1,
        column: start.column + 1,
        calleeText,
        argumentCount,
      });
    }

    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child, nextEnclosingFnId, nextEnclosingClass);
    }
  };

  const moduleId = fileFunctions.get(f.filePath)?.moduleId ?? makeFunctionId(f.filePath, 1, 1, '<module>');
  visit(f.tree.rootNode, moduleId, null);

  return {
    filePath: f.filePath,
    isFullyTyped: false,
    callExpressionCount,
    resolvedCallCount,
  };
}
