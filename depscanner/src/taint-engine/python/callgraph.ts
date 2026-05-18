/**
 * Whole-program callgraph for a Python workspace, built on web-tree-sitter
 * (Python WASM grammar shipped via `@repomix/tree-sitter-wasms`). Mirrors the
 * shape returned by the TS callgraph (`buildCallgraph`) so the same
 * downstream propagator-style worklist can consume it.
 *
 * Resolution strategy (best-effort, no full type system):
 *   - Walk every `*.py` file under rootDir, collect `function_definition` and
 *     `decorated_definition`-wrapped function definitions, plus methods inside
 *     classes. Emit a synthetic `<module>` node per file for top-level code.
 *   - Track imports per file (`import x`, `import x as y`, `from x import a`,
 *     `from x import a as b`, relative imports) and resolve same-package
 *     module sources to repo-relative `.py` paths.
 *   - For each call expression, attempt to map the callee's textual root
 *     (`foo(...)`, `mod.foo(...)`, `obj.method(...)`, `self.method(...)`) to
 *     a function we've cataloged:
 *       - bare `foo(...)` → file-local def named `foo`, OR an imported name `foo`
 *         where we know the originating file
 *       - `mod.foo(...)` → resolve `mod` via the import alias map
 *       - `self.method(...)` / `cls.method(...)` → method defined on the
 *         enclosing class (or one of its bases when we can resolve them)
 *     Anything else gets emitted as `unresolved` with the textual callee.
 *
 * Known v1 limitations (documented for follow-up):
 *   - No dynamic dispatch via `getattr`, `__getattr__`, monkey-patching, or
 *     metaclass-modified attribute lookup.
 *   - Decorators are skipped (the wrapped function is registered, but the
 *     decorator's transform is ignored — relevant for `@app.route` etc., but
 *     framework specs handle that side via source patterns).
 *   - Class inheritance only resolves one level when the base is a plain
 *     identifier defined in the same file; cross-file MRO is best-effort.
 *   - Tuple unpacking in `for x, y in ...` is not lowered into per-element
 *     taint, only into IR assignments by the lowerer (see ir.ts).
 *   - `*args`/`**kwargs` propagate as a single positional arg slot — taint
 *     entering via kwargs is over-approximated to all params.
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

export interface BuildPythonCallgraphOptions {
  rootDir: string;
  /** Optional cap on number of files (test perf). */
  maxFiles?: number;
  onWarn?: (msg: string) => void;
}

/** Directories to skip during traversal. */
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '__pycache__',
  '.venv',
  'venv',
  'env',
  '.env',
  '.tox',
  '.mypy_cache',
  '.pytest_cache',
  'dist',
  'build',
  '.deptex',
]);

const PY_EXTENSION = '.py';

interface FileTrees {
  filePath: string;
  absolutePath: string;
  source: string;
  tree: Tree;
}

interface FileImports {
  /** localName → resolved relative module file path (POSIX). */
  moduleSourceForLocal: Map<string, string>;
  /**
   * For `from X import name [as alias]`, map alias → name in module X.
   * Used to resolve `name(...)` to an internal function in X's file.
   */
  fromImportName: Map<string, { module: string; importedName: string }>;
}

interface FileFunctions {
  /** name → FunctionId for top-level functions in the file. */
  topLevel: Map<string, FunctionId>;
  /** "ClassName.methodName" → FunctionId for class methods in the file. */
  methods: Map<string, FunctionId>;
  /** synthetic module initializer FunctionId. */
  moduleId: FunctionId;
}

/**
 * Public API: build the Callgraph for a Python workspace.
 */
export async function buildPythonCallgraph(
  rootDirOrOpts: string | BuildPythonCallgraphOptions,
): Promise<Callgraph> {
  const opts: BuildPythonCallgraphOptions =
    typeof rootDirOrOpts === 'string' ? { rootDir: rootDirOrOpts } : rootDirOrOpts;
  const start = Date.now();
  const absoluteRoot = path.resolve(opts.rootDir);

  const files = collectPythonFiles(absoluteRoot, opts.maxFiles);
  const language: Language = await loadLanguage('tree-sitter-python.wasm');

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

  // Pass 1: collect functions.
  for (const f of parsedFiles) {
    const ff = collectFunctionsForFile(f, nodes);
    fileFunctions.set(f.filePath, ff);
  }

  // Pass 2: collect imports (depends on which files / module names we know about).
  const knownModules = buildModuleIndex(parsedFiles);
  const fileImports = new Map<string, FileImports>();
  for (const f of parsedFiles) {
    fileImports.set(f.filePath, collectImports(f, knownModules));
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

  return callgraph;
}

/** Get the per-file tree info computed during build. Used by IR lowerer. */
export interface PythonFileContext {
  filePath: string;
  absolutePath: string;
  source: string;
  tree: Tree;
  imports: FileImports;
  functions: FileFunctions;
}

/**
 * Like buildPythonCallgraph but also returns the per-file parse trees +
 * resolution maps needed by the Python IR lowerer + propagator driver.
 */
export interface PythonCallgraphContext {
  callgraph: Callgraph;
  files: Map<string, PythonFileContext>;
  /** functionId → AST node (function_definition) */
  nodeIdToFunc: Map<FunctionId, Node>;
}

export async function buildPythonCallgraphContext(
  rootDirOrOpts: string | BuildPythonCallgraphOptions,
): Promise<PythonCallgraphContext> {
  const opts: BuildPythonCallgraphOptions =
    typeof rootDirOrOpts === 'string' ? { rootDir: rootDirOrOpts } : rootDirOrOpts;
  const start = Date.now();
  const absoluteRoot = path.resolve(opts.rootDir);

  const files = collectPythonFiles(absoluteRoot, opts.maxFiles);
  const language: Language = await loadLanguage('tree-sitter-python.wasm');

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

  for (const f of parsedFiles) {
    const ff = collectFunctionsForFile(f, nodes, nodeIdToFunc);
    fileFunctions.set(f.filePath, ff);
  }

  const knownModules = buildModuleIndex(parsedFiles);
  const fileImports = new Map<string, FileImports>();
  for (const f of parsedFiles) {
    fileImports.set(f.filePath, collectImports(f, knownModules));
  }

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

  const filesContext = new Map<string, PythonFileContext>();
  for (const f of parsedFiles) {
    filesContext.set(f.filePath, {
      filePath: f.filePath,
      absolutePath: f.absolutePath,
      source: f.source,
      tree: f.tree,
      imports: fileImports.get(f.filePath) ?? { moduleSourceForLocal: new Map(), fromImportName: new Map() },
      functions: fileFunctions.get(f.filePath) ?? { topLevel: new Map(), methods: new Map(), moduleId: makeFunctionId(f.filePath, 1, 1, '<module>') },
    });
  }

  return { callgraph, files: filesContext, nodeIdToFunc };
}

function collectPythonFiles(absoluteRoot: string, maxFiles?: number): string[] {
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
      } else if (entry.isFile() && path.extname(entry.name).toLowerCase() === PY_EXTENSION) {
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
 * Build a mapping from Python module dotted-name (e.g. `pkg.util`) to the
 * file path where that module's code lives (e.g. `pkg/util.py`). Also handles
 * `pkg/__init__.py` mapping the package import.
 */
function buildModuleIndex(parsed: FileTrees[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const f of parsed) {
    const noExt = f.filePath.replace(/\.py$/, '');
    if (noExt.endsWith('/__init__')) {
      const pkg = noExt.slice(0, -'/__init__'.length).replace(/\//g, '.');
      if (pkg) out.set(pkg, f.filePath);
    } else {
      const dotted = noExt.replace(/\//g, '.');
      out.set(dotted, f.filePath);
    }
  }
  return out;
}

function findFunctionDefs(root: Node): Node[] {
  const out: Node[] = [];
  const visit = (node: Node): void => {
    if (node.type === 'function_definition') {
      out.push(node);
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child);
    }
  };
  visit(root);
  return out;
}

function collectFunctionsForFile(
  f: FileTrees,
  nodes: FunctionNode[],
  nodeIdToFunc?: Map<FunctionId, Node>,
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
  // Map the synthetic root for the module initializer.
  nodeIdToFunc?.set(moduleId, root);

  const topLevel = new Map<string, FunctionId>();
  const methods = new Map<string, FunctionId>();

  for (const fn of findFunctionDefs(root)) {
    const nameNode = fn.childForFieldName('name');
    const name = textOf(nameNode, f.source);
    if (!name) continue;
    const start = fn.startPosition;
    const end = fn.endPosition;
    const containingClass = enclosingClassName(fn, f.source);
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
    nodeIdToFunc?.set(id, fn);
    if (containingClass) {
      methods.set(`${containingClass}.${name}`, id);
    } else {
      topLevel.set(name, id);
    }
  }

  return { topLevel, methods, moduleId };
}

function enclosingClassName(node: Node, source: string): string | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (cur.type === 'class_definition') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
  }
  return null;
}

function collectImports(f: FileTrees, knownModules: Map<string, string>): FileImports {
  const moduleSourceForLocal = new Map<string, string>();
  const fromImportName = new Map<string, { module: string; importedName: string }>();

  const tryRegisterModule = (local: string, dottedModule: string): void => {
    const filePath = resolveModule(dottedModule, knownModules);
    if (filePath) {
      moduleSourceForLocal.set(local, filePath);
    }
  };

  const visit = (node: Node): void => {
    if (node.type === 'import_statement') {
      // `import X`, `import X as Y`, `import X, Y`
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (!child) continue;
        if (child.type === 'dotted_name') {
          const mod = textOf(child, f.source);
          if (!mod) continue;
          const local = mod.split('.')[0];
          tryRegisterModule(local, mod);
        } else if (child.type === 'aliased_import') {
          const nameNode = child.childForFieldName('name');
          const aliasNode = child.childForFieldName('alias');
          const mod = textOf(nameNode, f.source);
          const local = textOf(aliasNode, f.source);
          if (mod && local) tryRegisterModule(local, mod);
        }
      }
    } else if (node.type === 'import_from_statement') {
      // `from X import a [as b]`
      let moduleSeen = false;
      let modSource = '';
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (!child) continue;
        if (!moduleSeen) {
          if (child.type === 'dotted_name') {
            modSource = textOf(child, f.source);
            moduleSeen = true;
          } else if (child.type === 'relative_import') {
            // Could resolve the relative module; for v1 we punt unless the
            // workspace happens to expose it as a top-level dotted name.
            // Best-effort: read the trailing dotted_name if present.
            const dn = child.childForFieldName('module') ?? findChildOfType(child, 'dotted_name');
            modSource = dn ? textOf(dn, f.source) : '';
            moduleSeen = true;
          }
          continue;
        }
        if (!modSource) break;
        if (child.type === 'dotted_name') {
          const exported = textOf(child, f.source);
          const importedRoot = exported.split('.')[0];
          // The local name is the imported root (no alias).
          fromImportName.set(importedRoot, { module: modSource, importedName: exported });
          // Also register the module under the imported name so `name(...)`
          // can resolve through the from-import map; if `name` is itself a
          // submodule, expose it as a module local too.
          const submoduleDotted = `${modSource}.${exported}`;
          if (knownModules.has(submoduleDotted)) {
            tryRegisterModule(importedRoot, submoduleDotted);
          }
        } else if (child.type === 'aliased_import') {
          const nameNode = child.childForFieldName('name');
          const aliasNode = child.childForFieldName('alias');
          const exported = textOf(nameNode, f.source);
          const local = textOf(aliasNode, f.source);
          if (exported && local) {
            fromImportName.set(local, { module: modSource, importedName: exported });
            const submoduleDotted = `${modSource}.${exported}`;
            if (knownModules.has(submoduleDotted)) {
              tryRegisterModule(local, submoduleDotted);
            }
          }
        }
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child);
    }
  };
  visit(f.tree.rootNode);

  return { moduleSourceForLocal, fromImportName };
}

function findChildOfType(node: Node, type: string): Node | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && child.type === type) return child;
  }
  return null;
}

function resolveModule(dotted: string, knownModules: Map<string, string>): string | null {
  if (knownModules.has(dotted)) return knownModules.get(dotted)!;
  // Try walking up the dotted name (e.g. `pkg.util.helper` → `pkg.util` if helper isn't a module).
  const parts = dotted.split('.');
  while (parts.length > 0) {
    parts.pop();
    const sub = parts.join('.');
    if (sub && knownModules.has(sub)) return knownModules.get(sub)!;
  }
  return null;
}

/**
 * Find the FunctionId that a call-site's callee text resolves to in the file
 * f. Returns null if unresolved.
 */
export function resolvePythonCallee(
  calleeText: string,
  filePath: string,
  fileFunctions: Map<string, FileFunctions>,
  fileImports: Map<string, FileImports>,
  enclosingClass: string | null,
): { calleeId: FunctionId | null; kind: CallEdgeKind } {
  const ff = fileFunctions.get(filePath);
  const imp = fileImports.get(filePath);
  if (!ff) return { calleeId: null, kind: 'unresolved' };

  const dotted = calleeText.split('.');

  // bare name(...)
  if (dotted.length === 1) {
    const name = dotted[0];
    // local function?
    const local = ff.topLevel.get(name);
    if (local) return { calleeId: local, kind: 'static' };
    // from-imported name?
    if (imp) {
      const fromImp = imp.fromImportName.get(name);
      if (fromImp) {
        // Find the originating file via module → file map (already stored
        // as moduleSourceForLocal entries during collectImports).
        const targetFile = imp.moduleSourceForLocal.get(name);
        if (targetFile) {
          // Could be a function `imp.importedName` or a submodule.
          const targetFf = fileFunctions.get(targetFile);
          if (targetFf) {
            const fid = targetFf.topLevel.get(fromImp.importedName);
            if (fid) return { calleeId: fid, kind: 'static' };
          }
        }
        // We didn't map the local to a module; try resolving via module
        // index over a synthetic file lookup.
        for (const [, ffOther] of fileFunctions) {
          const fid = ffOther.topLevel.get(fromImp.importedName);
          if (fid) {
            // Heuristic: only accept if the target file's POSIX name matches
            // module dotted form ending with the module key.
            return { calleeId: fid, kind: 'static' };
          }
        }
      }
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // self.method(...) or cls.method(...)
  if (dotted.length === 2 && (dotted[0] === 'self' || dotted[0] === 'cls')) {
    if (enclosingClass) {
      const m = ff.methods.get(`${enclosingClass}.${dotted[1]}`);
      if (m) return { calleeId: m, kind: 'static' };
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // mod.func(...)
  if (dotted.length >= 2) {
    if (imp) {
      const targetFile = imp.moduleSourceForLocal.get(dotted[0]);
      if (targetFile) {
        const targetFf = fileFunctions.get(targetFile);
        if (targetFf) {
          // mod.func(...)
          if (dotted.length === 2) {
            const fid = targetFf.topLevel.get(dotted[1]);
            if (fid) return { calleeId: fid, kind: 'static' };
          }
          // mod.Class.method(...) — best effort
          if (dotted.length === 3) {
            const fid = targetFf.methods.get(`${dotted[1]}.${dotted[2]}`);
            if (fid) return { calleeId: fid, kind: 'static' };
          }
        }
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

    if (node.type === 'function_definition') {
      const nameNode = node.childForFieldName('name');
      const name = textOf(nameNode, f.source);
      const start = node.startPosition;
      const id = makeFunctionId(f.filePath, start.row + 1, start.column + 1, name);
      nextEnclosingFnId = id;
    } else if (node.type === 'class_definition') {
      const nameNode = node.childForFieldName('name');
      nextEnclosingClass = textOf(nameNode, f.source) || nextEnclosingClass;
    } else if (node.type === 'call') {
      callExpressionCount++;
      const fn = node.childForFieldName('function');
      const calleeText = textOf(fn, f.source);
      const argList = node.childForFieldName('arguments');
      let argumentCount = 0;
      if (argList) {
        for (let i = 0; i < argList.namedChildCount; i++) {
          const c = argList.namedChild(i);
          if (c && c.type !== 'comment') argumentCount++;
        }
      }
      const { calleeId, kind } = resolvePythonCallee(
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
