/**
 * Whole-program callgraph for a PHP workspace, built on web-tree-sitter
 * (PHP WASM grammar shipped via `@repomix/tree-sitter-wasms`). Mirrors the
 * shape returned by the TS callgraph (`buildCallgraph`) so the same
 * downstream propagator-style worklist can consume it.
 *
 * Resolution strategy (best-effort, no full type inference):
 *   - Walk every `*.php` file under rootDir, collect `function_definition` and
 *     `method_declaration` (the latter inside `class_declaration`/
 *     `trait_declaration`/`interface_declaration`). Emit a synthetic `<file>`
 *     node per file for top-level (script-style) statements.
 *   - Track the file's namespace (`namespace Foo\Bar;`) and `use` statements
 *     (`use Foo\Bar\Baz;`, `use Foo\Bar\Baz as B;`, `use function Foo\bar;`)
 *     to build `simpleName -> FQN` aliases.
 *   - For each call expression, attempt to map the callee text to a
 *     cataloged function:
 *       - `func(...)`             → bare function (file-local, then global FQN)
 *       - `Foo::method(...)`      → static method on aliased / FQN class
 *       - `$obj->method(...)`     → instance method; resolve $obj's type via
 *         simple `$x = new C()` pattern, parameter type hints, and property
 *         declarations on $this (best-effort, same-file, same-class)
 *       - `$this->method(...)`    → method on the enclosing class
 *       - `parent::method(...)`   → method on the declared parent class
 *
 * Cross-file lookup is by class FQN match (FQN built from the file's
 * `namespace` + simple class name, or via `use` aliases). `require` /
 * `include` / `require_once` / `include_once` are NOT resolved into
 * symbol-import edges — PHP's autoloader (Composer PSR-4) supplies that in
 * practice; we rely on `use` statements + global FQN match instead.
 *
 * Known v1 limitations (documented for follow-up):
 *   - No `__call`/`__get`/`__callStatic` magic-method modeling.
 *   - Class hierarchy resolution beyond same-file `extends X` (single hop)
 *     and same-namespace match — no MRO / interface fanout.
 *   - No `eval`-tracked code, dynamic class names (`new $cls()`), or trait
 *     `use` body inlining.
 *   - Variadic args (`...$args`) collapse to a single positional slot.
 *   - Late static binding (`static::`) treated like `self::` (best-effort).
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

export interface BuildPhpCallgraphOptions {
  rootDir: string;
  /** Optional cap on number of files (test perf). */
  maxFiles?: number;
  onWarn?: (msg: string) => void;
}

const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'vendor',
  'cache',
  'var',
  '.deptex',
  '.idea',
  '.vscode',
  'dist',
  'build',
]);

const PHP_EXTENSIONS = new Set(['.php', '.phtml']);

interface FileTrees {
  filePath: string;
  absolutePath: string;
  source: string;
  tree: Tree;
}

interface FileImports {
  /** Simple name (last segment) → FQN, populated from `use Foo\Bar\Baz [as Alias];`. */
  classAliases: Map<string, string>;
  /** Function-import: `use function Foo\bar [as b];` — alias → fully qualified function name. */
  functionAliases: Map<string, string>;
  /** Constant-import: `use const ...` — alias → FQN (not used for callgraph but tracked). */
  constAliases: Map<string, string>;
  /** Namespace declared at the top of the file, or empty string. */
  namespace: string;
}

interface FileFunctions {
  /** simple function name (no namespace) → FunctionId for top-level functions in the file. */
  topLevelByName: Map<string, FunctionId>;
  /** "ClassName::methodName" or "ClassName->methodName" → FunctionId. We store both
   * arrow (instance) and double-colon (static) under separate keys for clarity, but
   * resolution is forgiving. */
  methods: Map<string, FunctionId>;
  /** simple class name → declared parent class simple name (from `extends X`). */
  classParent: Map<string, string>;
  /** simple class name → AST class_declaration node. */
  classNodes: Map<string, Node>;
  /** synthetic file initializer FunctionId. */
  fileId: FunctionId;
}

/** Public API: build the Callgraph for a PHP workspace. */
export async function buildPhpCallgraph(
  rootDirOrOpts: string | BuildPhpCallgraphOptions,
): Promise<Callgraph> {
  const ctx = await buildPhpCallgraphContext(rootDirOrOpts);
  return ctx.callgraph;
}

/** Per-file context carried through to the IR lowerer + driver. */
export interface PhpFileContext {
  filePath: string;
  absolutePath: string;
  source: string;
  tree: Tree;
  imports: FileImports;
  functions: FileFunctions;
}

export interface PhpCallgraphContext {
  callgraph: Callgraph;
  files: Map<string, PhpFileContext>;
  /** functionId → AST node (function_definition, method_declaration, or file root). */
  nodeIdToFunc: Map<FunctionId, Node>;
  /** Global FQN function name → FunctionId (built from namespace + bare name). */
  globalFunctionsByFqn: Map<string, FunctionId>;
  /** Global FQN class name → file path that declared it. */
  classFqnToFile: Map<string, string>;
}

export async function buildPhpCallgraphContext(
  rootDirOrOpts: string | BuildPhpCallgraphOptions,
): Promise<PhpCallgraphContext> {
  const opts: BuildPhpCallgraphOptions =
    typeof rootDirOrOpts === 'string' ? { rootDir: rootDirOrOpts } : rootDirOrOpts;
  const start = Date.now();
  const absoluteRoot = path.resolve(opts.rootDir);

  const files = collectPhpFiles(absoluteRoot, opts.maxFiles);
  const language: Language = await loadLanguage('tree-sitter-php.wasm');

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
  const nodeIdToFunc = new Map<FunctionId, Node>();
  const fileFunctionsByPath = new Map<string, FileFunctions>();
  const fileImportsByPath = new Map<string, FileImports>();
  const globalFunctionsByFqn = new Map<string, FunctionId>();
  const classFqnToFile = new Map<string, string>();

  // Pass 1: collect imports + functions per file.
  for (const f of parsedFiles) {
    const imports = collectImports(f);
    fileImportsByPath.set(f.filePath, imports);

    const functions = collectFunctionsForFile(f, imports, nodes, nodeIdToFunc);
    fileFunctionsByPath.set(f.filePath, functions);

    // Register top-level functions under their FQN (namespace + name).
    for (const [name, id] of functions.topLevelByName) {
      const fqn = imports.namespace ? `${imports.namespace}\\${name}` : name;
      // Don't overwrite earlier definitions; first-wins.
      if (!globalFunctionsByFqn.has(fqn)) globalFunctionsByFqn.set(fqn, id);
      // Also under the bare name as a fallback when no namespace is in play.
      if (!imports.namespace && !globalFunctionsByFqn.has(name)) {
        globalFunctionsByFqn.set(name, id);
      }
    }
    // Register classes by FQN.
    for (const [simple] of functions.classNodes) {
      const fqn = imports.namespace ? `${imports.namespace}\\${simple}` : simple;
      if (!classFqnToFile.has(fqn)) classFqnToFile.set(fqn, f.filePath);
    }
  }

  // Pass 2: emit edges.
  const edges: CallEdge[] = [];
  const fileStats: FileStats[] = [];
  for (const f of parsedFiles) {
    const stats = collectCallEdges(
      f,
      fileFunctionsByPath,
      fileImportsByPath,
      globalFunctionsByFqn,
      classFqnToFile,
      edges,
    );
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
    // v3 composer precision arc — emit the FIRST namespace segment of every
    // `use Vendor\Package\Class` declaration. Composer PURLs encode dep
    // namespace as the vendor (`symfony` of `symfony/console`), so the
    // maven-bidirectional-prefix path in depMatchesUsedTransitives matches
    // `symfony/*` deps when source code uses any `Symfony\...` namespace.
    usedDependencies: extractPhpUsedDependencies(fileImportsByPath, fileFunctionsByPath),
  };

  const filesContext = new Map<string, PhpFileContext>();
  for (const f of parsedFiles) {
    filesContext.set(f.filePath, {
      filePath: f.filePath,
      absolutePath: f.absolutePath,
      source: f.source,
      tree: f.tree,
      imports: fileImportsByPath.get(f.filePath) ?? {
        classAliases: new Map(),
        functionAliases: new Map(),
        constAliases: new Map(),
        namespace: '',
      },
      functions: fileFunctionsByPath.get(f.filePath) ?? {
        topLevelByName: new Map(),
        methods: new Map(),
        classParent: new Map(),
        classNodes: new Map(),
        fileId: makeFunctionId(f.filePath, 1, 1, '<file>'),
      },
    });
  }

  return { callgraph, files: filesContext, nodeIdToFunc, globalFunctionsByFqn, classFqnToFile };
}

function collectPhpFiles(absoluteRoot: string, maxFiles?: number): string[] {
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
      } else if (entry.isFile() && PHP_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
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

/** Strip a leading `\` from a fully-qualified PHP name (the global-namespace prefix). */
function stripLeadingBackslash(s: string): string {
  return s.startsWith('\\') ? s.slice(1) : s;
}

/** Last segment of a `\`-separated FQN. */
function lastSegment(fqn: string): string {
  const stripped = stripLeadingBackslash(fqn);
  const idx = stripped.lastIndexOf('\\');
  return idx >= 0 ? stripped.slice(idx + 1) : stripped;
}

/** Collect namespace + use-statement aliases for a file. */
function collectImports(f: FileTrees): FileImports {
  const classAliases = new Map<string, string>();
  const functionAliases = new Map<string, string>();
  const constAliases = new Map<string, string>();
  let namespace = '';

  const root = f.tree.rootNode;

  const visit = (node: Node): void => {
    if (node.type === 'namespace_definition') {
      // `namespace Foo\Bar;` or `namespace Foo\Bar { ... }`
      const nameNode = node.childForFieldName('name')
        ?? findChildOfType(node, 'namespace_name')
        ?? findChildOfType(node, 'qualified_name')
        ?? findChildOfType(node, 'name');
      if (nameNode) namespace = stripLeadingBackslash(textOf(nameNode, f.source));
    } else if (node.type === 'namespace_use_declaration') {
      // Determine the kind: function, const, or class (default).
      // tree-sitter-php exposes 'function' / 'const' as anonymous children when present.
      let kind: 'class' | 'function' | 'const' = 'class';
      for (let i = 0; i < node.childCount; i++) {
        const c = node.child(i);
        if (!c) continue;
        if (c.type === 'function') kind = 'function';
        else if (c.type === 'const') kind = 'const';
      }
      for (let i = 0; i < node.namedChildCount; i++) {
        const clause = node.namedChild(i);
        if (!clause) continue;
        if (clause.type !== 'namespace_use_clause') continue;
        // Each clause has a name (name / qualified_name) and optional alias.
        const names: Node[] = [];
        let aliasNode: Node | null = null;
        for (let j = 0; j < clause.namedChildCount; j++) {
          const cc = clause.namedChild(j);
          if (!cc) continue;
          if (cc.type === 'name' || cc.type === 'qualified_name' || cc.type === 'namespace_name') {
            names.push(cc);
          } else if (cc.type === 'namespace_aliasing_clause') {
            // alias is the inner name
            const aliasName = findChildOfType(cc, 'name') ?? cc.namedChild(0);
            if (aliasName) aliasNode = aliasName;
          }
        }
        if (names.length === 0) continue;
        const fqn = stripLeadingBackslash(textOf(names[0], f.source));
        if (!fqn) continue;
        // If the clause has a second `name` immediately (legacy parse shape with `as` exposed
        // as a sibling rather than a wrapping clause), treat the second name as alias.
        let alias: string;
        if (aliasNode) {
          alias = textOf(aliasNode, f.source);
        } else if (names.length > 1) {
          alias = textOf(names[names.length - 1], f.source);
        } else {
          alias = lastSegment(fqn);
        }
        if (!alias) continue;
        if (kind === 'function') functionAliases.set(alias, fqn);
        else if (kind === 'const') constAliases.set(alias, fqn);
        else classAliases.set(alias, fqn);
      }
    } else if (node.type === 'namespace_use_group_declaration' || node.type === 'namespace_group_use_clause') {
      // `use Foo\Bar\{Baz, Qux as Q};` — best-effort.
      // The grammar exposes a prefix (`namespace_name`/`qualified_name`) followed by group clauses.
      const prefix = findChildOfType(node, 'qualified_name')
        ?? findChildOfType(node, 'namespace_name')
        ?? findChildOfType(node, 'name');
      const prefixText = prefix ? stripLeadingBackslash(textOf(prefix, f.source)) : '';
      for (let i = 0; i < node.namedChildCount; i++) {
        const clause = node.namedChild(i);
        if (!clause) continue;
        if (clause.type !== 'namespace_use_clause') continue;
        const innerName = findChildOfType(clause, 'name') ?? findChildOfType(clause, 'qualified_name');
        if (!innerName) continue;
        const innerText = textOf(innerName, f.source);
        const fqn = prefixText ? `${prefixText}\\${stripLeadingBackslash(innerText)}` : stripLeadingBackslash(innerText);
        let alias = lastSegment(fqn);
        const aliasClause = findChildOfType(clause, 'namespace_aliasing_clause');
        if (aliasClause) {
          const aliasName = findChildOfType(aliasClause, 'name') ?? aliasClause.namedChild(0);
          if (aliasName) alias = textOf(aliasName, f.source);
        }
        if (alias) classAliases.set(alias, fqn);
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child);
    }
  };
  visit(root);

  return { classAliases, functionAliases, constAliases, namespace };
}

function findChildOfType(node: Node, type: string): Node | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && child.type === type) return child;
  }
  return null;
}

/** Walk to find every `function_definition` and `method_declaration` in the tree. */
function findFunctionLikeNodes(root: Node): Array<{ node: Node; isMethod: boolean }> {
  const out: Array<{ node: Node; isMethod: boolean }> = [];
  const visit = (node: Node): void => {
    if (node.type === 'function_definition') {
      out.push({ node, isMethod: false });
    } else if (node.type === 'method_declaration') {
      out.push({ node, isMethod: true });
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child);
    }
  };
  visit(root);
  return out;
}

function enclosingClassName(node: Node, source: string): string | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (
      cur.type === 'class_declaration' ||
      cur.type === 'trait_declaration' ||
      cur.type === 'interface_declaration' ||
      cur.type === 'enum_declaration'
    ) {
      const nameNode = cur.childForFieldName('name') ?? findChildOfType(cur, 'name');
      return textOf(nameNode, source) || null;
    }
  }
  return null;
}

function collectFunctionsForFile(
  f: FileTrees,
  _imports: FileImports,
  nodes: FunctionNode[],
  nodeIdToFunc: Map<FunctionId, Node>,
): FileFunctions {
  const root = f.tree.rootNode;
  const lastLine = root.endPosition.row + 1;

  // Synthetic per-file initializer for top-level statements.
  const fileId = makeFunctionId(f.filePath, 1, 1, '<file>');
  nodes.push({
    id: fileId,
    name: '<file>',
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
  nodeIdToFunc.set(fileId, root);

  const topLevelByName = new Map<string, FunctionId>();
  const methods = new Map<string, FunctionId>();
  const classParent = new Map<string, string>();
  const classNodes = new Map<string, Node>();

  // Collect class/trait/interface declarations + their parent (`extends`).
  const visit = (node: Node): void => {
    if (
      node.type === 'class_declaration' ||
      node.type === 'trait_declaration' ||
      node.type === 'interface_declaration' ||
      node.type === 'enum_declaration'
    ) {
      const nameNode = node.childForFieldName('name') ?? findChildOfType(node, 'name');
      const simple = textOf(nameNode, f.source);
      if (simple) {
        classNodes.set(simple, node);
        // Look for a `base_clause` / `class_base_clause` carrying `extends X`.
        const baseClause = findChildOfType(node, 'base_clause') ?? findChildOfType(node, 'class_base_clause');
        if (baseClause) {
          const baseName = findChildOfType(baseClause, 'name')
            ?? findChildOfType(baseClause, 'qualified_name');
          if (baseName) classParent.set(simple, lastSegment(textOf(baseName, f.source)));
        }
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child);
    }
  };
  visit(root);

  for (const { node, isMethod } of findFunctionLikeNodes(root)) {
    const nameNode = node.childForFieldName('name') ?? findChildOfType(node, 'name');
    const name = textOf(nameNode, f.source);
    if (!name) continue;
    const start = node.startPosition;
    const end = node.endPosition;
    const containingClass = isMethod ? enclosingClassName(node, f.source) : null;
    const kind: FunctionKind = isMethod ? 'method' : 'function_declaration';
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
    nodeIdToFunc.set(id, node);
    if (containingClass) {
      methods.set(`${containingClass}::${name}`, id);
      methods.set(`${containingClass}->${name}`, id);
    } else {
      topLevelByName.set(name, id);
    }
  }

  return { topLevelByName, methods, classParent, classNodes, fileId };
}

/**
 * Resolve a callee's textual root to a FunctionId. The shapes we recognize:
 *   - bare:                `foo`
 *   - static method:       `Foo::bar`, `\Ns\Foo::bar`, `parent::bar`, `self::bar`, `static::bar`
 *   - instance method:     `$obj->bar` or `$this->bar`
 *
 * `enclosingClass` is the simple class name of the function being analyzed.
 * `localTypes` maps `$varName` (without leading $) to a simple class name when
 * the type is statically inferable (parameter type hint or `$x = new C()`).
 */
export function resolvePhpCallee(args: {
  calleeText: string;
  filePath: string;
  fileFunctions: Map<string, FileFunctions>;
  fileImports: Map<string, FileImports>;
  globalFunctionsByFqn: Map<string, FunctionId>;
  classFqnToFile: Map<string, string>;
  enclosingClass: string | null;
  localTypes: Map<string, string>;
}): { calleeId: FunctionId | null; kind: CallEdgeKind } {
  const {
    calleeText,
    filePath,
    fileFunctions,
    fileImports,
    globalFunctionsByFqn,
    classFqnToFile,
    enclosingClass,
    localTypes,
  } = args;

  const ff = fileFunctions.get(filePath);
  const imp = fileImports.get(filePath);
  if (!ff || !imp) return { calleeId: null, kind: 'unresolved' };

  const text = calleeText.trim();
  if (!text) return { calleeId: null, kind: 'unresolved' };

  // ---- $this->method ---------------------------------------------------------
  if (text.startsWith('$this->')) {
    const methodName = text.slice('$this->'.length);
    if (enclosingClass) {
      const id = ff.methods.get(`${enclosingClass}->${methodName}`)
        ?? ff.methods.get(`${enclosingClass}::${methodName}`);
      if (id) return { calleeId: id, kind: 'static' };
      // Walk parent class (one hop, same file).
      const parent = ff.classParent.get(enclosingClass);
      if (parent) {
        const pid = ff.methods.get(`${parent}->${methodName}`) ?? ff.methods.get(`${parent}::${methodName}`);
        if (pid) return { calleeId: pid, kind: 'static' };
      }
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // ---- parent::method / self::method / static::method ----------------------
  const scopedMatch = text.match(/^(parent|self|static)::(.+)$/);
  if (scopedMatch) {
    const [, scope, methodName] = scopedMatch;
    if (scope === 'parent' && enclosingClass) {
      const parent = ff.classParent.get(enclosingClass);
      if (parent) {
        const pid = ff.methods.get(`${parent}->${methodName}`) ?? ff.methods.get(`${parent}::${methodName}`);
        if (pid) return { calleeId: pid, kind: 'static' };
        // Cross-file: parent might live elsewhere; resolve via classAliases
        const fqn = imp.classAliases.get(parent);
        if (fqn) {
          const otherFile = classFqnToFile.get(fqn);
          if (otherFile) {
            const otherFf = fileFunctions.get(otherFile);
            const id = otherFf?.methods.get(`${parent}->${methodName}`)
              ?? otherFf?.methods.get(`${parent}::${methodName}`);
            if (id) return { calleeId: id, kind: 'static' };
          }
        }
      }
    } else if ((scope === 'self' || scope === 'static') && enclosingClass) {
      const id = ff.methods.get(`${enclosingClass}::${methodName}`)
        ?? ff.methods.get(`${enclosingClass}->${methodName}`);
      if (id) return { calleeId: id, kind: 'static' };
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // ---- Foo::method (static call) -------------------------------------------
  const staticMatch = text.match(/^([\\\w]+)::(\w+)$/);
  if (staticMatch) {
    const [, className, methodName] = staticMatch;
    const simple = lastSegment(className);
    // Same-file class?
    const localId = ff.methods.get(`${simple}::${methodName}`) ?? ff.methods.get(`${simple}->${methodName}`);
    if (localId) return { calleeId: localId, kind: 'static' };
    // Cross-file via aliases or FQN?
    const fqn = imp.classAliases.get(simple) ?? stripLeadingBackslash(className);
    const otherFile = classFqnToFile.get(fqn);
    if (otherFile) {
      const otherFf = fileFunctions.get(otherFile);
      const id = otherFf?.methods.get(`${simple}::${methodName}`)
        ?? otherFf?.methods.get(`${simple}->${methodName}`);
      if (id) return { calleeId: id, kind: 'static' };
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // ---- $var->method --------------------------------------------------------
  const instMatch = text.match(/^\$(\w+)->(\w+)$/);
  if (instMatch) {
    const [, varName, methodName] = instMatch;
    const typeSimple = localTypes.get(varName);
    if (typeSimple) {
      // Same-file?
      const id = ff.methods.get(`${typeSimple}->${methodName}`) ?? ff.methods.get(`${typeSimple}::${methodName}`);
      if (id) return { calleeId: id, kind: 'static' };
      // Cross-file?
      const fqn = imp.classAliases.get(typeSimple);
      if (fqn) {
        const otherFile = classFqnToFile.get(fqn);
        if (otherFile) {
          const otherFf = fileFunctions.get(otherFile);
          const otherId = otherFf?.methods.get(`${typeSimple}->${methodName}`)
            ?? otherFf?.methods.get(`${typeSimple}::${methodName}`);
          if (otherId) return { calleeId: otherId, kind: 'static' };
        }
      }
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // ---- bare function call: foo or \Ns\foo ---------------------------------
  // (No `::` and no `->` — treat entire text as a function name path.)
  if (!text.includes('::') && !text.includes('->') && !text.startsWith('$')) {
    const stripped = stripLeadingBackslash(text);
    // file-local
    const localId = ff.topLevelByName.get(stripped);
    if (localId) return { calleeId: localId, kind: 'static' };
    // function-use alias
    const aliased = imp.functionAliases.get(stripped);
    if (aliased) {
      const id = globalFunctionsByFqn.get(aliased);
      if (id) return { calleeId: id, kind: 'static' };
    }
    // global FQN: try as-is, then with the file's namespace prepended.
    const direct = globalFunctionsByFqn.get(stripped);
    if (direct) return { calleeId: direct, kind: 'static' };
    if (imp.namespace) {
      const withNs = `${imp.namespace}\\${stripped}`;
      const idNs = globalFunctionsByFqn.get(withNs);
      if (idNs) return { calleeId: idNs, kind: 'static' };
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  return { calleeId: null, kind: 'unresolved' };
}

interface CollectCallEdgesContext {
  filePath: string;
  source: string;
  enclosingFnId: FunctionId;
  enclosingClass: string | null;
  /** $name → simple class name (parameter type hints + `new C()`). */
  localTypes: Map<string, string>;
}

function collectCallEdges(
  f: FileTrees,
  fileFunctions: Map<string, FileFunctions>,
  fileImports: Map<string, FileImports>,
  globalFunctionsByFqn: Map<string, FunctionId>,
  classFqnToFile: Map<string, string>,
  edges: CallEdge[],
): FileStats {
  let callExpressionCount = 0;
  let resolvedCallCount = 0;

  // Helper to extract a call-expression's callee text (the part before the args).
  const calleeTextOf = (callNode: Node): string => {
    // The grammar exposes the callee as the first named child (function_call_expression
    // has `function` field; member_call_expression has `object` + `name` field; same for scoped).
    if (callNode.type === 'function_call_expression') {
      const fn = callNode.childForFieldName('function');
      if (fn) return textOf(fn, f.source);
    } else if (callNode.type === 'member_call_expression') {
      const obj = callNode.childForFieldName('object');
      const name = callNode.childForFieldName('name');
      if (obj && name) return `${textOf(obj, f.source)}->${textOf(name, f.source)}`;
    } else if (callNode.type === 'scoped_call_expression') {
      const scope = callNode.childForFieldName('scope');
      const name = callNode.childForFieldName('name');
      if (scope && name) return `${textOf(scope, f.source)}::${textOf(name, f.source)}`;
    } else if (callNode.type === 'object_creation_expression') {
      // `new ClassName(...)` — emit edge to the constructor of ClassName as `new ClassName`.
      const typeNode = callNode.namedChild(0);
      if (typeNode) return `new ${textOf(typeNode, f.source)}`;
    }
    // Fallback: full text minus arguments.
    const t = textOf(callNode, f.source);
    const idx = t.indexOf('(');
    return idx >= 0 ? t.slice(0, idx) : t;
  };

  const argCountOf = (callNode: Node): number => {
    const argList = callNode.childForFieldName('arguments');
    if (!argList) return 0;
    let n = 0;
    for (let i = 0; i < argList.namedChildCount; i++) {
      const c = argList.namedChild(i);
      if (c && c.type !== 'comment') n++;
    }
    return n;
  };

  // Collect parameter type hints from a method/function body to seed localTypes.
  const seedTypesFromParams = (funcNode: Node, types: Map<string, string>): void => {
    const params = funcNode.childForFieldName('parameters');
    if (!params) return;
    for (let i = 0; i < params.namedChildCount; i++) {
      const p = params.namedChild(i);
      if (!p) continue;
      if (p.type !== 'simple_parameter' && p.type !== 'variadic_parameter' && p.type !== 'property_promotion_parameter') continue;
      const typeNode = p.childForFieldName('type');
      const nameNode = p.childForFieldName('name');
      if (typeNode && nameNode && nameNode.type === 'variable_name') {
        const typeText = textOf(typeNode, f.source);
        // Strip nullable `?` and union types — take the first name.
        const simple = lastSegment(typeText.replace(/^\?/, '').split('|')[0].trim());
        if (simple && /^[A-Za-z_][\w\\]*$/.test(simple)) {
          const varName = textOf(nameNode, f.source).replace(/^\$/, '');
          if (varName) types.set(varName, simple);
        }
      }
    }
  };

  const visit = (
    node: Node,
    ctx: CollectCallEdgesContext,
  ): void => {
    let nextCtx = ctx;

    if (node.type === 'function_definition') {
      const nameNode = node.childForFieldName('name');
      const name = textOf(nameNode, f.source);
      if (name) {
        const start = node.startPosition;
        const id = makeFunctionId(f.filePath, start.row + 1, start.column + 1, name);
        const types = new Map<string, string>();
        seedTypesFromParams(node, types);
        nextCtx = {
          ...ctx,
          enclosingFnId: id,
          enclosingClass: null,
          localTypes: types,
        };
      }
    } else if (node.type === 'method_declaration') {
      const nameNode = node.childForFieldName('name');
      const name = textOf(nameNode, f.source);
      if (name) {
        const start = node.startPosition;
        const id = makeFunctionId(f.filePath, start.row + 1, start.column + 1, name);
        const cls = enclosingClassName(node, f.source);
        const types = new Map<string, string>();
        seedTypesFromParams(node, types);
        nextCtx = {
          ...ctx,
          enclosingFnId: id,
          enclosingClass: cls,
          localTypes: types,
        };
      }
    } else if (node.type === 'assignment_expression') {
      // Track `$x = new C(...)` to seed localTypes for resolution.
      const left = node.childForFieldName('left');
      const right = node.namedChild(1);
      if (left?.type === 'variable_name' && right?.type === 'object_creation_expression') {
        const typeNode = right.namedChild(0);
        if (typeNode && (typeNode.type === 'name' || typeNode.type === 'qualified_name')) {
          const varName = textOf(left, f.source).replace(/^\$/, '');
          if (varName) ctx.localTypes.set(varName, lastSegment(textOf(typeNode, f.source)));
        }
      }
    } else if (
      node.type === 'function_call_expression' ||
      node.type === 'member_call_expression' ||
      node.type === 'scoped_call_expression' ||
      node.type === 'object_creation_expression'
    ) {
      callExpressionCount++;
      const calleeText = calleeTextOf(node);
      const argumentCount = argCountOf(node);
      const { calleeId, kind } = resolvePhpCallee({
        calleeText,
        filePath: f.filePath,
        fileFunctions,
        fileImports,
        globalFunctionsByFqn,
        classFqnToFile,
        enclosingClass: ctx.enclosingClass,
        localTypes: ctx.localTypes,
      });
      if (calleeId) resolvedCallCount++;
      const start = node.startPosition;
      edges.push({
        callerId: ctx.enclosingFnId,
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
      if (child) visit(child, nextCtx);
    }
  };

  const ff = fileFunctions.get(f.filePath);
  const fileId = ff?.fileId ?? makeFunctionId(f.filePath, 1, 1, '<file>');
  visit(f.tree.rootNode, {
    filePath: f.filePath,
    source: f.source,
    enclosingFnId: fileId,
    enclosingClass: null,
    localTypes: new Map(),
  });

  return {
    filePath: f.filePath,
    isFullyTyped: false,
    callExpressionCount,
    resolvedCallCount,
  };
}

/**
 * Walk every `use Vendor\Package\Class;` and emit the FIRST namespace
 * segment lowercased. Composer PURLs encode dep `namespace` as the vendor
 * (`symfony` of `symfony/console`); the maven-bidirectional-prefix path in
 * depMatchesUsedTransitives then matches any `symfony/*` PDV.
 *
 * Workspace-local namespaces (anything that resolves to a file in this
 * repo's classFqnToFile map) are filtered. Common single-word root names
 * like `App`, `Tests`, `Database` (Laravel skeleton conventions) get
 * blacklisted explicitly — they ARE workspace-local but show up in
 * classFqnToFile via the PSR-4 root prefix.
 */
export function extractPhpUsedDependencies(
  fileImportsByPath: Map<string, FileImports>,
  _fileFunctionsByPath: Map<string, FileFunctions>,
): Set<string> {
  const out = new Set<string>();
  // PHP top-level roots that almost always denote intra-project namespaces.
  // Laravel/Symfony skeletons stamp these in by default.
  const WORKSPACE_ROOTS = new Set([
    'app',
    'tests',
    'test',
    'database',
    'storage',
    'config',
    'public',
    'resources',
    'bootstrap',
  ]);

  for (const imports of fileImportsByPath.values()) {
    // Collect ALL maps (class, function, const) since `use` declarations
    // populate each of them depending on the import kind. Vendor namespace
    // is in the FQN regardless.
    const allFqns: string[] = [
      ...imports.classAliases.values(),
      ...imports.functionAliases.values(),
      ...imports.constAliases.values(),
    ];
    for (const fqn of allFqns) {
      const trimmed = fqn.replace(/^\\+/, '');
      const root = trimmed.split('\\')[0];
      if (!root) continue;
      const lower = root.toLowerCase();
      if (WORKSPACE_ROOTS.has(lower)) continue;
      out.add(lower);
    }
  }
  return out;
}
