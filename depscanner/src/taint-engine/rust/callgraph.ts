/**
 * Whole-program callgraph for a Rust workspace, built on web-tree-sitter
 * (Rust WASM grammar). Mirrors the shape returned by the TS / Python / Go
 * callgraphs (`buildCallgraph`) so the same downstream propagator-style
 * worklist can consume it.
 *
 * Resolution strategy (best-effort, no full type system):
 *   - Walk every `*.rs` file under rootDir, collect `function_item` and
 *     methods inside `impl_item` blocks. Emit a synthetic `<module>` node
 *     per file for top-level code (statics, `mod` declarations, macro
 *     invocations).
 *   - Track imports per file (`use foo::bar`, `use foo::{a, b}`,
 *     `use foo::bar as baz`) and `mod foo;` declarations to map dotted
 *     module names to file paths. Best-effort: `mod foo` in `src/lib.rs`
 *     resolves to `src/foo.rs` or `src/foo/mod.rs`.
 *   - For each call expression, attempt to map the callee's textual root
 *     (`bar()`, `mod::bar()`, `Self::method`, `self.method`, `obj.method`)
 *     to a function we've cataloged:
 *       - bare `foo(...)` → file-local fn named `foo`, OR a use-imported
 *         leaf where we know the originating file.
 *       - `mod::foo(...)` → resolve `mod` via the use-alias map to a
 *         workspace file, then look up `foo` as a top-level fn there.
 *       - `Self::method(...)` / `self.method(...)` → method on the
 *         enclosing impl block in the same file.
 *       - `obj.method(...)` → best-effort by matching the method name on
 *         any impl block in the same file.
 *     Anything else gets emitted as `unresolved` with the textual callee.
 *
 * Known v1 limitations (documented for follow-up):
 *   - No trait dispatch (the concrete type isn't statically obvious; trait
 *     methods like `Iterator::next` are unresolved).
 *   - No generic resolution — `sqlx::query::<_>(...)` is matched textually
 *     by the prefix only (the turbofish is part of the callee text).
 *   - Method receivers aren't typed; `obj.method()` resolves to any impl
 *     block in the file with a matching method name (over-approximated).
 *   - Lifetimes / borrows / `&` / `*` / `mut` are stripped at the IR layer.
 *   - Macro expansion is not modeled: macros (`format!`, `println!`,
 *     `vec!`, `log::info!`) are emitted as call-shape steps where the
 *     calleeText is `<name>!`.
 *   - `use foo::bar::*;` glob imports are partially handled (we record
 *     `foo::bar` as a known module; individual symbols aren't enumerated).
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

export interface BuildRustCallgraphOptions {
  rootDir: string;
  /** Optional cap on number of files (test perf). */
  maxFiles?: number;
  onWarn?: (msg: string) => void;
}

/** Directories to skip during traversal. */
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'target',
  'dist',
  'build',
  '.cache',
  '.deptex',
]);

const RS_EXTENSION = '.rs';

interface FileTrees {
  filePath: string;
  absolutePath: string;
  source: string;
  tree: Tree;
}

interface FileImports {
  /**
   * For `use mod_a::mod_b::Item as Alias`, alias → resolved file path of
   * mod_a::mod_b (best effort via the workspace module index).
   */
  moduleSourceForLocal: Map<string, string>;
  /**
   * For `use mod_a::mod_b::Item`, leafName → resolved (filePath, importedName)
   * so a bare `Item(...)` call can be resolved to a top-level fn in mod_a/mod_b.
   */
  fromImportName: Map<string, { filePath: string; importedName: string }>;
}

interface FileFunctions {
  /** name → FunctionId for top-level (free) functions in the file. */
  topLevel: Map<string, FunctionId>;
  /** "Type.methodName" → FunctionId for impl-block methods. */
  methods: Map<string, FunctionId>;
  /** methodName → set of FunctionIds (for `obj.method()` over-approximation). */
  methodsByName: Map<string, FunctionId[]>;
  /** synthetic module initializer FunctionId. */
  moduleId: FunctionId;
}

/**
 * Public API: build the Callgraph for a Rust workspace.
 */
export async function buildRustCallgraph(
  rootDirOrOpts: string | BuildRustCallgraphOptions,
): Promise<Callgraph> {
  const ctx = await buildRustCallgraphContext(rootDirOrOpts);
  return ctx.callgraph;
}

/** Per-file context needed by the IR lowerer + propagator driver. */
export interface RustFileContext {
  filePath: string;
  absolutePath: string;
  source: string;
  tree: Tree;
  imports: FileImports;
  functions: FileFunctions;
}

export interface RustCallgraphContext {
  callgraph: Callgraph;
  files: Map<string, RustFileContext>;
  /** functionId → AST node (function_item, or root for `<module>`) */
  nodeIdToFunc: Map<FunctionId, Node>;
}

export async function buildRustCallgraphContext(
  rootDirOrOpts: string | BuildRustCallgraphOptions,
): Promise<RustCallgraphContext> {
  const opts: BuildRustCallgraphOptions =
    typeof rootDirOrOpts === 'string' ? { rootDir: rootDirOrOpts } : rootDirOrOpts;
  const start = Date.now();
  const absoluteRoot = path.resolve(opts.rootDir);

  const files = collectRustFiles(absoluteRoot, opts.maxFiles);
  const language: Language = await loadLanguage('tree-sitter-rust.wasm');

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

  // Pass 1: collect functions per file.
  for (const f of parsedFiles) {
    const ff = collectFunctionsForFile(f, nodes, nodeIdToFunc);
    fileFunctions.set(f.filePath, ff);
  }

  // Pass 2: build the workspace module index from `mod` declarations + file
  // layout, then resolve imports against it.
  const moduleIndex = buildModuleIndex(parsedFiles);
  const fileImports = new Map<string, FileImports>();
  for (const f of parsedFiles) {
    fileImports.set(f.filePath, collectImports(f, moduleIndex, fileFunctions));
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

  const filesContext = new Map<string, RustFileContext>();
  for (const f of parsedFiles) {
    filesContext.set(f.filePath, {
      filePath: f.filePath,
      absolutePath: f.absolutePath,
      source: f.source,
      tree: f.tree,
      imports:
        fileImports.get(f.filePath) ?? {
          moduleSourceForLocal: new Map(),
          fromImportName: new Map(),
        },
      functions:
        fileFunctions.get(f.filePath) ?? {
          topLevel: new Map(),
          methods: new Map(),
          methodsByName: new Map(),
          moduleId: makeFunctionId(f.filePath, 1, 1, '<module>'),
        },
    });
  }

  return { callgraph, files: filesContext, nodeIdToFunc };
}

function collectRustFiles(absoluteRoot: string, maxFiles?: number): string[] {
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
      } else if (
        entry.isFile() &&
        path.extname(entry.name).toLowerCase() === RS_EXTENSION
      ) {
        out.push(full);
      }
    }
  }
  return out;
}

function toRelativePosix(absolute: string, absoluteRoot: string): string {
  return path.relative(absoluteRoot, absolute).split(path.sep).join('/');
}

export function makeFunctionId(
  filePath: string,
  line: number,
  column: number,
  name: string,
): FunctionId {
  return `${filePath}:${line}:${column}:${name}`;
}

function textOf(node: Node | null | undefined, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

/**
 * Build a mapping from Rust dotted module name (e.g. `crate::util::helpers`,
 * or just `util::helpers`) to the file path where that module's code lives.
 *
 * Strategy:
 *   - Each `.rs` file maps to a dotted module name based on its path:
 *       `src/lib.rs`         → `crate` (and `<root>`)
 *       `src/main.rs`        → `crate` (and `<root>`)
 *       `src/foo.rs`         → `foo` and `crate::foo`
 *       `src/foo/mod.rs`     → `foo` and `crate::foo`
 *       `src/foo/bar.rs`     → `foo::bar` and `crate::foo::bar`
 *   - Files outside an `src/` tree (e.g. fixture files) map by their
 *     directory layout directly: `actix-vuln/main.rs` → `crate` and the
 *     bare filename `main`.
 */
function buildModuleIndex(parsed: FileTrees[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const f of parsed) {
    const noExt = f.filePath.replace(/\.rs$/, '');
    const parts = noExt.split('/');

    // Find a `src` segment as the crate boundary, else assume the whole path
    // is the module name.
    const srcIdx = parts.lastIndexOf('src');
    let modParts: string[];
    if (srcIdx >= 0) {
      modParts = parts.slice(srcIdx + 1);
    } else {
      modParts = [parts[parts.length - 1]];
    }

    // Drop trailing `/mod` since `foo/mod.rs` IS module `foo`.
    if (modParts[modParts.length - 1] === 'mod') {
      modParts = modParts.slice(0, -1);
    }

    if (modParts.length === 0) continue;

    // Crate-root files: lib.rs / main.rs.
    if (modParts.length === 1 && (modParts[0] === 'lib' || modParts[0] === 'main')) {
      out.set('crate', f.filePath);
      out.set('<root>', f.filePath);
      continue;
    }

    const dotted = modParts.join('::');
    out.set(dotted, f.filePath);
    out.set(`crate::${dotted}`, f.filePath);
    // Also expose the leaf alone (helps `use foo;` resolve when there's
    // exactly one `foo.rs` in the workspace).
    const leaf = modParts[modParts.length - 1];
    if (!out.has(leaf)) out.set(leaf, f.filePath);
  }
  return out;
}

/** Collect `function_item`s and impl-block methods for a single file. */
function collectFunctionsForFile(
  f: FileTrees,
  nodes: FunctionNode[],
  nodeIdToFunc: Map<FunctionId, Node>,
): FileFunctions {
  const root = f.tree.rootNode;
  const lastLine = root.endPosition.row + 1;

  // Synthetic module initializer.
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
  const methodsByName = new Map<string, FunctionId[]>();

  const visit = (node: Node, enclosingType: string | null): void => {
    let nextEnclosing = enclosingType;
    if (node.type === 'impl_item') {
      // `impl Foo { ... }` or `impl Trait for Foo { ... }` — extract the
      // type the impl is for.
      const typeNode = node.childForFieldName('type');
      const t = typeNode ? textOf(typeNode, f.source) : null;
      nextEnclosing = t ?? nextEnclosing;
    }

    if (node.type === 'function_item') {
      const nameNode = node.childForFieldName('name');
      const name = textOf(nameNode, f.source);
      if (name) {
        const start = node.startPosition;
        const end = node.endPosition;
        const containingClass = enclosingType;
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
        nodeIdToFunc.set(id, node);
        if (containingClass) {
          methods.set(`${containingClass}.${name}`, id);
          const arr = methodsByName.get(name) ?? [];
          arr.push(id);
          methodsByName.set(name, arr);
        } else {
          topLevel.set(name, id);
        }
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child, nextEnclosing);
    }
  };

  visit(root, null);

  return { topLevel, methods, methodsByName, moduleId };
}

/**
 * Collect `use` declarations and `mod foo;` declarations into a per-file
 * import map.
 */
function collectImports(
  f: FileTrees,
  moduleIndex: Map<string, string>,
  fileFunctions: Map<string, FileFunctions>,
): FileImports {
  const moduleSourceForLocal = new Map<string, string>();
  const fromImportName = new Map<string, { filePath: string; importedName: string }>();

  // Resolve a `use` chain — `mod_a::mod_b::Item` — into either an alias for
  // the *module* (when the leaf is itself a module file) or an import of
  // a leaf SYMBOL (top-level fn) from the module file.
  const tryRegister = (localName: string, segments: string[]): void => {
    if (segments.length === 0) return;
    // Try resolving the full path as a module first.
    const fullDotted = segments.join('::');
    const fullFile = resolveModule(fullDotted, moduleIndex);
    if (fullFile) {
      moduleSourceForLocal.set(localName, fullFile);
      return;
    }
    // Else: leaf is a symbol, parent is the module.
    if (segments.length >= 2) {
      const parentDotted = segments.slice(0, -1).join('::');
      const leaf = segments[segments.length - 1];
      const parentFile = resolveModule(parentDotted, moduleIndex);
      if (parentFile) {
        // Validate the symbol exists in that file (best-effort).
        const ff = fileFunctions.get(parentFile);
        if (ff && ff.topLevel.has(leaf)) {
          fromImportName.set(localName, { filePath: parentFile, importedName: leaf });
          return;
        }
        // Even if we can't see the symbol, register the parent as a module
        // alias so `localName(...)` could still resolve later.
        moduleSourceForLocal.set(localName, parentFile);
        // And remember the symbol intent for fallback.
        fromImportName.set(localName, { filePath: parentFile, importedName: leaf });
      }
    } else {
      // Single segment, but not a known module — give up.
    }
  };

  // Walk a `use` arg recursively (identifier | scoped_identifier |
  // scoped_use_list | use_list | use_as_clause | use_wildcard).
  const handleUse = (node: Node, prefix: string[]): void => {
    if (node.type === 'identifier') {
      const name = textOf(node, f.source);
      const segments = [...prefix, name];
      tryRegister(name, segments);
      return;
    }
    if (node.type === 'scoped_identifier') {
      // Collect the dotted path from the scoped_identifier.
      const segments = collectScopedSegments(node, f.source);
      const local = segments[segments.length - 1];
      tryRegister(local, [...prefix, ...segments]);
      return;
    }
    if (node.type === 'scoped_use_list') {
      // path::{ list }
      const pathField = node.childForFieldName('path') ?? node.namedChild(0);
      const listField = node.childForFieldName('list') ?? node.namedChild(1);
      const pathSegments = pathField ? collectScopedSegments(pathField, f.source) : [];
      const newPrefix = [...prefix, ...pathSegments];
      if (listField && listField.type === 'use_list') {
        for (let i = 0; i < listField.namedChildCount; i++) {
          const item = listField.namedChild(i);
          if (item) handleUse(item, newPrefix);
        }
      }
      return;
    }
    if (node.type === 'use_list') {
      for (let i = 0; i < node.namedChildCount; i++) {
        const item = node.namedChild(i);
        if (item) handleUse(item, prefix);
      }
      return;
    }
    if (node.type === 'use_as_clause') {
      const pathNode = node.childForFieldName('path');
      const aliasNode = node.childForFieldName('alias');
      if (!pathNode || !aliasNode) return;
      const segments = collectScopedSegments(pathNode, f.source);
      const alias = textOf(aliasNode, f.source);
      tryRegister(alias, [...prefix, ...segments]);
      return;
    }
    if (node.type === 'use_wildcard') {
      // `use mod::*;` — register the module alias under its leaf name so
      // `leaf::sym(...)` still resolves; we don't enumerate symbols.
      const inner = node.namedChild(0);
      if (inner) {
        const segments = collectScopedSegments(inner, f.source);
        const all = [...prefix, ...segments];
        if (all.length > 0) {
          const leaf = all[all.length - 1];
          tryRegister(leaf, all);
        }
      }
      return;
    }
  };

  // `mod foo;` — declares a child module. Resolve to a workspace file.
  const handleModDecl = (node: Node): void => {
    const nameNode = node.childForFieldName('name');
    if (!nameNode) return;
    const name = textOf(nameNode, f.source);
    if (!name) return;
    // If the mod_item has a body, it's an inline module; nothing to resolve.
    const body = node.childForFieldName('body');
    if (body) return;
    const file = resolveModule(name, moduleIndex);
    if (file) moduleSourceForLocal.set(name, file);
  };

  const visit = (node: Node): void => {
    if (node.type === 'use_declaration') {
      const arg = node.namedChild(0);
      if (arg) handleUse(arg, []);
    } else if (node.type === 'mod_item') {
      handleModDecl(node);
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i);
      if (c) visit(c);
    }
  };
  visit(f.tree.rootNode);

  return { moduleSourceForLocal, fromImportName };
}

function collectScopedSegments(node: Node, source: string): string[] {
  // Recursively unwrap `scoped_identifier { path: <inner>, name: <ident> }`.
  if (node.type === 'identifier') return [textOf(node, source)];
  if (node.type === 'scoped_identifier') {
    const pathField = node.childForFieldName('path');
    const nameField = node.childForFieldName('name');
    const head = pathField ? collectScopedSegments(pathField, source) : [];
    const tail = nameField ? textOf(nameField, source) : '';
    return tail ? [...head, tail] : head;
  }
  // scoped_type_identifier or super-like: fall back to text and split.
  const txt = textOf(node, source);
  return txt ? txt.split('::') : [];
}

function resolveModule(dotted: string, moduleIndex: Map<string, string>): string | null {
  if (moduleIndex.has(dotted)) return moduleIndex.get(dotted)!;
  // Strip a leading `crate::` and retry.
  if (dotted.startsWith('crate::')) {
    const stripped = dotted.slice('crate::'.length);
    if (moduleIndex.has(stripped)) return moduleIndex.get(stripped)!;
  }
  // Walk up the chain.
  const parts = dotted.split('::');
  while (parts.length > 0) {
    parts.pop();
    const sub = parts.join('::');
    if (sub && moduleIndex.has(sub)) return moduleIndex.get(sub)!;
  }
  return null;
}

/**
 * Find the FunctionId that a call-site's callee text resolves to in the file
 * f. Returns null if unresolved.
 *
 * Callee shapes recognised:
 *   - `bar(...)`            → file-local fn or use-imported leaf
 *   - `mod::bar(...)`       → use-aliased module's top-level fn
 *   - `Self::method(...)`   → method on enclosing impl-block type
 *   - `self.method(...)`    → method on enclosing impl-block type
 *   - `obj.method(...)`     → file-local impl method (over-approximated by name)
 */
export function resolveRustCallee(
  calleeText: string,
  filePath: string,
  fileFunctions: Map<string, FileFunctions>,
  fileImports: Map<string, FileImports>,
  enclosingType: string | null,
): { calleeId: FunctionId | null; kind: CallEdgeKind } {
  const ff = fileFunctions.get(filePath);
  const imp = fileImports.get(filePath);
  if (!ff) return { calleeId: null, kind: 'unresolved' };

  // Strip turbofish `::<T, U>` and trailing `(...)`/`![...]` for resolution.
  const cleanText = stripTurbofish(calleeText);

  // Method call on a value: `receiver.method`.
  if (cleanText.includes('.') && !cleanText.includes('::')) {
    const segs = cleanText.split('.');
    if (segs.length >= 2) {
      const last = segs[segs.length - 1];
      // self.method / Self::method handled in `::` branch.
      // Fall back: file-local method by name (over-approximate).
      const candidates = ff.methodsByName.get(last);
      if (candidates && candidates.length === 1) {
        return { calleeId: candidates[0], kind: 'static' };
      }
      if (candidates && candidates.length > 1) {
        // Pick the first; mark virtual since we can't pinpoint the type.
        return { calleeId: candidates[0], kind: 'virtual' };
      }
      return { calleeId: null, kind: 'unresolved' };
    }
  }

  const dotted = cleanText.split('::');

  // bare `name(...)`
  if (dotted.length === 1) {
    const name = dotted[0];
    // file-local free function?
    const local = ff.topLevel.get(name);
    if (local) return { calleeId: local, kind: 'static' };
    // use-imported leaf?
    if (imp) {
      const fromImp = imp.fromImportName.get(name);
      if (fromImp) {
        const targetFf = fileFunctions.get(fromImp.filePath);
        if (targetFf) {
          const fid = targetFf.topLevel.get(fromImp.importedName);
          if (fid) return { calleeId: fid, kind: 'static' };
        }
      }
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // `Self::method(...)` or `self.method(...)` — enclosing impl-block.
  if (dotted.length === 2 && (dotted[0] === 'Self' || dotted[0] === 'self')) {
    if (enclosingType) {
      const m = ff.methods.get(`${enclosingType}.${dotted[1]}`);
      if (m) return { calleeId: m, kind: 'static' };
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  // `mod::name(...)` — use-aliased.
  if (dotted.length >= 2) {
    if (imp) {
      const targetFile = imp.moduleSourceForLocal.get(dotted[0]);
      if (targetFile) {
        const targetFf = fileFunctions.get(targetFile);
        if (targetFf) {
          // mod::name(...)
          if (dotted.length === 2) {
            const fid = targetFf.topLevel.get(dotted[1]);
            if (fid) return { calleeId: fid, kind: 'static' };
            // Method-on-Type? `mod::Type::method`
          }
          // mod::Type::method(...)
          if (dotted.length === 3) {
            const fid = targetFf.methods.get(`${dotted[1]}.${dotted[2]}`);
            if (fid) return { calleeId: fid, kind: 'static' };
          }
        }
      }
      // Or: dotted[0] is a leaf the file imported and `dotted[0]::name` is
      // the use-aliased Type's method.
      const leafImp = imp.fromImportName.get(dotted[0]);
      if (leafImp) {
        const targetFf = fileFunctions.get(leafImp.filePath);
        if (targetFf) {
          if (dotted.length === 2) {
            const fid = targetFf.methods.get(`${leafImp.importedName}.${dotted[1]}`);
            if (fid) return { calleeId: fid, kind: 'static' };
          }
        }
      }
    }
    return { calleeId: null, kind: 'unresolved' };
  }

  return { calleeId: null, kind: 'unresolved' };
}

function stripTurbofish(text: string): string {
  // Remove `::<...>` chunks (handle a single level of nesting).
  let out = text;
  for (let pass = 0; pass < 4; pass++) {
    const idx = out.indexOf('::<');
    if (idx < 0) break;
    let depth = 0;
    let end = -1;
    for (let i = idx + 2; i < out.length; i++) {
      const ch = out[i];
      if (ch === '<') depth++;
      else if (ch === '>') {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end < 0) break;
    out = out.slice(0, idx) + out.slice(end + 1);
  }
  return out;
}

function collectCallEdges(
  f: FileTrees,
  fileFunctions: Map<string, FileFunctions>,
  fileImports: Map<string, FileImports>,
  edges: CallEdge[],
): FileStats {
  let callExpressionCount = 0;
  let resolvedCallCount = 0;

  const visit = (node: Node, enclosingFnId: FunctionId, enclosingType: string | null): void => {
    let nextEnclosingFnId = enclosingFnId;
    let nextEnclosingType = enclosingType;

    if (node.type === 'function_item') {
      const nameNode = node.childForFieldName('name');
      const name = textOf(nameNode, f.source);
      if (name) {
        const start = node.startPosition;
        const id = makeFunctionId(f.filePath, start.row + 1, start.column + 1, name);
        nextEnclosingFnId = id;
      }
    } else if (node.type === 'impl_item') {
      const typeNode = node.childForFieldName('type');
      if (typeNode) {
        const t = textOf(typeNode, f.source);
        if (t) nextEnclosingType = t;
      }
    } else if (node.type === 'call_expression' || node.type === 'macro_invocation') {
      callExpressionCount++;
      const isMacro = node.type === 'macro_invocation';
      const fnNode = isMacro
        ? node.childForFieldName('macro')
        : node.childForFieldName('function');
      let calleeText = textOf(fnNode, f.source);
      if (isMacro && calleeText) calleeText = `${calleeText}!`;
      const argList = isMacro
        ? node.childForFieldName('token_tree')
        : node.childForFieldName('arguments');
      let argumentCount = 0;
      if (argList) {
        for (let i = 0; i < argList.namedChildCount; i++) {
          const c = argList.namedChild(i);
          if (c && c.type !== 'comment') argumentCount++;
        }
      }
      const { calleeId, kind } = resolveRustCallee(
        calleeText,
        f.filePath,
        fileFunctions,
        fileImports,
        enclosingType,
      );
      if (calleeId) resolvedCallCount++;
      const start = node.startPosition;
      edges.push({
        callerId: nextEnclosingFnId,
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
      if (child) visit(child, nextEnclosingFnId, nextEnclosingType);
    }
  };

  const moduleId =
    fileFunctions.get(f.filePath)?.moduleId ?? makeFunctionId(f.filePath, 1, 1, '<module>');
  visit(f.tree.rootNode, moduleId, null);

  return {
    filePath: f.filePath,
    isFullyTyped: false,
    callExpressionCount,
    resolvedCallCount,
  };
}
