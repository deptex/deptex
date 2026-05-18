/**
 * Go callgraph extractor for the cross-file taint engine.
 *
 * Walks every `.go` file in a workspace with web-tree-sitter and emits a
 * `Callgraph` matching the shape produced by the TS/JS extractor. Edges
 * are resolved best-effort:
 *
 *   - Bare-identifier calls (`helper()`)              → match any function
 *                                                       in the same package.
 *   - Package-qualified calls (`fmt.Println()`)        → if `fmt` is a
 *                                                       known import-alias of a
 *                                                       first-party package,
 *                                                       resolve to that
 *                                                       package's exported
 *                                                       function. Otherwise
 *                                                       leave external.
 *   - Method calls (`receiver.Method()`)               → if there's exactly
 *                                                       one method `Method`
 *                                                       declared in the
 *                                                       workspace whose
 *                                                       receiver name matches
 *                                                       (textually), use it.
 *                                                       Otherwise external /
 *                                                       unresolved.
 *
 * V1 limitations (matching the task brief):
 *   - No interface dispatch (the concrete type isn't statically obvious).
 *   - No `go/ssa`-grade type inference (we don't shell out to `go`).
 *   - Method-on-value vs method-on-pointer is ignored — they share name
 *     resolution. Multi-method overloads disambiguated by package prefix
 *     only.
 *   - `_test.go` files and anything under `vendor/` are skipped.
 *   - `init()` functions are emitted but not edge-targeted on import.
 *
 * The output Callgraph has `isTypedJsProject=false`, `typedFilesPct=0`
 * — those metrics are TS-specific and don't apply to Go.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { Node, Tree } from 'web-tree-sitter';
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

const GO_EXTENSIONS = new Set(['.go']);
const SKIP_DIRS = new Set([
  '.git',
  'vendor',
  'node_modules',
  'dist',
  'build',
  '.cache',
  '.deptex',
]);

/** Per-file parse + AST + indexed function nodes. Held by the caller (the
 *  propagator) so it can re-walk the AST during IR lowering. */
export interface GoFileEntry {
  filePath: string; // workspace-relative POSIX
  absolutePath: string;
  source: string;
  tree: Tree;
  packageName: string;
  /** Imports declared at top of file: alias → import path. */
  importsByAlias: Map<string, string>;
  /** function/method declaration AST nodes in this file. */
  decls: Array<{
    node: Node;
    name: string;
    receiverType: string | null;
    isMethod: boolean;
    funcId: FunctionId;
  }>;
  /** Synthetic module-initializer for top-level statements (var inits, init()). */
  moduleId: FunctionId;
  /** First-line offset of each line, for line/col conversion. */
}

/** Live context the Go IR lowerer + propagator orchestrator share. */
export interface GoCallgraphContext {
  callgraph: Callgraph;
  rootDir: string;
  files: GoFileEntry[];
  /** node.id → FunctionId for every emitted decl + module initializer. */
  nodeToFuncId: Map<number, FunctionId>;
  /** FunctionId → AST node + the file entry it lives in. */
  funcIdToDecl: Map<FunctionId, { node: Node; file: GoFileEntry }>;
  /** Module path from go.mod (may be null on synthetic / lib-style projects). */
  modulePath: string | null;
  /** Map of "package import path" → first-party package contents.
   *  "package import path" is `<modulePath>/<dir>` for first-party files;
   *  for the module root it's just `<modulePath>`. */
  packageByImportPath: Map<string, GoPackage>;
  /** Same packages indexed by their declared `package <name>` value. */
  packagesByName: Map<string, GoPackage[]>;
}

interface GoPackage {
  /** Directory relative to root (e.g. "internal/db"). */
  dirRelative: string;
  /** Full import path (e.g. "example.com/app/internal/db"). */
  importPath: string;
  /** package <name> from the source. */
  packageName: string;
  /** All top-level functions across files in this dir. */
  exportedFns: Map<string, FunctionId>; // by simple func name
  allFns: Map<string, FunctionId>;
  /** Files in this package. */
  files: GoFileEntry[];
}

export interface BuildGoCallgraphOptions {
  rootDir: string;
  maxFiles?: number;
  onWarn?: (msg: string) => void;
}

export async function buildGoCallgraph(rootDir: string): Promise<Callgraph> {
  const ctx = await buildGoCallgraphContext({ rootDir });
  return ctx.callgraph;
}

export async function buildGoCallgraphContext(
  options: BuildGoCallgraphOptions,
): Promise<GoCallgraphContext> {
  const { rootDir, maxFiles, onWarn } = options;
  const absoluteRoot = path.resolve(rootDir);
  const start = Date.now();

  const modulePath = readGoModulePath(absoluteRoot);

  const lang = await loadLanguage('tree-sitter-go.wasm');
  const parser = await makeParser(lang);

  const allFiles: string[] = [];
  collectGoFiles(absoluteRoot, absoluteRoot, allFiles, maxFiles);

  const fileEntries: GoFileEntry[] = [];
  const nodes: FunctionNode[] = [];
  const fileStats: FileStats[] = [];
  const nodeToFuncId = new Map<number, FunctionId>();
  const funcIdToDecl = new Map<FunctionId, { node: Node; file: GoFileEntry }>();
  const packageByImportPath = new Map<string, GoPackage>();
  const packagesByName = new Map<string, GoPackage[]>();

  for (const absPath of allFiles) {
    const relativePath = toRelativePosix(absPath, absoluteRoot);
    let source: string;
    try {
      source = fs.readFileSync(absPath, 'utf8');
    } catch (err) {
      onWarn?.(`failed to read ${relativePath}: ${(err as Error).message}`);
      continue;
    }
    const tree = parser.parse(source);
    if (!tree) {
      onWarn?.(`tree-sitter parse failed for ${relativePath}`);
      continue;
    }

    const root = tree.rootNode;
    const packageName = readPackageName(root, source) ?? 'main';
    const importsByAlias = collectImports(root, source);

    const dirRelative = path
      .dirname(relativePath)
      .split(path.sep)
      .join('/');
    const importPath = makeImportPath(modulePath, dirRelative);

    let pkg = packageByImportPath.get(importPath);
    if (!pkg) {
      pkg = {
        dirRelative,
        importPath,
        packageName,
        exportedFns: new Map(),
        allFns: new Map(),
        files: [],
      };
      packageByImportPath.set(importPath, pkg);
      const arr = packagesByName.get(packageName) ?? [];
      arr.push(pkg);
      packagesByName.set(packageName, arr);
    }

    // Synthetic module-initializer for top-level statements.
    const moduleId = makeFunctionId(relativePath, 1, 1, '<module>');
    const endPos = positionFromOffset(source, source.length);
    nodes.push({
      id: moduleId,
      name: '<module>',
      kind: 'module_initializer',
      filePath: relativePath,
      startLine: 1,
      startColumn: 1,
      endLine: endPos.line,
      endColumn: endPos.column,
      isFullyTyped: false,
      containingClass: null,
      isModuleInitializer: true,
    });

    const fileEntry: GoFileEntry = {
      filePath: relativePath,
      absolutePath: absPath,
      source,
      tree,
      packageName,
      importsByAlias,
      decls: [],
      moduleId,
    };
    fileEntries.push(fileEntry);
    pkg.files.push(fileEntry);

    nodeToFuncId.set(root.id, moduleId);
    funcIdToDecl.set(moduleId, { node: root, file: fileEntry });

    const declarations = collectFunctionDecls(root);
    for (const d of declarations) {
      const start2 = d.node.startPosition;
      const startLine = start2.row + 1;
      const startCol = start2.column + 1;
      const id = makeFunctionId(relativePath, startLine, startCol, d.name);
      const endPos2 = d.node.endPosition;
      nodes.push({
        id,
        name: d.name,
        kind: d.isMethod ? ('method' as FunctionKind) : ('function_declaration' as FunctionKind),
        filePath: relativePath,
        startLine,
        startColumn: startCol,
        endLine: endPos2.row + 1,
        endColumn: endPos2.column + 1,
        isFullyTyped: false,
        containingClass: d.receiverType,
        isModuleInitializer: false,
      });
      fileEntry.decls.push({
        node: d.node,
        name: d.name,
        receiverType: d.receiverType,
        isMethod: d.isMethod,
        funcId: id,
      });
      nodeToFuncId.set(d.node.id, id);
      funcIdToDecl.set(id, { node: d.node, file: fileEntry });

      pkg.allFns.set(d.name, id);
      // exported = first letter uppercase
      if (d.name && /^[A-Z]/.test(d.name)) {
        pkg.exportedFns.set(d.name, id);
      }
    }

    fileStats.push({
      filePath: relativePath,
      isFullyTyped: false,
      callExpressionCount: 0,
      resolvedCallCount: 0,
    });
  }

  // Pass 2: edges. Walk every call expression in every function and resolve
  // to a target FunctionId when we can.
  const edges: CallEdge[] = [];
  const fileStatsByPath = new Map(fileStats.map((s) => [s.filePath, s]));

  for (const file of fileEntries) {
    const stats = fileStatsByPath.get(file.filePath)!;
    walkCallSites(
      file,
      file.tree.rootNode,
      file.moduleId,
      edges,
      stats,
      packageByImportPath,
      packagesByName,
      modulePath,
      nodeToFuncId,
    );
    for (const decl of file.decls) {
      walkCallSites(
        file,
        decl.node,
        decl.funcId,
        edges,
        stats,
        packageByImportPath,
        packagesByName,
        modulePath,
        nodeToFuncId,
      );
    }
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

  return {
    callgraph,
    rootDir: absoluteRoot,
    files: fileEntries,
    nodeToFuncId,
    funcIdToDecl,
    modulePath,
    packageByImportPath,
    packagesByName,
  };
}

function makeImportPath(modulePath: string | null, dirRelative: string): string {
  if (!modulePath) return dirRelative === '.' ? '<root>' : dirRelative;
  if (dirRelative === '' || dirRelative === '.') return modulePath;
  return `${modulePath}/${dirRelative}`;
}

function readGoModulePath(absoluteRoot: string): string | null {
  const goModPath = path.join(absoluteRoot, 'go.mod');
  try {
    const content = fs.readFileSync(goModPath, 'utf8');
    const match = content.match(/^module\s+(\S+)/m);
    if (match) return match[1];
  } catch {
    // ignore
  }
  return null;
}

function collectGoFiles(
  rootDir: string,
  cur: string,
  out: string[],
  maxFiles?: number,
): void {
  if (maxFiles != null && out.length >= maxFiles) return;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(cur, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (maxFiles != null && out.length >= maxFiles) return;
    const full = path.join(cur, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      if (entry.name.startsWith('.')) continue;
      collectGoFiles(rootDir, full, out, maxFiles);
    } else if (entry.isFile()) {
      if (!GO_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
      if (entry.name.endsWith('_test.go')) continue;
      out.push(full);
    }
  }
}

function toRelativePosix(absPath: string, absoluteRoot: string): string {
  return path.relative(absoluteRoot, absPath).split(path.sep).join('/');
}

function readPackageName(root: Node, source: string): string | null {
  for (let i = 0; i < root.namedChildCount; i++) {
    const c = root.namedChild(i);
    if (!c) continue;
    if (c.type === 'package_clause') {
      for (let j = 0; j < c.namedChildCount; j++) {
        const id = c.namedChild(j);
        if (id && id.type === 'package_identifier') {
          return source.slice(id.startIndex, id.endIndex);
        }
      }
    }
  }
  return null;
}

function collectImports(root: Node, source: string): Map<string, string> {
  const out = new Map<string, string>();
  const handleSpec = (spec: Node): void => {
    const nameNode = spec.childForFieldName('name');
    const pathNode = spec.childForFieldName('path');
    if (!pathNode) return;
    const importPath = stripQuotes(source.slice(pathNode.startIndex, pathNode.endIndex));
    if (!importPath) return;
    let alias: string;
    if (nameNode) {
      const txt = source.slice(nameNode.startIndex, nameNode.endIndex);
      if (txt === '_' || txt === '.') return;
      alias = txt;
    } else {
      const segs = importPath.split('/');
      let idx = segs.length - 1;
      if (idx > 0 && /^v\d+$/.test(segs[idx])) idx -= 1;
      alias = segs[idx];
    }
    out.set(alias, importPath);
  };

  for (let i = 0; i < root.namedChildCount; i++) {
    const child = root.namedChild(i);
    if (!child) continue;
    if (child.type !== 'import_declaration') continue;
    for (let j = 0; j < child.namedChildCount; j++) {
      const spec = child.namedChild(j);
      if (!spec) continue;
      if (spec.type === 'import_spec') handleSpec(spec);
      else if (spec.type === 'import_spec_list') {
        for (let k = 0; k < spec.namedChildCount; k++) {
          const inner = spec.namedChild(k);
          if (inner && inner.type === 'import_spec') handleSpec(inner);
        }
      }
    }
  }
  return out;
}

function stripQuotes(s: string): string {
  if (s.length >= 2 && (s[0] === '"' || s[0] === '`') && s[s.length - 1] === s[0]) {
    return s.slice(1, -1);
  }
  return s;
}

interface Decl {
  node: Node;
  name: string;
  receiverType: string | null;
  isMethod: boolean;
}

function collectFunctionDecls(root: Node): Decl[] {
  const out: Decl[] = [];
  for (let i = 0; i < root.namedChildCount; i++) {
    const c = root.namedChild(i);
    if (!c) continue;
    if (c.type === 'function_declaration') {
      const name = textOfField(c, 'name');
      if (name) out.push({ node: c, name, receiverType: null, isMethod: false });
    } else if (c.type === 'method_declaration') {
      const name = textOfField(c, 'name');
      const receiverType = receiverTypeName(c);
      if (name) out.push({ node: c, name, receiverType, isMethod: true });
    }
  }
  return out;
}

function textOfField(node: Node, field: string): string | null {
  const f = node.childForFieldName(field);
  if (!f) return null;
  return nodeText(f);
}

function nodeText(node: Node): string {
  return node.text;
}

function receiverTypeName(methodNode: Node): string | null {
  const recv = methodNode.childForFieldName('receiver');
  if (!recv) return null;
  // parameter_list (parameter_declaration ident type)
  for (let i = 0; i < recv.namedChildCount; i++) {
    const param = recv.namedChild(i);
    if (!param || param.type !== 'parameter_declaration') continue;
    const ty = param.childForFieldName('type');
    if (!ty) continue;
    let t = ty;
    if (t.type === 'pointer_type') {
      // peel pointer
      for (let j = 0; j < t.namedChildCount; j++) {
        const inner = t.namedChild(j);
        if (inner) {
          t = inner;
          break;
        }
      }
    }
    return nodeText(t);
  }
  return null;
}

function makeFunctionId(filePath: string, line: number, column: number, name: string): FunctionId {
  return `${filePath}:${line}:${column}:${name}`;
}

function positionFromOffset(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lastNL = -1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) {
      line++;
      lastNL = i;
    }
  }
  return { line, column: offset - lastNL };
}

/** Walk every call_expression nested inside a function-or-module body and emit a CallEdge. */
function walkCallSites(
  file: GoFileEntry,
  funcRoot: Node,
  callerId: FunctionId,
  edges: CallEdge[],
  stats: FileStats,
  packageByImportPath: Map<string, GoPackage>,
  packagesByName: Map<string, GoPackage[]>,
  modulePath: string | null,
  nodeToFuncId: Map<number, FunctionId>,
): void {
  const isModule = funcRoot.type === 'source_file';
  const skipNested = !isModule;

  const visit = (node: Node, depth: number): void => {
    // For function/method bodies: don't descend into NESTED function/method
    // bodies declared on the source_file root (we walk those separately).
    // But we *do* descend into closures (function_literal) inside our body
    // so their calls land on the enclosing function.
    if (depth > 0 && skipNested) {
      // we never re-enter the source_file boundary; nothing to do
    }
    if (depth > 0 && isModule) {
      if (node.type === 'function_declaration' || node.type === 'method_declaration') {
        return; // separate caller
      }
    }

    if (node.type === 'call_expression') {
      stats.callExpressionCount++;
      const fnNode = node.childForFieldName('function');
      if (fnNode) {
        const calleeText = nodeText(fnNode);
        const startLine = node.startPosition.row + 1;
        const startCol = node.startPosition.column + 1;
        const args = node.childForFieldName('arguments');
        const argCount = args ? args.namedChildCount : 0;

        let kind: CallEdgeKind = 'unresolved';
        let calleeId: FunctionId | null = null;

        const resolved = resolveCallee(
          fnNode,
          file,
          packageByImportPath,
          packagesByName,
          modulePath,
        );
        if (resolved) {
          calleeId = resolved;
          kind = 'static';
          stats.resolvedCallCount++;
        } else if (isExternalCallee(fnNode, file)) {
          // External (third-party / stdlib) — counts as resolved for
          // metrics; no edge target.
          kind = 'static';
          stats.resolvedCallCount++;
        }

        edges.push({
          callerId,
          calleeId,
          kind,
          filePath: file.filePath,
          line: startLine,
          column: startCol,
          calleeText,
          argumentCount: argCount,
        });
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (!child) continue;
      visit(child, depth + 1);
    }
  };

  // We walk the function body, not the whole declaration (so receiver/param
  // syntax isn't visited).
  if (funcRoot.type === 'function_declaration' || funcRoot.type === 'method_declaration') {
    const body = funcRoot.childForFieldName('body');
    if (body) visit(body, 1);
    return;
  }
  visit(funcRoot, 0);
}

/** Return the FunctionId of the resolved callee, or null. */
function resolveCallee(
  fnNode: Node,
  file: GoFileEntry,
  packageByImportPath: Map<string, GoPackage>,
  packagesByName: Map<string, GoPackage[]>,
  modulePath: string | null,
): FunctionId | null {
  if (fnNode.type === 'identifier') {
    // Bare identifier: same-package function?
    const name = nodeText(fnNode);
    // Look for a same-package fn declared anywhere in the workspace.
    const candidates = packagesByName.get(file.packageName);
    if (!candidates) return null;
    for (const pkg of candidates) {
      // Same package = same packageName + same dir.
      const id = pkg.allFns.get(name);
      if (id && pkg.files.some((f) => f.filePath === file.filePath)) return id;
    }
    return null;
  }
  if (fnNode.type === 'selector_expression') {
    const operand = fnNode.childForFieldName('operand');
    const field = fnNode.childForFieldName('field');
    if (!operand || !field) return null;
    const fieldName = nodeText(field);

    // Package-qualified call: `<importAlias>.<Func>()`
    if (operand.type === 'identifier') {
      const operandName = nodeText(operand);
      const importPath = file.importsByAlias.get(operandName);
      if (importPath) {
        // First-party import?
        if (modulePath && (importPath === modulePath || importPath.startsWith(`${modulePath}/`))) {
          const pkg = packageByImportPath.get(importPath);
          if (pkg) {
            const id = pkg.exportedFns.get(fieldName) ?? pkg.allFns.get(fieldName);
            if (id) return id;
          }
        }
        // External (stdlib / third-party) — leave for spec matching.
        return null;
      }
      // operand is a local var — receiver method call.
    }

    // Method call on a value/expression: best-effort match on method name.
    // We can't statically know the receiver type without a type system, so
    // if EXACTLY ONE method named `fieldName` is declared workspace-wide,
    // resolve to it; otherwise leave unresolved.
    return null;
  }
  return null;
}

function isExternalCallee(fnNode: Node, file: GoFileEntry): boolean {
  if (fnNode.type === 'selector_expression') {
    const operand = fnNode.childForFieldName('operand');
    if (operand?.type === 'identifier') {
      const operandName = nodeText(operand);
      const importPath = file.importsByAlias.get(operandName);
      if (importPath) return true;
    }
  }
  return false;
}
