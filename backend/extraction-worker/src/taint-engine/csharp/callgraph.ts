/**
 * Whole-program callgraph for a C# workspace, built on tree-sitter C#.
 *
 * Mirrors the shape returned by ../callgraph.ts (TS/JS), python/callgraph.ts,
 * and java/callgraph.ts so the C# engine can plug into the same propagator
 * IR + framework specs.
 *
 * Resolution strategy (best-effort static name matching, modeled on Java):
 *   - same namespace OR `using` directive matching a class name → calls of
 *     the form `ClassName.Method(...)` (static) and calls on a variable
 *     typed `ClassName` resolve to that class.
 *   - `this.Method(...)` and bare `Method(...)` resolve within the enclosing
 *     class.
 *   - `base.Method(...)` resolves to the superclass declared on the
 *     enclosing class (single-inheritance, simple-name match).
 *   - `new Foo(args)` — emitted as a call edge with calleeText `new Foo`
 *     and (best-effort) resolved to the constructor declared on `Foo`.
 *
 * Known v1 limitations (documented for follow-up):
 *   - No DI container resolution. `[Inject]`/constructor-injected fields
 *     only resolve when the field's declared type matches a class we
 *     extracted.
 *   - Generics are erased: `Foo<int>.Bar(...)` is treated as `Foo.Bar(...)`.
 *   - Polymorphism: when a variable is typed as an interface, calls resolve
 *     to the interface's declaration if any exists; otherwise external.
 *   - Partial classes are NOT merged — every `partial class Foo` in a file
 *     is treated as its own type. Multi-file partial classes therefore
 *     under-resolve cross-file calls.
 *   - `dynamic` dispatch is treated as unresolved.
 *   - LINQ method-syntax chains are walked but receiver typing is brittle.
 *   - Local function captures (`local_function_statement` referencing the
 *     enclosing method's locals) are registered as separate functions, but
 *     captured-local taint isn't flowed across the boundary.
 *   - extension-method calls (`x.MyExt()` where MyExt is a static method on
 *     a `static class`) don't resolve via receiver typing — they only
 *     resolve when written in the static form `Ext.MyExt(x, ...)`.
 *   - Top-level statements (Program.cs) parse as `compilation_unit`
 *     children directly; we represent them in the synthetic `<file>`
 *     module-initializer node.
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

/** Per-file index built once during pass 1; consumed by pass 2 + IR lowerer. */
export interface CSharpFileIndex {
  filePath: string;
  /** Workspace-relative POSIX path. */
  relativePath: string;
  /** tree-sitter parse tree. */
  tree: Tree;
  /** Source text. */
  source: string;
  /** Namespace declaration ("A.B.C") or empty for top-level. */
  namespaceName: string;
  /** simpleName -> FQN, populated from `using A.B.C;` directives.
   * For C# `using`s import a *namespace*, not a type — we record the namespace
   * itself under its tail segment so `Foo.Bar` lookups can compose. We also
   * record any visible class declared in another file's namespace on
   * resolution time. */
  usings: string[];
  /** classes (and structs / records / interfaces) declared in this file
   * by simple name → AST class_declaration node. */
  classesBySimpleName: Map<string, Node>;
}

export interface CSharpMethodEntry {
  id: FunctionId;
  node: Node;
  fileIndex: CSharpFileIndex;
  /** Containing class simple name, or null for top-level / local fns. */
  className: string | null;
  /** Containing class FQN if resolvable. */
  classFqn: string | null;
  /** Method name (simple). */
  methodName: string;
  /** Number of parameters. */
  paramCount: number;
  /** Whether the method has a static modifier. */
  isStatic: boolean;
}

export interface CSharpCallgraphContext {
  callgraph: Callgraph;
  /** Method entry by FunctionId. */
  methodById: Map<FunctionId, CSharpMethodEntry>;
  /** Class FQN -> simpleName -> entries (overloads share simple name). */
  methodsByClassFqn: Map<string, Map<string, CSharpMethodEntry[]>>;
  /** simpleName -> FQN for every class we extracted (across files). */
  classFqnBySimpleName: Map<string, string>;
  /** All file indexes. */
  files: CSharpFileIndex[];
  /** Convenience for the propagate driver: functionId → AST function node. */
  nodeIdToFunc: Map<FunctionId, Node>;
}

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'bin',
  'obj',
  'packages',
  'dist',
  '.deptex',
  '.idea',
  '.vs',
]);

/** Public API — returns a Callgraph matching the shape of buildCallgraph. */
export async function buildCSharpCallgraph(rootDir: string): Promise<Callgraph> {
  const ctx = await buildCSharpCallgraphContext(rootDir);
  return ctx.callgraph;
}

/** Internal API — returns Callgraph + the lookups the IR lowerer needs. */
export async function buildCSharpCallgraphContext(rootDir: string): Promise<CSharpCallgraphContext> {
  const start = Date.now();
  const absoluteRoot = path.resolve(rootDir);

  const csFiles = collectCSharpFiles(absoluteRoot);
  const language = await loadLanguage('tree-sitter-c_sharp.wasm');
  const parser = await makeParser(language);

  const files: CSharpFileIndex[] = [];
  for (const abs of csFiles) {
    let source: string;
    try {
      source = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    const tree = parser.parse(source);
    if (!tree) continue;
    const relativePath = toRelativePosix(abs, absoluteRoot);
    files.push(buildFileIndex(abs, relativePath, tree, source));
  }

  // Build a global simpleName -> FQN map from same-namespace classes.
  const classFqnBySimpleName = new Map<string, string>();
  for (const f of files) {
    for (const [simple] of f.classesBySimpleName) {
      const fqn = f.namespaceName ? `${f.namespaceName}.${simple}` : simple;
      // First writer wins; partial classes/duplicates collapse here.
      if (!classFqnBySimpleName.has(simple)) {
        classFqnBySimpleName.set(simple, fqn);
      }
    }
  }

  // Pass 1: collect functions (methods + constructors + local functions
  // + module init per file).
  const nodes: FunctionNode[] = [];
  const methodById = new Map<FunctionId, CSharpMethodEntry>();
  const methodsByClassFqn = new Map<string, Map<string, CSharpMethodEntry[]>>();
  const nodeIdToFunc = new Map<FunctionId, Node>();

  for (const f of files) {
    // Synthetic module initializer per file (used for top-level statements
    // a.k.a. Program.cs and any free-standing statement nodes).
    const moduleId = makeFunctionId(f.relativePath, 1, 1, '<file>');
    nodes.push({
      id: moduleId,
      name: '<file>',
      kind: 'module_initializer',
      filePath: f.relativePath,
      startLine: 1,
      startColumn: 1,
      endLine: f.tree.rootNode.endPosition.row + 1,
      endColumn: 1,
      isFullyTyped: false,
      containingClass: null,
      isModuleInitializer: true,
    });
    nodeIdToFunc.set(moduleId, f.tree.rootNode);

    // Walk every class and collect methods + constructors + local functions.
    const walk = (node: Node, currentClass: { node: Node; simpleName: string; fqn: string } | null): void => {
      if (
        node.type === 'class_declaration' ||
        node.type === 'struct_declaration' ||
        node.type === 'record_declaration' ||
        node.type === 'interface_declaration'
      ) {
        const nameNode = node.childForFieldName('name');
        const simpleName = nameNode ? f.source.slice(nameNode.startIndex, nameNode.endIndex) : '<anon>';
        const fqn = f.namespaceName ? `${f.namespaceName}.${simpleName}` : simpleName;
        currentClass = { node, simpleName, fqn };
      }

      if (
        node.type === 'method_declaration' ||
        node.type === 'constructor_declaration' ||
        node.type === 'local_function_statement'
      ) {
        const isCtor = node.type === 'constructor_declaration';
        const nameNode = node.childForFieldName('name');
        const methodName = isCtor
          ? (currentClass?.simpleName ?? '<init>')
          : (nameNode ? f.source.slice(nameNode.startIndex, nameNode.endIndex) : '<anon>');

        const start = node.startPosition;
        const end = node.endPosition;
        const className = currentClass?.simpleName ?? null;
        const classFqn = currentClass?.fqn ?? null;
        const id = makeFunctionId(f.relativePath, start.row + 1, start.column + 1, methodName);

        const params = node.childForFieldName('parameters');
        let paramCount = 0;
        if (params) {
          for (let i = 0; i < params.namedChildCount; i++) {
            const c = params.namedChild(i)!;
            if (c.type === 'parameter') paramCount++;
          }
        }

        const isStatic = hasModifier(node, 'static');

        const kind: FunctionKind =
          isCtor ? 'constructor'
          : node.type === 'local_function_statement' ? 'function_declaration'
          : 'method';
        nodes.push({
          id,
          name: methodName,
          kind,
          filePath: f.relativePath,
          startLine: start.row + 1,
          startColumn: start.column + 1,
          endLine: end.row + 1,
          endColumn: end.column + 1,
          isFullyTyped: true, // C# is statically typed
          containingClass: className,
          isModuleInitializer: false,
        });
        nodeIdToFunc.set(id, node);

        const entry: CSharpMethodEntry = {
          id,
          node,
          fileIndex: f,
          className,
          classFqn,
          methodName,
          paramCount,
          isStatic,
        };
        methodById.set(id, entry);

        if (classFqn) {
          let byName = methodsByClassFqn.get(classFqn);
          if (!byName) {
            byName = new Map();
            methodsByClassFqn.set(classFqn, byName);
          }
          let entries = byName.get(methodName);
          if (!entries) {
            entries = [];
            byName.set(methodName, entries);
          }
          entries.push(entry);
        }
      }

      for (let i = 0; i < node.namedChildCount; i++) {
        walk(node.namedChild(i)!, currentClass);
      }
    };
    walk(f.tree.rootNode, null);
  }

  // Pass 2: collect call edges.
  const edges: CallEdge[] = [];
  const fileStats: FileStats[] = [];

  for (const f of files) {
    let callExpressionCount = 0;
    let resolvedCallCount = 0;

    const collectCallsForMethod = (
      methodNode: Node,
      methodEntry: CSharpMethodEntry | null,
      callerId: FunctionId,
    ): void => {
      const localTypes = new Map<string, string>();
      const fieldTypes = methodEntry?.classFqn
        ? collectFieldTypesFromClass(findEnclosingClass(methodNode), f.source)
        : new Map<string, string>();

      // Collect parameter types.
      const params = methodNode.childForFieldName('parameters');
      if (params) {
        for (let i = 0; i < params.namedChildCount; i++) {
          const p = params.namedChild(i)!;
          if (p.type !== 'parameter') continue;
          const typeNode = p.childForFieldName('type');
          const nameNode = p.childForFieldName('name');
          if (typeNode && nameNode) {
            localTypes.set(textOf(nameNode, f.source), simpleTypeName(typeNode, f.source));
          }
        }
      }

      // Method body: tree-sitter-c-sharp uses 'body' field for blocks; some
      // shapes use expression-bodied members → 'body' may be an
      // arrow_expression_clause.
      const body = methodNode.childForFieldName('body');
      if (!body) return;

      const walkExprs = (n: Node): void => {
        if (n.type === 'local_declaration_statement') {
          const decl = findChildOfType(n, 'variable_declaration');
          if (decl) {
            const typeNode = decl.childForFieldName('type');
            const typeSimple = typeNode ? simpleTypeName(typeNode, f.source) : null;
            if (typeSimple) {
              for (let i = 0; i < decl.namedChildCount; i++) {
                const c = decl.namedChild(i)!;
                if (c.type !== 'variable_declarator') continue;
                const nameNode = c.childForFieldName('name') ?? c.namedChild(0);
                if (nameNode && nameNode.type === 'identifier') {
                  localTypes.set(textOf(nameNode, f.source), typeSimple);
                }
              }
            }
          }
        }

        if (n.type === 'invocation_expression') {
          callExpressionCount++;
          const fnNode = n.childForFieldName('function');
          const calleeText = stripGenericsFromCallee(textOf(fnNode, f.source));
          const start = n.startPosition;
          const { kind, calleeId, didResolve } = resolveInvocation({
            invocation: n,
            source: f.source,
            file: f,
            classFqnBySimpleName,
            methodsByClassFqn,
            fieldTypes,
            localTypes,
            currentClassFqn: methodEntry?.classFqn ?? null,
            currentClassNode: findEnclosingClass(methodNode),
          });
          if (didResolve) resolvedCallCount++;
          const argList = n.childForFieldName('arguments');
          let argumentCount = 0;
          if (argList) {
            for (let i = 0; i < argList.namedChildCount; i++) {
              const c = argList.namedChild(i);
              if (c && c.type === 'argument') argumentCount++;
            }
          }
          edges.push({
            callerId,
            calleeId,
            kind,
            filePath: f.relativePath,
            line: start.row + 1,
            column: start.column + 1,
            calleeText,
            argumentCount,
          });
        } else if (n.type === 'object_creation_expression') {
          callExpressionCount++;
          const typeNode = n.childForFieldName('type');
          const typeSimple = typeNode ? simpleTypeName(typeNode, f.source) : '<anon>';
          const start = n.startPosition;
          const { kind, calleeId, didResolve } = resolveObjectCreation({
            node: n,
            source: f.source,
            file: f,
            classFqnBySimpleName,
            methodsByClassFqn,
          });
          if (didResolve) resolvedCallCount++;
          const argList = n.childForFieldName('arguments');
          let argumentCount = 0;
          if (argList) {
            for (let i = 0; i < argList.namedChildCount; i++) {
              const c = argList.namedChild(i);
              if (c && c.type === 'argument') argumentCount++;
            }
          }
          // Use bare type name as calleeText so YAML patterns like
          // `SqlCommand(*)` and `Process.Start(*)` style sinks can match.
          // (Constructors aren't typically called via dotted names; keep both
          // shapes available by emitting the type name.)
          edges.push({
            callerId,
            calleeId,
            kind,
            filePath: f.relativePath,
            line: start.row + 1,
            column: start.column + 1,
            calleeText: typeSimple,
            argumentCount,
          });
        }

        for (let i = 0; i < n.namedChildCount; i++) walkExprs(n.namedChild(i)!);
      };
      walkExprs(body);
    };

    // Walk each declared method/constructor in this file.
    const declaredInFile: CSharpMethodEntry[] = [];
    for (const entry of methodById.values()) {
      if (entry.fileIndex === f) declaredInFile.push(entry);
    }
    for (const entry of declaredInFile) {
      collectCallsForMethod(entry.node, entry, entry.id);
    }

    fileStats.push({
      filePath: f.relativePath,
      isFullyTyped: true,
      callExpressionCount,
      resolvedCallCount,
    });
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
    methodById,
    methodsByClassFqn,
    classFqnBySimpleName,
    files,
    nodeIdToFunc,
  };
}

// ---------------- helpers ----------------

function buildFileIndex(absPath: string, relativePath: string, tree: Tree, source: string): CSharpFileIndex {
  const root = tree.rootNode;
  const usings: string[] = [];
  let namespaceName = '';

  // Walk the top-level: collect using directives, namespace declaration, and
  // then walk into namespace bodies for nested classes.
  const visitTopLevel = (node: Node): void => {
    if (node.type === 'using_directive') {
      // Children include `static`?, name (qualified_name | identifier), `;`.
      // We collect the qualified target as a `usings` entry.
      let nameNode: Node | null = null;
      for (let i = node.namedChildCount - 1; i >= 0; i--) {
        const c = node.namedChild(i)!;
        if (c.type === 'qualified_name' || c.type === 'identifier' || c.type === 'name_equals') continue;
        // The grammar exposes the imported name as the last named child
        // typed `qualified_name` or `identifier` in most builds.
      }
      // Fall back to the rightmost qualified_name / identifier child.
      for (let i = node.namedChildCount - 1; i >= 0; i--) {
        const c = node.namedChild(i)!;
        if (c.type === 'qualified_name' || c.type === 'identifier') {
          nameNode = c;
          break;
        }
      }
      if (nameNode) usings.push(textOf(nameNode, source));
    } else if (node.type === 'namespace_declaration' || node.type === 'file_scoped_namespace_declaration') {
      const nameNode = node.childForFieldName('name') ?? findFirstOfTypes(node, ['qualified_name', 'identifier']);
      if (nameNode) namespaceName = textOf(nameNode, source);
      // Recurse into the body (block / declaration list) so classes inside
      // a namespace surface in classesBySimpleName.
      for (let i = 0; i < node.namedChildCount; i++) {
        visitTopLevel(node.namedChild(i)!);
      }
      return;
    }
    // For other top-level nodes (class_declaration, etc.) we simply leave the
    // collection to the simple-name walk below.
  };
  for (let i = 0; i < root.namedChildCount; i++) {
    visitTopLevel(root.namedChild(i)!);
  }

  // Collect class/struct/record/interface declarations by simple name.
  const classesBySimpleName = new Map<string, Node>();
  const walk = (node: Node): void => {
    if (
      node.type === 'class_declaration' ||
      node.type === 'struct_declaration' ||
      node.type === 'record_declaration' ||
      node.type === 'interface_declaration'
    ) {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        classesBySimpleName.set(textOf(nameNode, source), node);
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);

  return {
    filePath: absPath,
    relativePath,
    tree,
    source,
    namespaceName,
    usings,
    classesBySimpleName,
  };
}

function collectFieldTypesFromClass(classNode: Node | null, source: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!classNode) return out;
  // The class body in tree-sitter-c-sharp is named `body` and is a
  // `declaration_list` containing `field_declaration` / `property_declaration`
  // children.
  const body = classNode.childForFieldName('body');
  if (!body) return out;
  for (let i = 0; i < body.namedChildCount; i++) {
    const member = body.namedChild(i)!;
    if (member.type === 'field_declaration' || member.type === 'event_field_declaration') {
      const decl = findChildOfType(member, 'variable_declaration');
      if (!decl) continue;
      const typeNode = decl.childForFieldName('type');
      const typeSimple = typeNode ? simpleTypeName(typeNode, source) : null;
      if (!typeSimple) continue;
      for (let j = 0; j < decl.namedChildCount; j++) {
        const c = decl.namedChild(j)!;
        if (c.type !== 'variable_declarator') continue;
        const nameNode = c.childForFieldName('name') ?? c.namedChild(0);
        if (nameNode && nameNode.type === 'identifier') {
          out.set(textOf(nameNode, source), typeSimple);
        }
      }
    } else if (member.type === 'property_declaration') {
      const typeNode = member.childForFieldName('type');
      const nameNode = member.childForFieldName('name');
      if (typeNode && nameNode) {
        out.set(textOf(nameNode, source), simpleTypeName(typeNode, source));
      }
    }
  }
  return out;
}

function findEnclosingClass(node: Node): Node | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (
      cur.type === 'class_declaration' ||
      cur.type === 'struct_declaration' ||
      cur.type === 'record_declaration' ||
      cur.type === 'interface_declaration'
    ) {
      return cur;
    }
  }
  return null;
}

function hasModifier(node: Node, mod: string): boolean {
  // tree-sitter-c-sharp emits modifiers as a `modifier` named child on the
  // declaration. They may also appear as anonymous children on some builds —
  // walk both.
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'modifier') {
      // The modifier's text is the keyword itself ("public", "static", ...).
      // The grammar doesn't expose a single field; we compare childCount
      // children's types AND raw text fragments.
      for (let j = 0; j < c.childCount; j++) {
        const k = c.child(j)!;
        if (k.type === mod) return true;
      }
      // Fallback: compare the raw text.
      // (Some grammars expose the keyword as the modifier node's only token.)
    }
  }
  for (let i = 0; i < node.childCount; i++) {
    const c = node.child(i)!;
    if (c.type === mod) return true;
  }
  return false;
}

function simpleTypeName(typeNode: Node, source: string): string {
  // Drop generic args + array/nullable wrappers; return the leaf name.
  if (typeNode.type === 'identifier' || typeNode.type === 'predefined_type') {
    return textOf(typeNode, source);
  }
  if (typeNode.type === 'generic_name') {
    const nameNode = typeNode.childForFieldName('name') ?? typeNode.namedChild(0);
    return nameNode ? textOf(nameNode, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'qualified_name') {
    // The trailing segment is the class.
    const last = typeNode.namedChild(typeNode.namedChildCount - 1);
    return last ? simpleTypeName(last, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'array_type') {
    const elem = typeNode.childForFieldName('type') ?? typeNode.namedChild(0);
    return elem ? simpleTypeName(elem, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'nullable_type') {
    const inner = typeNode.namedChild(0);
    return inner ? simpleTypeName(inner, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'pointer_type') {
    const inner = typeNode.namedChild(0);
    return inner ? simpleTypeName(inner, source) : textOf(typeNode, source);
  }
  // Fallback: raw text, generics stripped.
  return stripGenericsFromCallee(textOf(typeNode, source));
}

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function findChildOfType(node: Node, type: string): Node | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === type) return c;
  }
  return null;
}

function findFirstOfTypes(node: Node, types: string[]): Node | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (types.includes(c.type)) return c;
  }
  return null;
}

/** Strip generic type arguments from callee text:
 *    `Foo<int>.Bar<T>(...)` → `Foo.Bar(...)`
 *    `Repo<User>.Find` → `Repo.Find`
 *  Naïve angle-bracket stripper; good enough for v1 since pattern matching
 *  tolerates the resulting form. */
export function stripGenericsFromCallee(text: string): string {
  if (!text || text.indexOf('<') < 0) return text;
  let out = '';
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '<') {
      depth++;
      continue;
    }
    if (ch === '>') {
      if (depth > 0) depth--;
      continue;
    }
    if (depth === 0) out += ch;
  }
  return out;
}

interface ResolveCallArgs {
  invocation: Node;
  source: string;
  file: CSharpFileIndex;
  classFqnBySimpleName: Map<string, string>;
  methodsByClassFqn: Map<string, Map<string, CSharpMethodEntry[]>>;
  fieldTypes: Map<string, string>;
  localTypes: Map<string, string>;
  currentClassFqn: string | null;
  currentClassNode: Node | null;
}

interface ResolveResult {
  kind: CallEdgeKind;
  calleeId: FunctionId | null;
  didResolve: boolean;
}

export function resolveInvocation(args: ResolveCallArgs): ResolveResult {
  const { invocation, source, file, classFqnBySimpleName, methodsByClassFqn, fieldTypes, localTypes, currentClassFqn } =
    args;

  const fnNode = invocation.childForFieldName('function');
  if (!fnNode) return { kind: 'unresolved', calleeId: null, didResolve: false };

  // Strip generic args at the resolution layer too.
  const callText = stripGenericsFromCallee(textOf(fnNode, source));

  // Parse the callee shape:
  //   identifier              → bare call
  //   member_access_expression with `expression` + `name` fields
  //   conditional_access_expression  → x?.M(...) — drop the ?. and treat as member
  //   generic_name            → bare generic call (rare); strip args
  //   qualified_name          → A.B.M — treat last seg as method, leading as class chain
  let receiverText = '';
  let methodName = '';

  if (fnNode.type === 'identifier') {
    methodName = textOf(fnNode, source);
  } else if (fnNode.type === 'generic_name') {
    const nameNode = fnNode.childForFieldName('name') ?? fnNode.namedChild(0);
    methodName = nameNode ? textOf(nameNode, source) : '';
  } else if (fnNode.type === 'member_access_expression') {
    const expr = fnNode.childForFieldName('expression');
    const name = fnNode.childForFieldName('name');
    if (expr) receiverText = stripGenericsFromCallee(textOf(expr, source));
    if (name) {
      const nm = name.type === 'generic_name'
        ? (name.childForFieldName('name') ?? name.namedChild(0))
        : name;
      methodName = nm ? textOf(nm, source) : '';
    }
  } else if (fnNode.type === 'conditional_access_expression') {
    // x?.M(...) — pop down to the underlying member access if present.
    const inner = invocation.childForFieldName('function');
    // Best-effort: re-parse as splitting on the last '.'.
    const idx = callText.lastIndexOf('.');
    if (idx > 0) {
      receiverText = callText.slice(0, idx).replace(/\?$/, '');
      methodName = callText.slice(idx + 1);
    } else {
      methodName = callText;
    }
    if (inner) void inner; // referenced for symmetry
  } else if (fnNode.type === 'qualified_name') {
    const idx = callText.lastIndexOf('.');
    if (idx > 0) {
      receiverText = callText.slice(0, idx);
      methodName = callText.slice(idx + 1);
    } else {
      methodName = callText;
    }
  } else {
    // Fall back to a textual split.
    const idx = callText.lastIndexOf('.');
    if (idx > 0) {
      receiverText = callText.slice(0, idx);
      methodName = callText.slice(idx + 1);
    } else {
      methodName = callText;
    }
  }

  if (!methodName) return { kind: 'unresolved', calleeId: null, didResolve: false };

  // Bare call: `foo(...)` — resolves to enclosing class method.
  if (!receiverText) {
    if (currentClassFqn) {
      const entries = methodsByClassFqn.get(currentClassFqn)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // `base.Method(...)` — resolve to superclass.
  if (receiverText === 'base') {
    const superFqn = resolveSuperclassFqn(args.currentClassNode, file, classFqnBySimpleName);
    if (superFqn) {
      const entries = methodsByClassFqn.get(superFqn)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // `this.Method(...)` — resolve within enclosing class.
  if (receiverText === 'this') {
    if (currentClassFqn) {
      const entries = methodsByClassFqn.get(currentClassFqn)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // Single-segment receiver: identifier (could be a class name OR a local).
  if (!receiverText.includes('.')) {
    // Class name shape (static call: `ClassName.Method(...)`).
    const directClassFqn = classFqnBySimpleName.get(receiverText);
    if (directClassFqn) {
      const entries = methodsByClassFqn.get(directClassFqn)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
      // External (eg `Convert.ToInt32` – not declared in workspace).
      return { kind: 'static', calleeId: null, didResolve: true };
    }
    // Local / field of typed receiver.
    const typeName = localTypes.get(receiverText) ?? fieldTypes.get(receiverText);
    if (typeName) {
      const fqn = classFqnBySimpleName.get(typeName);
      if (fqn) {
        const entries = methodsByClassFqn.get(fqn)?.get(methodName);
        if (entries && entries[0]) {
          return { kind: 'static', calleeId: entries[0].id, didResolve: true };
        }
        return { kind: 'virtual', calleeId: null, didResolve: true };
      }
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // Dotted receiver: `Pkg.Class.Method`-shape OR `obj.Sub.Method`.
  // Try treating the entire receiverText as a known class FQN.
  const directEntries = methodsByClassFqn.get(receiverText)?.get(methodName);
  if (directEntries && directEntries[0]) {
    return { kind: 'static', calleeId: directEntries[0].id, didResolve: true };
  }
  // Use the last segment as a simple class name.
  const lastSeg = receiverText.split('.').pop()!;
  const importedFqn = classFqnBySimpleName.get(lastSeg);
  if (importedFqn) {
    const entries = methodsByClassFqn.get(importedFqn)?.get(methodName);
    if (entries && entries[0]) {
      return { kind: 'static', calleeId: entries[0].id, didResolve: true };
    }
    return { kind: 'static', calleeId: null, didResolve: true };
  }
  return { kind: 'unresolved', calleeId: null, didResolve: false };
}

function resolveObjectCreation(args: {
  node: Node;
  source: string;
  file: CSharpFileIndex;
  classFqnBySimpleName: Map<string, string>;
  methodsByClassFqn: Map<string, Map<string, CSharpMethodEntry[]>>;
}): ResolveResult {
  const { node, source, classFqnBySimpleName, methodsByClassFqn } = args;
  const typeNode = node.childForFieldName('type');
  if (!typeNode) return { kind: 'unresolved', calleeId: null, didResolve: false };
  const simple = simpleTypeName(typeNode, source);
  const fqn = classFqnBySimpleName.get(simple);
  if (!fqn) {
    // External constructor (eg `new SqlCommand(...)` from BCL).
    return { kind: 'static', calleeId: null, didResolve: true };
  }
  const ctors = methodsByClassFqn.get(fqn)?.get(simple);
  if (ctors && ctors[0]) {
    return { kind: 'static', calleeId: ctors[0].id, didResolve: true };
  }
  // No explicit constructor — default ctor. Counts as resolved-no-body.
  return { kind: 'static', calleeId: null, didResolve: true };
}

function resolveSuperclassFqn(
  classNode: Node | null,
  _file: CSharpFileIndex,
  classFqnBySimpleName: Map<string, string>,
): string | null {
  if (!classNode) return null;
  if (classNode.type !== 'class_declaration' && classNode.type !== 'record_declaration') return null;
  // tree-sitter-c-sharp exposes inheritance as a `base_list` named child.
  const baseList = findChildOfType(classNode, 'base_list');
  if (!baseList) return null;
  // First entry in the base_list is the superclass (interfaces follow).
  const first = baseList.namedChild(0);
  if (!first) return null;
  const simple = simpleTypeName(first, _file.source);
  return classFqnBySimpleName.get(simple) ?? null;
}

function makeFunctionId(filePath: string, line: number, column: number, name: string): FunctionId {
  return `${filePath}:${line}:${column}:${name}`;
}

function collectCSharpFiles(absoluteRoot: string, maxFiles?: number): string[] {
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
        if (entry.name.startsWith('.')) continue;
        stack.push(full);
      } else if (entry.isFile()) {
        if (entry.name.toLowerCase().endsWith('.cs')) {
          out.push(full);
        }
      }
    }
  }

  return out;
}

function toRelativePosix(fileName: string, absoluteRoot: string): string {
  return path.relative(absoluteRoot, fileName).split(path.sep).join('/');
}
