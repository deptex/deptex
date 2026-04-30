/**
 * Whole-program callgraph for a Java workspace, built on tree-sitter Java.
 *
 * Mirrors the shape returned by ../callgraph.ts (TS/JS) so the Java engine
 * can plug into the same propagator IR + framework specs. Resolution
 * strategy is best-effort static type-name matching:
 *   - same package → call resolves to the class declared in the same dir
 *     (subject to public-class-per-file convention; we walk every type)
 *   - explicit `import a.b.ClassName;` → the simple name `ClassName` resolves
 *     to that FQN; calls of the form `ClassName.method(...)` (static) and
 *     calls on a variable typed `ClassName` resolve to that class
 *   - fully-qualified `pkg.ClassName.method(...)` resolves directly
 *   - `super.method(...)` resolves to the superclass declared on the
 *     enclosing class (single-inheritance, simple-name match)
 *   - `this.method(...)` and bare `method(...)` resolve within the
 *     enclosing class
 *
 * Limitations (documented for v1):
 *   - No reflection / DI container resolution. `@Autowired` field calls only
 *     resolve when the field's declared type matches a class we extracted.
 *   - Polymorphism: when a variable is typed as an interface, calls resolve
 *     to the interface's method declaration (= 'virtual' edge with calleeId
 *     pointing at the interface method, not its implementations). The
 *     propagator over-approximates virtual edges as external.
 *   - Generics are erased; `List<T>` is treated as `List`.
 *   - Inner / anonymous / lambda classes parse but resolution is brittle.
 *   - We don't track try-with-resources / annotation-defined constructors
 *     beyond the explicit `new Foo(...)` shape.
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
export interface JavaFileIndex {
  filePath: string;
  /** Workspace-relative POSIX path. */
  relativePath: string;
  /** tree-sitter parse tree. */
  tree: Tree;
  /** Source text. */
  source: string;
  /** Package declaration ("a.b.c") or empty for default package. */
  packageName: string;
  /** simpleName -> FQN, populated from `import a.b.c.Name;` declarations. */
  imports: Map<string, string>;
  /** Wildcard imports `import a.b.*` — the package roots, in declaration order. */
  wildcardImports: string[];
  /** classes declared in this file by simple name → AST class_declaration node. */
  classesBySimpleName: Map<string, Node>;
}

export interface JavaMethodEntry {
  id: FunctionId;
  node: Node;
  fileIndex: JavaFileIndex;
  /** Containing class simple name, or null for static-init blocks etc. */
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

export interface JavaCallgraphContext {
  callgraph: Callgraph;
  /** Method entry by FunctionId. */
  methodById: Map<FunctionId, JavaMethodEntry>;
  /** Class FQN -> simpleName -> entries (overloads share simple name). */
  methodsByClassFqn: Map<string, Map<string, JavaMethodEntry[]>>;
  /** simpleName -> FQN for every class we extracted (across files). */
  classFqnBySimpleName: Map<string, string>;
  /** All file indexes. */
  files: JavaFileIndex[];
}

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'target',
  'build',
  'out',
  '.gradle',
  '.idea',
  '.mvn',
  'dist',
  '.deptex',
]);

/** Public API — returns a Callgraph matching the shape of buildCallgraph. */
export async function buildJavaCallgraph(rootDir: string): Promise<Callgraph> {
  const ctx = await buildJavaCallgraphContext(rootDir);
  return ctx.callgraph;
}

/** Internal API — returns Callgraph + the lookups the IR lowerer needs. */
export async function buildJavaCallgraphContext(rootDir: string): Promise<JavaCallgraphContext> {
  const start = Date.now();
  const absoluteRoot = path.resolve(rootDir);

  const javaFiles = collectJavaFiles(absoluteRoot);
  const language = await loadLanguage('tree-sitter-java.wasm');
  const parser = await makeParser(language);

  const files: JavaFileIndex[] = [];
  for (const abs of javaFiles) {
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

  // Build a global simpleName -> FQN map from same-package classes (so files
  // in pkg/a.java that reference `B` get resolved to `pkg.B` even without an
  // explicit import).
  const classFqnBySimpleName = new Map<string, string>();
  // pkg → set of simpleNames
  const samePackageClasses = new Map<string, Map<string, string>>();
  for (const f of files) {
    let bucket = samePackageClasses.get(f.packageName);
    if (!bucket) {
      bucket = new Map();
      samePackageClasses.set(f.packageName, bucket);
    }
    for (const [simple] of f.classesBySimpleName) {
      const fqn = f.packageName ? `${f.packageName}.${simple}` : simple;
      classFqnBySimpleName.set(simple, fqn);
      bucket.set(simple, fqn);
    }
  }

  // Pass 1: collect functions (methods + constructors + module init per file)
  const nodes: FunctionNode[] = [];
  const methodById = new Map<FunctionId, JavaMethodEntry>();
  const methodsByClassFqn = new Map<string, Map<string, JavaMethodEntry[]>>();

  for (const f of files) {
    // Synthetic module initializer per file (unused for Java but matches TS shape).
    const moduleId = makeFunctionId(f.relativePath, 1, 1, '<module>');
    nodes.push({
      id: moduleId,
      name: '<module>',
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

    // Walk every class and collect methods + constructors.
    const walk = (node: Node, currentClass: { node: Node; simpleName: string; fqn: string } | null): void => {
      if (
        node.type === 'class_declaration' ||
        node.type === 'interface_declaration' ||
        node.type === 'enum_declaration' ||
        node.type === 'record_declaration'
      ) {
        const nameNode = node.childForFieldName('name');
        const simpleName = nameNode ? f.source.slice(nameNode.startIndex, nameNode.endIndex) : '<anon>';
        const fqn = f.packageName ? `${f.packageName}.${simpleName}` : simpleName;
        currentClass = { node, simpleName, fqn };
      }

      if (node.type === 'method_declaration' || node.type === 'constructor_declaration') {
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
            if (c.type === 'formal_parameter' || c.type === 'spread_parameter') paramCount++;
          }
        }

        const isStatic = hasModifier(node, 'static');

        nodes.push({
          id,
          name: methodName,
          kind: (isCtor ? 'constructor' : 'method') as FunctionKind,
          filePath: f.relativePath,
          startLine: start.row + 1,
          startColumn: start.column + 1,
          endLine: end.row + 1,
          endColumn: end.column + 1,
          isFullyTyped: true, // Java is statically typed
          containingClass: className,
          isModuleInitializer: false,
        });

        const entry: JavaMethodEntry = {
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

    // Per-method param + local var → declared simple type name
    // (populated when we enter a method, used to resolve receiver types).
    const collectCallsForMethod = (
      methodNode: Node,
      methodEntry: JavaMethodEntry | null,
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
          if (p.type !== 'formal_parameter' && p.type !== 'spread_parameter') continue;
          const typeNode = p.childForFieldName('type');
          const nameNode = p.childForFieldName('name');
          if (typeNode && nameNode) {
            localTypes.set(textOf(nameNode, f.source), simpleTypeName(typeNode, f.source));
          }
        }
      }

      const body = methodNode.childForFieldName('body');
      if (!body) return;

      const walkExprs = (n: Node): void => {
        // Track local variable types as we walk.
        if (n.type === 'local_variable_declaration') {
          const typeNode = n.childForFieldName('type');
          const typeSimple = typeNode ? simpleTypeName(typeNode, f.source) : null;
          if (typeSimple) {
            for (let i = 0; i < n.namedChildCount; i++) {
              const c = n.namedChild(i)!;
              if (c.type !== 'variable_declarator') continue;
              const nameNode = c.childForFieldName('name');
              if (nameNode) localTypes.set(textOf(nameNode, f.source), typeSimple);
            }
          }
        }

        if (n.type === 'method_invocation') {
          callExpressionCount++;
          const calleeText = textOf(n, f.source).split('(')[0].trim();
          const start = n.startPosition;
          const { kind, calleeId, didResolve } = resolveMethodInvocation({
            node: n,
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
              argumentCount++;
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
          const calleeText = typeNode ? simpleTypeName(typeNode, f.source) : '<anon>';
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
              argumentCount++;
            }
          }
          edges.push({
            callerId,
            calleeId,
            kind,
            filePath: f.relativePath,
            line: start.row + 1,
            column: start.column + 1,
            calleeText: `new ${calleeText}`,
            argumentCount,
          });
        }

        for (let i = 0; i < n.namedChildCount; i++) walkExprs(n.namedChild(i)!);
      };
      walkExprs(body);
    };

    // Walk each declared method/constructor in this file.
    const declaredInFile: JavaMethodEntry[] = [];
    for (const entry of methodById.values()) {
      if (entry.fileIndex === f) declaredInFile.push(entry);
    }
    for (const entry of declaredInFile) {
      collectCallsForMethod(entry.node, entry, entry.id);
    }

    fileStats.push({
      filePath: f.relativePath,
      isFullyTyped: true, // Java is statically typed; we still report a metric
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
  };
}

// ---------------- helpers ----------------

function buildFileIndex(absPath: string, relativePath: string, tree: Tree, source: string): JavaFileIndex {
  const root = tree.rootNode;
  const imports = new Map<string, string>();
  const wildcardImports: string[] = [];
  let packageName = '';

  // Package declaration is the first top-level child usually.
  for (let i = 0; i < root.namedChildCount; i++) {
    const c = root.namedChild(i)!;
    if (c.type === 'package_declaration') {
      // Find scoped_identifier or identifier
      for (let j = 0; j < c.namedChildCount; j++) {
        const id = c.namedChild(j)!;
        if (id.type === 'scoped_identifier' || id.type === 'identifier') {
          packageName = textOf(id, source);
          break;
        }
      }
    } else if (c.type === 'import_declaration') {
      // Static or wildcard? Inspect text for `static` keyword and trailing `.*;`
      const importText = source.slice(c.startIndex, c.endIndex).trim();
      const isStatic = /^import\s+static\b/.test(importText);
      const isWildcard = importText.replace(/;$/, '').trim().endsWith('.*');

      // Find the FQN (scoped_identifier)
      let fqnNode: Node | null = null;
      for (let j = c.namedChildCount - 1; j >= 0; j--) {
        const candidate = c.namedChild(j)!;
        if (candidate.type === 'scoped_identifier' || candidate.type === 'identifier') {
          fqnNode = candidate;
          break;
        }
      }
      if (!fqnNode) continue;
      const fqn = textOf(fqnNode, source);
      if (!fqn) continue;

      if (isWildcard) {
        wildcardImports.push(fqn);
        continue;
      }
      if (isStatic) {
        // import static a.b.C.foo; — the simple name is `foo`, target is the
        // method on `a.b.C`. We record the C class for static-call resolution.
        const lastDot = fqn.lastIndexOf('.');
        if (lastDot > 0) {
          const className = fqn.slice(0, lastDot);
          const simple = fqn.slice(lastDot + 1);
          // Store under the simple method name so bare calls can find the
          // declaring class. We use a `static:` prefix to disambiguate.
          imports.set(`static:${simple}`, className);
        }
        continue;
      }
      const lastDot = fqn.lastIndexOf('.');
      const simple = lastDot >= 0 ? fqn.slice(lastDot + 1) : fqn;
      imports.set(simple, fqn);
    }
  }

  // Collect class declarations by simple name.
  const classesBySimpleName = new Map<string, Node>();
  const walk = (node: Node): void => {
    if (
      node.type === 'class_declaration' ||
      node.type === 'interface_declaration' ||
      node.type === 'enum_declaration' ||
      node.type === 'record_declaration'
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
    packageName,
    imports,
    wildcardImports,
    classesBySimpleName,
  };
}

function collectFieldTypesFromClass(classNode: Node | null, source: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!classNode) return out;
  const body = classNode.childForFieldName('body');
  if (!body) return out;
  for (let i = 0; i < body.namedChildCount; i++) {
    const member = body.namedChild(i)!;
    if (member.type !== 'field_declaration') continue;
    const typeNode = member.childForFieldName('type');
    const typeSimple = typeNode ? simpleTypeName(typeNode, source) : null;
    if (!typeSimple) continue;
    for (let j = 0; j < member.namedChildCount; j++) {
      const c = member.namedChild(j)!;
      if (c.type !== 'variable_declarator') continue;
      const nameNode = c.childForFieldName('name');
      if (nameNode) out.set(textOf(nameNode, source), typeSimple);
    }
  }
  return out;
}

function findEnclosingClass(node: Node): Node | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (
      cur.type === 'class_declaration' ||
      cur.type === 'interface_declaration' ||
      cur.type === 'enum_declaration' ||
      cur.type === 'record_declaration'
    ) {
      return cur;
    }
  }
  return null;
}

function hasModifier(node: Node, mod: string): boolean {
  const modifiers = node.namedChild(0);
  if (!modifiers || modifiers.type !== 'modifiers') return false;
  for (let i = 0; i < modifiers.namedChildCount; i++) {
    const c = modifiers.namedChild(i)!;
    // tree-sitter-java emits modifiers like `public`, `static` as anonymous
    // children — namedChildCount might miss them. Walk childCount.
  }
  for (let i = 0; i < modifiers.childCount; i++) {
    const c = modifiers.child(i)!;
    if (c.type === mod) return true;
  }
  return false;
}

function simpleTypeName(typeNode: Node, source: string): string {
  // type_identifier  → "String"
  // generic_type     → first child is the type_identifier
  // scoped_type_identifier → last segment
  // array_type       → element type's simple name
  if (typeNode.type === 'type_identifier') return textOf(typeNode, source);
  if (typeNode.type === 'generic_type') {
    const first = typeNode.namedChild(0);
    return first ? simpleTypeName(first, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'scoped_type_identifier') {
    const last = typeNode.namedChild(typeNode.namedChildCount - 1);
    return last ? textOf(last, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'array_type') {
    const elem = typeNode.childForFieldName('element');
    return elem ? simpleTypeName(elem, source) : textOf(typeNode, source);
  }
  return textOf(typeNode, source);
}

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

interface ResolveCallArgs {
  node: Node;
  source: string;
  file: JavaFileIndex;
  classFqnBySimpleName: Map<string, string>;
  methodsByClassFqn: Map<string, Map<string, JavaMethodEntry[]>>;
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

function resolveMethodInvocation(args: ResolveCallArgs): ResolveResult {
  const { node, source, file, classFqnBySimpleName, methodsByClassFqn, fieldTypes, localTypes, currentClassFqn } =
    args;

  const objectField = node.childForFieldName('object');
  const nameField = node.childForFieldName('name');
  if (!nameField) return { kind: 'unresolved', calleeId: null, didResolve: false };
  const methodName = textOf(nameField, source);

  // Bare call: `foo(...)` — resolves to enclosing class or static import.
  if (!objectField) {
    if (currentClassFqn) {
      const classMethods = methodsByClassFqn.get(currentClassFqn);
      const entries = classMethods?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
    }
    // Static import?
    const staticDeclaringClass = file.imports.get(`static:${methodName}`);
    if (staticDeclaringClass) {
      const entries = methodsByClassFqn.get(staticDeclaringClass)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // `super.foo(...)` — resolve to superclass declared on this class.
  const objText = textOf(objectField, source);
  if (objText === 'super') {
    const superFqn = resolveSuperclassFqn(args.currentClassNode, file, classFqnBySimpleName);
    if (superFqn) {
      const entries = methodsByClassFqn.get(superFqn)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // `this.foo(...)` — resolve within enclosing class.
  if (objText === 'this') {
    if (currentClassFqn) {
      const entries = methodsByClassFqn.get(currentClassFqn)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // Receiver is an identifier — look up its type via locals → fields.
  if (objectField.type === 'identifier') {
    const recvName = objText;
    // Is the identifier itself a class name (static call shape: ClassName.method)?
    const directClassFqn = classFqnBySimpleName.get(recvName) ?? file.imports.get(recvName);
    if (directClassFqn) {
      const entries = methodsByClassFqn.get(directClassFqn)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
      // External (e.g. java.lang.String) — counts as resolved but no edge.
      return { kind: 'static', calleeId: null, didResolve: true };
    }
    // Local variable
    const typeName = localTypes.get(recvName) ?? fieldTypes.get(recvName);
    if (typeName) {
      const fqn = classFqnBySimpleName.get(typeName) ?? file.imports.get(typeName);
      if (fqn) {
        const entries = methodsByClassFqn.get(fqn)?.get(methodName);
        if (entries && entries[0]) {
          return { kind: 'static', calleeId: entries[0].id, didResolve: true };
        }
        // External type — virtual w/o edge.
        return { kind: 'virtual', calleeId: null, didResolve: true };
      }
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // Receiver is a field access (possibly fully qualified): `pkg.Class.method`.
  if (objectField.type === 'field_access' || objectField.type === 'scoped_identifier') {
    // Try interpreting as `Class.method` (static): if last-but-one segment
    // resolves to a known class.
    const text = textOf(objectField, source);
    const segments = text.split('.');
    const lastSeg = segments[segments.length - 1];
    // Treat the whole text as a possible FQN class name (drop methodName which
    // is the call's name field, not part of `objectField`).
    const fqnGuess = text;
    const directEntries = methodsByClassFqn.get(fqnGuess)?.get(methodName);
    if (directEntries && directEntries[0]) {
      return { kind: 'static', calleeId: directEntries[0].id, didResolve: true };
    }
    // Last segment is a class simple name → resolve via imports.
    const importedFqn = file.imports.get(lastSeg) ?? classFqnBySimpleName.get(lastSeg);
    if (importedFqn) {
      const entries = methodsByClassFqn.get(importedFqn)?.get(methodName);
      if (entries && entries[0]) {
        return { kind: 'static', calleeId: entries[0].id, didResolve: true };
      }
      return { kind: 'static', calleeId: null, didResolve: true };
    }
    return { kind: 'unresolved', calleeId: null, didResolve: false };
  }

  // Chained / nested invocation receiver — leave for the propagator's
  // external/unresolved over-approximation.
  return { kind: 'unresolved', calleeId: null, didResolve: false };
}

function resolveObjectCreation(args: {
  node: Node;
  source: string;
  file: JavaFileIndex;
  classFqnBySimpleName: Map<string, string>;
  methodsByClassFqn: Map<string, Map<string, JavaMethodEntry[]>>;
}): ResolveResult {
  const { node, source, file, classFqnBySimpleName, methodsByClassFqn } = args;
  const typeNode = node.childForFieldName('type');
  if (!typeNode) return { kind: 'unresolved', calleeId: null, didResolve: false };
  const simple = simpleTypeName(typeNode, source);
  const fqn = file.imports.get(simple) ?? classFqnBySimpleName.get(simple);
  if (!fqn) {
    // External constructor (e.g. `new RuntimeException(...)`).
    return { kind: 'static', calleeId: null, didResolve: true };
  }
  // Pick a constructor entry whose name matches the class simple name.
  const ctors = methodsByClassFqn.get(fqn)?.get(simple);
  if (ctors && ctors[0]) {
    return { kind: 'static', calleeId: ctors[0].id, didResolve: true };
  }
  // No constructor declared (default ctor) — counts as resolved-no-body.
  return { kind: 'static', calleeId: null, didResolve: true };
}

function resolveSuperclassFqn(
  classNode: Node | null,
  file: JavaFileIndex,
  classFqnBySimpleName: Map<string, string>,
): string | null {
  if (!classNode) return null;
  if (classNode.type !== 'class_declaration') return null;
  const superclass = classNode.childForFieldName('superclass');
  if (!superclass) return null;
  // The superclass field value is a `superclass` node containing a type_identifier.
  let typeNode: Node | null = superclass;
  if (superclass.namedChildCount > 0) {
    typeNode = superclass.namedChild(0);
  }
  if (!typeNode) return null;
  const simple = simpleTypeName(typeNode, file.source);
  return file.imports.get(simple) ?? classFqnBySimpleName.get(simple) ?? null;
}

function makeFunctionId(filePath: string, line: number, column: number, name: string): FunctionId {
  return `${filePath}:${line}:${column}:${name}`;
}

function collectJavaFiles(absoluteRoot: string, maxFiles?: number): string[] {
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
        if (entry.name.toLowerCase().endsWith('.java')) {
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
