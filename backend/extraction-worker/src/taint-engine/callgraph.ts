/**
 * Whole-program callgraph for a TS/JS workspace, built on the TypeScript
 * Compiler API. The callgraph is the substrate the propagator (M2) walks
 * forward over to push taint from sources to sinks.
 *
 * Resolution strategy: for each CallExpression we ask the TypeChecker for the
 * resolved signature. When the signature has a declaration we map the
 * declaration's source location back to the FunctionNode the walk emitted.
 * Calls the type checker can't resolve (untyped JS, dynamic dispatch through
 * `any`, eval-like patterns) are emitted with kind='unresolved' so the
 * propagator can decide whether to over-approximate.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';
import type {
  Callgraph,
  CallEdge,
  CallEdgeKind,
  FileStats,
  FunctionId,
  FunctionKind,
  FunctionNode,
} from './types';

export interface BuildCallgraphOptions {
  /** Absolute path to the workspace root. */
  rootDir: string;
  /** Optional cap on number of source files; useful for tests + perf bounding. */
  maxFiles?: number;
  /** Optional logger for progress + warnings. */
  onWarn?: (message: string) => void;
}

/** File extensions we consider source for the callgraph. */
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']);

/** Directory names skipped during workspace walk. */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.cache',
  '.turbo',
  'coverage',
  '.deptex',
]);

/** Default permissive tsconfig used when the workspace has none. */
const FALLBACK_COMPILER_OPTIONS: ts.CompilerOptions = {
  target: ts.ScriptTarget.ES2020,
  module: ts.ModuleKind.CommonJS,
  moduleResolution: ts.ModuleResolutionKind.NodeJs,
  allowJs: true,
  checkJs: false,
  noEmit: true,
  esModuleInterop: true,
  resolveJsonModule: true,
  skipLibCheck: true,
  jsx: ts.JsxEmit.Preserve,
  strict: false,
  isolatedModules: false,
};

export async function buildCallgraph(options: BuildCallgraphOptions): Promise<Callgraph> {
  const { rootDir, maxFiles, onWarn } = options;
  const start = Date.now();

  const absoluteRoot = path.resolve(rootDir);
  const { compilerOptions, hasOwnTsconfig, configFiles } = loadCompilerOptions(absoluteRoot, onWarn);

  const sourceFiles = collectSourceFiles(absoluteRoot, maxFiles);
  // Make sure tsconfig-listed files are included (e.g. ambient .d.ts) even if
  // walk missed them; concat + dedupe.
  const allFiles = Array.from(new Set([...configFiles, ...sourceFiles]));

  const program = ts.createProgram({
    rootNames: allFiles,
    options: compilerOptions,
  });
  const checker = program.getTypeChecker();

  const nodes: FunctionNode[] = [];
  const edges: CallEdge[] = [];
  const fileStats: FileStats[] = [];
  const declarationToNodeId = new Map<ts.Node, FunctionId>();

  // Pass 1: collect every function-like declaration and emit a synthetic
  // module initializer per source file. Done in a separate pass so call-site
  // resolution in pass 2 can map declarations to already-known FunctionIds.
  for (const sourceFile of program.getSourceFiles()) {
    if (sourceFile.isDeclarationFile) continue;
    if (!isInsideWorkspace(sourceFile.fileName, absoluteRoot)) continue;
    collectFunctions(sourceFile, absoluteRoot, nodes, declarationToNodeId, checker);
  }

  // Pass 2: walk every call expression and emit edges.
  for (const sourceFile of program.getSourceFiles()) {
    if (sourceFile.isDeclarationFile) continue;
    if (!isInsideWorkspace(sourceFile.fileName, absoluteRoot)) continue;
    const stats = collectCallEdges(
      sourceFile,
      absoluteRoot,
      nodes,
      declarationToNodeId,
      checker,
      edges,
    );
    fileStats.push(stats);
  }

  const typedFiles = fileStats.filter((s) => s.isFullyTyped).length;
  const typedFilesPct = fileStats.length === 0 ? 0 : (typedFiles / fileStats.length) * 100;
  const totalCalls = fileStats.reduce((sum, s) => sum + s.callExpressionCount, 0);
  const resolvedCalls = fileStats.reduce((sum, s) => sum + s.resolvedCallCount, 0);
  const resolutionRate = totalCalls === 0 ? 0 : (resolvedCalls / totalCalls) * 100;
  const isTypedJsProject = typedFilesPct >= 80 || resolutionRate >= 95;

  return {
    rootDir: absoluteRoot,
    hasOwnTsconfig,
    isTypedJsProject,
    typedFilesPct: Math.round(typedFilesPct * 100) / 100,
    nodes,
    edges,
    fileStats,
    buildMs: Date.now() - start,
    fileCount: fileStats.length,
  };
}

/** Discover and load the workspace's tsconfig.json, or synthesize a fallback. */
function loadCompilerOptions(
  absoluteRoot: string,
  onWarn?: (message: string) => void,
): { compilerOptions: ts.CompilerOptions; hasOwnTsconfig: boolean; configFiles: string[] } {
  const tsconfigPath = ts.findConfigFile(absoluteRoot, ts.sys.fileExists, 'tsconfig.json');
  if (!tsconfigPath) {
    return { compilerOptions: FALLBACK_COMPILER_OPTIONS, hasOwnTsconfig: false, configFiles: [] };
  }
  // findConfigFile may walk up. Reject configs that live above absoluteRoot.
  // Normalize both to absolute paths with native separators before comparing
  // (tsc returns forward-slash paths on Windows; path.resolve returns native).
  const normalizedConfigDir = path.resolve(path.dirname(tsconfigPath));
  if (normalizedConfigDir !== absoluteRoot && !normalizedConfigDir.startsWith(absoluteRoot + path.sep)) {
    return { compilerOptions: FALLBACK_COMPILER_OPTIONS, hasOwnTsconfig: false, configFiles: [] };
  }

  const configFile = ts.readConfigFile(tsconfigPath, ts.sys.readFile);
  if (configFile.error) {
    onWarn?.(`tsconfig.json parse error: ${ts.flattenDiagnosticMessageText(configFile.error.messageText, '\n')}`);
    return { compilerOptions: FALLBACK_COMPILER_OPTIONS, hasOwnTsconfig: false, configFiles: [] };
  }

  const parsed = ts.parseJsonConfigFileContent(
    configFile.config,
    ts.sys,
    path.dirname(tsconfigPath),
  );
  if (parsed.errors.length > 0) {
    for (const err of parsed.errors) {
      onWarn?.(`tsconfig.json: ${ts.flattenDiagnosticMessageText(err.messageText, '\n')}`);
    }
  }

  // Force allowJs + noEmit. We always want to include .js files in the program
  // even if the workspace's tsconfig excludes them, and we never emit.
  const compilerOptions: ts.CompilerOptions = {
    ...parsed.options,
    allowJs: true,
    noEmit: true,
    skipLibCheck: true,
  };

  return { compilerOptions, hasOwnTsconfig: true, configFiles: parsed.fileNames };
}

/** Synchronous filesystem walk. Returns absolute POSIX-normalized paths. */
function collectSourceFiles(absoluteRoot: string, maxFiles?: number): string[] {
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
        const ext = path.extname(entry.name).toLowerCase();
        if (SOURCE_EXTENSIONS.has(ext)) {
          // Skip declaration files — they have no executable code.
          if (entry.name.endsWith('.d.ts')) continue;
          out.push(full);
        }
      }
    }
  }

  return out;
}

function isInsideWorkspace(fileName: string, absoluteRoot: string): boolean {
  const resolved = path.resolve(fileName);
  return resolved === absoluteRoot || resolved.startsWith(absoluteRoot + path.sep);
}

function toRelativePosix(fileName: string, absoluteRoot: string): string {
  return path.relative(absoluteRoot, fileName).split(path.sep).join('/');
}

function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function functionKindOf(node: ts.Node): FunctionKind {
  if (ts.isFunctionDeclaration(node)) return 'function_declaration';
  if (ts.isFunctionExpression(node)) return 'function_expression';
  if (ts.isArrowFunction(node)) return 'arrow_function';
  if (ts.isMethodDeclaration(node)) return 'method';
  if (ts.isConstructorDeclaration(node)) return 'constructor';
  if (ts.isGetAccessorDeclaration(node)) return 'getter';
  if (ts.isSetAccessorDeclaration(node)) return 'setter';
  return 'function_declaration';
}

/** Best-effort name extraction. Returns synthetic `<anonymous@line:col>` when no name available. */
function functionNameOf(node: ts.Node, sourceFile: ts.SourceFile): string {
  if (ts.isConstructorDeclaration(node)) return 'constructor';

  if (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  ) {
    if (node.name && (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name))) {
      return node.name.text;
    }
  }

  // Arrow / function expression assigned to a variable: pull the variable name.
  const parent = node.parent;
  if (parent) {
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
    if (ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
    if (ts.isPropertyDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
  }

  const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return `<anonymous@${line + 1}:${character + 1}>`;
}

/** Walk up to find the enclosing class declaration name, if any. */
function containingClassOf(node: ts.Node): string | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isClassDeclaration(cur) || ts.isClassExpression(cur)) {
      return cur.name?.text ?? '<anonymous_class>';
    }
    cur = cur.parent;
  }
  return null;
}

function isFullyTypedSignature(node: ts.SignatureDeclaration, checker: ts.TypeChecker): boolean {
  const signature = checker.getSignatureFromDeclaration(node);
  if (!signature) return false;
  const returnType = checker.getReturnTypeOfSignature(signature);
  if (returnType.flags & ts.TypeFlags.Any) return false;
  for (const param of signature.parameters) {
    const decl = param.valueDeclaration ?? param.declarations?.[0];
    if (!decl) return false;
    const paramType = checker.getTypeOfSymbolAtLocation(param, decl);
    if (paramType.flags & ts.TypeFlags.Any) return false;
  }
  return true;
}

function makeFunctionId(filePath: string, line: number, column: number, name: string): FunctionId {
  return `${filePath}:${line}:${column}:${name}`;
}

/** Pass 1: collect function-like declarations + a per-file synthetic module initializer. */
function collectFunctions(
  sourceFile: ts.SourceFile,
  absoluteRoot: string,
  nodes: FunctionNode[],
  declarationToNodeId: Map<ts.Node, FunctionId>,
  checker: ts.TypeChecker,
): void {
  const relativePath = toRelativePosix(sourceFile.fileName, absoluteRoot);

  // Synthetic module initializer for top-level statements (require/import side
  // effects, top-level express() setup, etc).
  const moduleId = makeFunctionId(relativePath, 1, 1, '<module>');
  nodes.push({
    id: moduleId,
    name: '<module>',
    kind: 'module_initializer',
    filePath: relativePath,
    startLine: 1,
    startColumn: 1,
    endLine: sourceFile.getLineAndCharacterOfPosition(sourceFile.getEnd()).line + 1,
    endColumn: 1,
    isFullyTyped: false,
    containingClass: null,
    isModuleInitializer: true,
  });
  declarationToNodeId.set(sourceFile, moduleId);

  const visit = (node: ts.Node): void => {
    if (isFunctionLike(node)) {
      const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
      const name = functionNameOf(node, sourceFile);
      const id = makeFunctionId(relativePath, start.line + 1, start.character + 1, name);
      const fullyTyped = isFullyTypedSignature(node as ts.SignatureDeclaration, checker);
      nodes.push({
        id,
        name,
        kind: functionKindOf(node),
        filePath: relativePath,
        startLine: start.line + 1,
        startColumn: start.character + 1,
        endLine: end.line + 1,
        endColumn: end.character + 1,
        isFullyTyped: fullyTyped,
        containingClass: containingClassOf(node),
        isModuleInitializer: false,
      });
      declarationToNodeId.set(node, id);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
}

/** Find the nearest enclosing function-like ancestor, or the source file (= module initializer). */
function enclosingFunctionOf(node: ts.Node): ts.Node {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (isFunctionLike(cur)) return cur;
    if (ts.isSourceFile(cur)) return cur;
    cur = cur.parent;
  }
  // Should be unreachable; nodes always live inside a SourceFile.
  return node;
}

/** Resolve the symbol of a CallExpression's callee through aliases (imports, re-exports). */
function resolveCalleeSymbol(call: ts.CallExpression, checker: ts.TypeChecker): ts.Symbol | undefined {
  let symbol = checker.getSymbolAtLocation(call.expression);

  // Handle property access (e.g. `obj.method()`): the symbol of the full
  // expression is on the rightmost identifier.
  if (!symbol && ts.isPropertyAccessExpression(call.expression)) {
    symbol = checker.getSymbolAtLocation(call.expression.name);
  }
  if (!symbol && ts.isElementAccessExpression(call.expression)) {
    // Dynamic property access — leave unresolved.
    return undefined;
  }

  // Walk through import / export / namespace aliases.
  if (symbol && symbol.flags & ts.SymbolFlags.Alias) {
    try {
      symbol = checker.getAliasedSymbol(symbol);
    } catch {
      // Some malformed re-export chains throw; fall through with the alias.
    }
  }

  return symbol;
}

/** Pick the "best" declaration of a symbol to map back to a FunctionNode.
 *  Prefers function-like declarations; returns the first declaration otherwise. */
function pickFunctionDeclaration(symbol: ts.Symbol): ts.Node | undefined {
  const decls = symbol.declarations;
  if (!decls || decls.length === 0) return undefined;
  for (const d of decls) {
    if (isFunctionLike(d)) return d;
  }
  // A variable declaration whose initializer is a function expression / arrow
  // — we registered the function expression in pass 1, not the variable.
  for (const d of decls) {
    if (ts.isVariableDeclaration(d) && d.initializer && isFunctionLike(d.initializer)) {
      return d.initializer;
    }
    if (ts.isPropertyAssignment(d) && isFunctionLike(d.initializer)) {
      return d.initializer;
    }
    if (ts.isPropertyDeclaration(d) && d.initializer && isFunctionLike(d.initializer)) {
      return d.initializer;
    }
  }
  return decls[0];
}

/** Pass 2: emit one CallEdge per CallExpression and return per-file stats. */
function collectCallEdges(
  sourceFile: ts.SourceFile,
  absoluteRoot: string,
  nodes: FunctionNode[],
  declarationToNodeId: Map<ts.Node, FunctionId>,
  checker: ts.TypeChecker,
  edges: CallEdge[],
): FileStats {
  const relativePath = toRelativePosix(sourceFile.fileName, absoluteRoot);
  const isTsFile = /\.(ts|tsx|mts|cts)$/i.test(sourceFile.fileName);

  let callExpressionCount = 0;
  let resolvedCallCount = 0;

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      callExpressionCount++;
      const enclosing = enclosingFunctionOf(node);
      const callerId = declarationToNodeId.get(enclosing);
      if (!callerId) {
        ts.forEachChild(node, visit);
        return;
      }

      const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      const calleeText = node.expression.getText(sourceFile);

      let kind: CallEdgeKind = 'unresolved';
      let calleeId: FunctionId | null = null;

      const callExpr = node as ts.CallExpression | ts.NewExpression;
      const symbol = ts.isCallExpression(callExpr)
        ? resolveCalleeSymbol(callExpr, checker)
        : checker.getSymbolAtLocation(callExpr.expression);

      if (symbol) {
        const decl = pickFunctionDeclaration(symbol);
        if (decl) {
          // Interface method (MethodSignature, abstract method): emit a virtual
          // edge with no calleeId. The propagator (M2) will join across
          // possible implementations using the type checker's getImplementations.
          if (ts.isMethodSignature(decl) || isInterfaceMethod(decl)) {
            kind = 'virtual';
            resolvedCallCount++;
          } else {
            const found = declarationToNodeId.get(decl);
            if (found) {
              calleeId = found;
              kind = 'static';
              resolvedCallCount++;
            } else if (isExternalDeclaration(decl, absoluteRoot)) {
              // External (node_modules / lib) — counts as resolved for the
              // typing-quality metric. We don't emit an edge to a node we
              // don't have. The propagator handles externals via framework specs.
              resolvedCallCount++;
              kind = 'static';
            }
          }
        }
      }

      edges.push({
        callerId,
        calleeId,
        kind,
        filePath: relativePath,
        line: start.line + 1,
        column: start.character + 1,
        calleeText,
        argumentCount: callExpr.arguments?.length ?? 0,
      });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);

  // A file is "fully typed" if it's TS *or* if every JS call site resolved.
  const isFullyTyped =
    isTsFile ||
    (callExpressionCount > 0 && resolvedCallCount / callExpressionCount >= 0.95);

  return {
    filePath: relativePath,
    isFullyTyped,
    callExpressionCount,
    resolvedCallCount,
  };
}

function isExternalDeclaration(decl: ts.Node, absoluteRoot: string): boolean {
  const sf = decl.getSourceFile();
  return !isInsideWorkspace(sf.fileName, absoluteRoot);
}

function isInterfaceMethod(decl: ts.Node): boolean {
  if (ts.isMethodSignature(decl)) return true;
  let cur: ts.Node | undefined = decl.parent;
  while (cur) {
    if (ts.isInterfaceDeclaration(cur)) return true;
    if (ts.isClassDeclaration(cur)) return false;
    cur = cur.parent;
  }
  return false;
}

// Mark unused export to avoid tree-shaking / lint complaints; types module
// re-exports go through index.ts.
export type { Callgraph, CallEdge, FunctionNode, FileStats } from './types';
