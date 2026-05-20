/**
 * Shared types for the Deptex cross-file taint engine.
 *
 * The engine is a deterministic forward-propagation taint analysis built on the
 * TypeScript Compiler API. M1 covers the substrate: a whole-program callgraph
 * over a TS/JS workspace. Later milestones layer the IR, propagator, framework
 * spec loader, and AI augmentation on top of these types.
 */

/** Stable ID for a function across the callgraph. Format: `<filePath>:<line>:<column>:<name>`. */
export type FunctionId = string;

/** Kind of callable the node represents. */
export type FunctionKind =
  | 'function_declaration'
  | 'function_expression'
  | 'arrow_function'
  | 'method'
  | 'constructor'
  | 'getter'
  | 'setter'
  | 'module_initializer';

/** A function (or function-like) discovered during program walk. */
export interface FunctionNode {
  id: FunctionId;
  /** Display name (best effort — anonymous functions get a synthetic name like `<anonymous@line>`). */
  name: string;
  kind: FunctionKind;
  /** Workspace-relative POSIX path. */
  filePath: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  /** True if all parameters and return type were resolvable to non-`any` types. Heuristic for typing quality. */
  isFullyTyped: boolean;
  /** When the function is declared inside a class, the class name. Null for top-level. */
  containingClass: string | null;
  /** True if this node is the synthetic per-file module initializer (top-level statements). */
  isModuleInitializer: boolean;
}

/** How the call edge was resolved. */
export type CallEdgeKind =
  /** Resolved via the type checker to a single declaration. */
  | 'static'
  /** Resolved via interface / abstract method — multiple potential targets. */
  | 'virtual'
  /** Callee identifier had no resolvable symbol (untyped, dynamic, eval-like). */
  | 'unresolved';

/** A call site -> callee edge. For unresolved calls the calleeId is null. */
export interface CallEdge {
  /** ID of the function containing the call site. */
  callerId: FunctionId;
  /** Resolved callee. Null when kind === 'unresolved'. */
  calleeId: FunctionId | null;
  kind: CallEdgeKind;
  /** Workspace-relative POSIX path of the call site. */
  filePath: string;
  line: number;
  column: number;
  /** Display text of the called expression (e.g. `req.body.name`, `child_process.exec`, `helper`). */
  calleeText: string;
  /** Number of arguments at the call site. Useful for sink modeling later. */
  argumentCount: number;
  /**
   * v3 (precision arc): absolute source path of the resolved callee's
   * declaration when the call resolves into dep code (node_modules /
   * site-packages / pkg/mod / registry/src / .m2 / etc.). Null when the
   * callee is in the workspace, unresolved, or the per-language callgraph
   * doesn't track external paths yet (Ruby/PHP/C# in v3 — deferred to v3.1).
   *
   * Used by `extractUsedDependencies` to credit transitives the callgraph
   * confirmed are actually called. The reachability classifier reads the
   * resulting set to demote `unreachable` → `module` (jackson-vs-idna fix).
   */
  calleeExternalSourcePath?: string | null;
}

/** Per-file telemetry collected during callgraph construction. */
export interface FileStats {
  filePath: string;
  /** True when the file is `.ts` or `.tsx`, OR when it's `.js`/`.jsx` and tsc resolved every CallExpression. */
  isFullyTyped: boolean;
  callExpressionCount: number;
  resolvedCallCount: number;
}

/** Result of building the whole-program callgraph. */
export interface Callgraph {
  /** Workspace root the callgraph was built against (absolute POSIX path). */
  rootDir: string;
  /** Whether the workspace had its own tsconfig.json (false = synthetic permissive config used). */
  hasOwnTsconfig: boolean;
  /** Whether the project is "typed enough" for the propagator to trust its results.
   * Heuristic: ≥80% of source files are .ts/.tsx OR have ≥95% call resolution rate. */
  isTypedJsProject: boolean;
  /** Percentage of source files classified as fully typed. */
  typedFilesPct: number;
  nodes: FunctionNode[];
  edges: CallEdge[];
  fileStats: FileStats[];
  /** Wall-clock build time in milliseconds. */
  buildMs: number;
  /** Number of source files included in the program. */
  fileCount: number;
  /**
   * v3 (precision arc): set of dep package names (ecosystem-natural form —
   * npm `pkg` / `@scope/name`, pypi distribution name, go module path, cargo
   * crate, maven `groupId:artifactId`) the callgraph confirmed are reached
   * by at least one CallEdge from workspace code. Undefined when the
   * callgraph doesn't ship usedDependencies extraction for this language
   * (Ruby/PHP/C# in v3). Consumed by `updateReachabilityLevels` to demote
   * called-but-not-imported transitives from `unreachable` to `module`.
   */
  usedDependencies?: Set<string>;
}
