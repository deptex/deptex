/**
 * Normalized intermediate representation for the taint propagator.
 *
 * Stub for M1. M2 fleshes out Function/BasicBlock/Statement and the
 * astToIr() converter that lowers a TypeScript AST function into IR.
 */

export interface Statement {
  kind: 'assign' | 'call' | 'return' | 'branch';
  /** Workspace-relative POSIX path of the statement source location. */
  filePath: string;
  line: number;
  column: number;
}

export interface BasicBlock {
  id: string;
  statements: Statement[];
  /** IDs of successor blocks within the same function. */
  successors: string[];
}

export interface IrFunction {
  /** Matches Callgraph.FunctionNode.id. */
  id: string;
  entryBlockId: string;
  blocks: Map<string, BasicBlock>;
}
