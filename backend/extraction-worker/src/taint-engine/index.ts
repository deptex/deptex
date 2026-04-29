/**
 * Public surface for the Deptex cross-file taint engine.
 *
 * M1 ships only the callgraph substrate. M2+ will add the IR converter,
 * worklist propagator, framework spec loader, and the AI augmentation layer.
 */

export { buildCallgraph } from './callgraph';
export type { BuildCallgraphOptions } from './callgraph';
export type {
  Callgraph,
  CallEdge,
  CallEdgeKind,
  FileStats,
  FunctionId,
  FunctionKind,
  FunctionNode,
} from './types';
