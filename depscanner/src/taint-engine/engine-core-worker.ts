/**
 * worker_thread entry for the taint engine core.
 *
 * Runs `runEngineCore` (the IO-free, CPU-bound stage: callgraph build +
 * forward-propagation + non-taint detectors + client-SPA scoping) OFF the main
 * event loop, so a long synchronous callgraph build on a large repo can't
 * freeze the depscanner worker's heartbeat and get the scan reaped. See
 * `engine-worker-host.ts` for the full rationale.
 *
 * Contract: receives `RunEngineCoreOptions` (minus the non-cloneable signal /
 * onWarn) via `workerData`; posts back exactly one message —
 *   { type: 'result', result: EngineCoreResult, warnings: string[] }
 *   { type: 'error',  message, stack, warnings }
 */

import { parentPort, workerData } from 'worker_threads';
import { runEngineCore, type RunEngineCoreOptions } from './runner';
import type { PropagateResult } from './propagator';

/**
 * Drop the heavy, main-thread-unused parts of the result before structured-
 * cloning it across the boundary: the callgraph nodes/edges/fileStats (can be
 * large on a big repo) and the lowered IR (the detectors already consumed it
 * in-core). The host only reads `flows`, the callgraph metadata
 * (`isTypedJsProject`, `typedFilesPct`, `usedDependencies`), `stats`, and
 * `aborted`.
 */
function slim(result: EngineCoreResultLike): EngineCoreResultLike {
  const p = result.propagation;
  if (!p) return result;
  const slimProp: PropagateResult = {
    ...p,
    callgraph: { ...p.callgraph, nodes: [], edges: [], fileStats: [] },
    irFunctions: undefined,
  };
  return { ...result, propagation: slimProp };
}

type EngineCoreResultLike = Awaited<ReturnType<typeof runEngineCore>>;

async function main(): Promise<void> {
  if (!parentPort) return;
  const warnings: string[] = [];
  const opts = workerData as RunEngineCoreOptions;
  try {
    const result = await runEngineCore({ ...opts, onWarn: (m) => warnings.push(m) });
    parentPort.postMessage({ type: 'result', result: slim(result), warnings });
  } catch (err) {
    const e = err as Error;
    parentPort.postMessage({
      type: 'error',
      message: e?.message ?? String(err),
      stack: e?.stack,
      warnings,
    });
  }
}

void main();
