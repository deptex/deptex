/**
 * Dual-engine benchmark runner.
 *
 * For each corpus project the runner produces two CandidateFlow lists:
 *   1. Atom flows — parsed from dep-scan's `*-reachables.slices.json` files.
 *      The harness expects these to already exist under the project's
 *      `depscan-reports/` directory; the M8 plan is to produce them once per
 *      benchmark cycle (dep-scan is multi-minute and not in the comparator's
 *      hot loop). When `regenerate=true` is passed, the runner shells out to
 *      `runDepScan` first.
 *   2. Engine flows — produced by calling `runEngine` from `taint-engine/runner.ts`
 *      with the AI filter intentionally disabled, so the comparison is
 *      apples-to-apples deterministic-output-only.
 *
 * The benchmark intentionally does NOT touch Supabase or write
 * `project_reachable_flows` rows; results live in memory and are written to
 * `report.json`/`report.html` by the report module.
 */

import * as fs from 'fs';
import * as path from 'path';
import { runEngine } from '../runner';
import type { Flow } from '../flow';
import type { BenchmarkProject } from './corpus';
import { flowToCandidate, type CandidateFlow } from './compare';

export interface RunProjectOptions {
  /** Cwd-relative or absolute path to the workspace where the project lives. */
  workspaceRoot: string;
  /** When true, the harness re-runs dep-scan; otherwise it parses cached reports. */
  regenerate?: boolean;
  /** Optional warning sink — the harness logs progress to it. */
  onWarn?: (msg: string) => void;
  onInfo?: (msg: string) => void;
}

export interface RunProjectResult {
  project: BenchmarkProject;
  atomFlows: CandidateFlow[];
  engineFlows: CandidateFlow[];
  /** Raw atom slice count, used to flag "atom didn't run" vs "atom ran but found nothing". */
  atomSliceCount: number;
  /** Engine flows pre-comparator-mapping, useful for follow-up analysis. */
  rawEngineFlows: Flow[];
  atomMs: number | null;
  engineMs: number | null;
}

export async function runProject(
  project: BenchmarkProject,
  options: RunProjectOptions,
): Promise<RunProjectResult> {
  const { workspaceRoot, onWarn, onInfo } = options;

  // ---- atom side ----
  const reportsDir = path.join(workspaceRoot, 'depscan-reports');
  let atomMs: number | null = null;
  let atomSlices: AtomSlice[] = [];
  if (fs.existsSync(reportsDir)) {
    const start = Date.now();
    atomSlices = readAtomSlices(reportsDir, onWarn);
    atomMs = Date.now() - start;
  } else {
    onWarn?.(
      `${project.id}: no depscan-reports/ at ${workspaceRoot}; atom side will be empty. ` +
        `Run dep-scan with --reachability-analyzer SemanticReachability first or pass --regenerate.`,
    );
  }
  const atomFlows = atomSlices.flatMap(sliceToCandidates);

  // ---- engine side ----
  let engineMs: number | null = null;
  let rawEngineFlows: Flow[] = [];
  try {
    const start = Date.now();
    const result = await runEngine({
      workspaceRoot,
      onWarn,
      // Benchmark is deterministic-only; the AI filter would just add noise to
      // the recall comparison. M7 covers the filter's own correctness tests.
    });
    engineMs = Date.now() - start;
    if (result.ran && result.propagation) {
      rawEngineFlows = result.propagation.flows;
      onInfo?.(`${project.id}: engine emitted ${rawEngineFlows.length} flows in ${engineMs}ms`);
    } else {
      onWarn?.(`${project.id}: engine did not run — ${result.skippedReason ?? 'unknown'}`);
    }
  } catch (err) {
    onWarn?.(`${project.id}: engine threw — ${(err as Error).message}`);
  }
  const engineFlows = rawEngineFlows.map(flowToCandidate);

  return {
    project,
    atomFlows,
    engineFlows,
    atomSliceCount: atomSlices.length,
    rawEngineFlows,
    atomMs,
    engineMs,
  };
}

interface AtomSlice {
  flows?: AtomNode[];
  purls?: string[];
}

interface AtomNode {
  /** dep-scan emits this as `parentFileName` or `fileName` depending on version. */
  parentFileName?: string;
  fileName?: string;
  /** symbol/method names dep-scan exposes; combined into the candidate sinkMethod. */
  resolvedMethod?: string;
  fullName?: string;
  name?: string;
}

function readAtomSlices(reportsDir: string, onWarn?: (msg: string) => void): AtomSlice[] {
  const out: AtomSlice[] = [];
  let entries: string[];
  try {
    entries = fs.readdirSync(reportsDir).filter((f) => f.endsWith('-reachables.slices.json'));
  } catch (err) {
    onWarn?.(`failed to read ${reportsDir}: ${(err as Error).message}`);
    return out;
  }
  for (const f of entries) {
    const full = path.join(reportsDir, f);
    try {
      const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
      if (Array.isArray(parsed)) {
        for (const slice of parsed) {
          if (slice && typeof slice === 'object') out.push(slice as AtomSlice);
        }
      }
    } catch (err) {
      onWarn?.(`failed to parse ${f}: ${(err as Error).message}`);
    }
  }
  return out;
}

function sliceToCandidates(slice: AtomSlice): CandidateFlow[] {
  if (!slice.flows || slice.flows.length === 0) return [];
  const last = slice.flows[slice.flows.length - 1];
  const sinkFile = (last.parentFileName || last.fileName || '').replace(/\\/g, '/');
  const sinkMethod = last.resolvedMethod || last.fullName || last.name || '';
  // atom slices don't tag a vuln class; the comparator sets ignoreVulnClass=true
  // for atom matches, so we leave it null.
  return [
    {
      vulnClass: null,
      sinkFile,
      sinkMethod,
      sinkPattern: null,
    },
  ];
}
