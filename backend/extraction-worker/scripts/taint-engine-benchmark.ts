#!/usr/bin/env node
/**
 * CLI for the M8 atom-vs-taint-engine benchmark.
 *
 * Usage:
 *   npm run taint-engine:benchmark -- \
 *     --corpus path/to/corpus.json \
 *     --workspace-root path/to/workspaces \
 *     --output ./benchmark-output
 *
 * The corpus references projects either by absolute `path` (run-in-place) or
 * `git`+`ref` (cloned into <workspace-root>/<id> if --workspace-root is set).
 * For each project the harness expects `depscan-reports/` to already contain
 * dep-scan's `*-reachables.slices.json` output (run dep-scan with
 * --reachability-analyzer SemanticReachability before invoking the harness;
 * the M8 plan separates corpus prep from comparator runs by design).
 *
 * Output goes to <output>/report.json + report.html. Exit code is 0 on
 * success, 1 on any project failure that would invalidate the comparison.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  loadCorpus,
  runProject,
  compareCorpus,
  buildReport,
  writeJsonReport,
  writeHtmlReport,
} from '../src/taint-engine/benchmark';
import type { CandidateFlow } from '../src/taint-engine/benchmark';

interface CliOptions {
  corpus: string;
  output: string;
  workspaceRoot?: string;
  pretty: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  let corpus = '';
  let output = './benchmark-output';
  let workspaceRoot: string | undefined;
  let pretty = true;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--corpus') corpus = argv[++i];
    else if (a === '--output') output = argv[++i];
    else if (a === '--workspace-root') workspaceRoot = argv[++i];
    else if (a === '--no-pretty') pretty = false;
    else if (a === '--help' || a === '-h') {
      printHelp();
      process.exit(0);
    } else if (a.startsWith('--')) {
      console.error(`unknown flag: ${a}`);
      process.exit(2);
    }
  }
  if (!corpus) {
    console.error('error: --corpus is required');
    printHelp();
    process.exit(2);
  }
  return { corpus, output, workspaceRoot, pretty };
}

function printHelp(): void {
  process.stdout.write(`Usage: taint-engine:benchmark --corpus <path> [options]

Required:
  --corpus <path>          Path to a JSON corpus file (see corpus.ts for format).

Options:
  --output <dir>           Where to write report.json + report.html. Default ./benchmark-output.
  --workspace-root <dir>   Directory under which corpus 'git'-based projects are checked out.
                           When omitted, only 'path'-based corpus entries are runnable.
  --no-pretty              Skip the HTML report; emit JSON only.

Exit code is 0 on a clean run, 1 if any corpus project failed.
`);
}

function resolveWorkspace(project: { id: string; path?: string; git?: string }, root?: string): string | null {
  if (project.path) return path.resolve(project.path);
  if (project.git && root) return path.resolve(root, project.id);
  return null;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const corpus = loadCorpus(opts.corpus);
  console.log(`Loaded corpus "${corpus.name}" with ${corpus.projects.length} project(s).`);

  const resultsByProject = new Map<string, { atom: CandidateFlow[]; engine: CandidateFlow[] }>();
  const timings: Array<{
    projectId: string;
    atomMs: number | null;
    engineMs: number | null;
    engineFlowsEmitted: number;
    atomFlowsEmitted: number;
  }> = [];

  let projectFailures = 0;
  for (const project of corpus.projects) {
    const ws = resolveWorkspace(project, opts.workspaceRoot);
    if (!ws) {
      console.error(`  ! ${project.id}: cannot resolve workspace (no path, and no --workspace-root for git project)`);
      projectFailures++;
      resultsByProject.set(project.id, { atom: [], engine: [] });
      timings.push({ projectId: project.id, atomMs: null, engineMs: null, engineFlowsEmitted: 0, atomFlowsEmitted: 0 });
      continue;
    }
    if (!fs.existsSync(ws)) {
      console.error(`  ! ${project.id}: workspace not found at ${ws}`);
      projectFailures++;
      resultsByProject.set(project.id, { atom: [], engine: [] });
      timings.push({ projectId: project.id, atomMs: null, engineMs: null, engineFlowsEmitted: 0, atomFlowsEmitted: 0 });
      continue;
    }
    console.log(`\n— ${project.id} (${project.ecosystem}) — ${ws}`);
    const result = await runProject(project, {
      workspaceRoot: ws,
      onWarn: (m) => console.error(`    ! ${m}`),
      onInfo: (m) => console.log(`    > ${m}`),
    });
    resultsByProject.set(project.id, { atom: result.atomFlows, engine: result.engineFlows });
    timings.push({
      projectId: project.id,
      atomMs: result.atomMs,
      engineMs: result.engineMs,
      engineFlowsEmitted: result.engineFlows.length,
      atomFlowsEmitted: result.atomFlows.length,
    });
    console.log(`    atom flows: ${result.atomFlows.length} · engine flows: ${result.engineFlows.length}`);
  }

  const recall = compareCorpus(corpus, resultsByProject);
  const report = buildReport({ corpus, recall, timings });
  const outDir = path.resolve(opts.output);
  const jsonPath = writeJsonReport(outDir, report);
  console.log(`\nWrote ${jsonPath}`);
  if (opts.pretty) {
    const htmlPath = writeHtmlReport(outDir, report);
    console.log(`Wrote ${htmlPath}`);
  }

  console.log('\n=== Summary ===');
  console.log(`atom recall          ${report.recall.atom.pct.toFixed(1)}% (${report.recall.atom.matched}/${report.recall.atom.expected})`);
  console.log(`taint engine recall  ${report.recall.taintEngine.pct.toFixed(1)}% (${report.recall.taintEngine.matched}/${report.recall.taintEngine.expected})`);
  console.log(`delta                ${report.recall.deltaPp >= 0 ? '+' : ''}${report.recall.deltaPp.toFixed(1)}pp`);
  console.log(`new detections       ${report.newDetections.length}`);
  console.log(`regressions          ${report.regressions.length}`);

  if (projectFailures > 0) {
    console.error(`\n${projectFailures} project(s) failed to run; report still emitted.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
