/**
 * CLI: build a callgraph for any local TS/JS workspace and dump it as JSON.
 *
 * Usage:
 *   npm run taint-engine:callgraph -- <path> [--max-files=N] [--summary]
 *
 * --summary suppresses the full edge list and prints only counts + per-file
 * stats; useful for perf-profiling large repos without flooding the terminal.
 */

import * as path from 'path';
import { buildCallgraph } from '../src/taint-engine';

interface ParsedArgs {
  rootDir: string;
  maxFiles?: number;
  summary: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2);
  let rootDir: string | undefined;
  let maxFiles: number | undefined;
  let summary = false;

  for (const a of args) {
    if (a === '--summary') {
      summary = true;
    } else if (a.startsWith('--max-files=')) {
      maxFiles = parseInt(a.split('=')[1], 10);
    } else if (!a.startsWith('--')) {
      rootDir = a;
    }
  }

  if (!rootDir) {
    process.stderr.write('Usage: npm run taint-engine:callgraph -- <path> [--max-files=N] [--summary]\n');
    process.exit(2);
  }

  return { rootDir: path.resolve(rootDir), maxFiles, summary };
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  const cg = await buildCallgraph({
    rootDir: opts.rootDir,
    maxFiles: opts.maxFiles,
    onWarn: (m) => process.stderr.write(`[warn] ${m}\n`),
  });

  if (opts.summary) {
    const resolvedEdges = cg.edges.filter((e) => e.kind !== 'unresolved').length;
    process.stdout.write(
      JSON.stringify(
        {
          rootDir: cg.rootDir,
          hasOwnTsconfig: cg.hasOwnTsconfig,
          isTypedJsProject: cg.isTypedJsProject,
          typedFilesPct: cg.typedFilesPct,
          fileCount: cg.fileCount,
          functionCount: cg.nodes.length,
          edgeCount: cg.edges.length,
          resolvedEdgeCount: resolvedEdges,
          resolutionRate:
            cg.edges.length === 0 ? 0 : Math.round((resolvedEdges / cg.edges.length) * 10000) / 100,
          buildMs: cg.buildMs,
        },
        null,
        2,
      ) + '\n',
    );
    return;
  }

  process.stdout.write(JSON.stringify(cg, null, 2) + '\n');
}

main().catch((err) => {
  process.stderr.write(`callgraph build failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
