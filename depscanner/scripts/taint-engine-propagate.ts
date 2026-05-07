/**
 * CLI: run the taint propagator over a workspace using one or more YAML
 * framework specs and print the resulting flows + perf stats as JSON.
 *
 * Usage:
 *   npm run taint-engine:propagate -- <workspacePath> --spec=<yaml>[,<yaml>...] [--summary]
 *
 * --summary suppresses the full flow list and prints only counts + per-stage
 * timings; useful for perf-profiling without flooding the terminal.
 */

import * as path from 'path';
import { loadSpec, propagate, type FrameworkSpec } from '../src/taint-engine';

interface ParsedArgs {
  rootDir: string;
  specPaths: string[];
  summary: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2);
  let rootDir: string | undefined;
  let specPaths: string[] = [];
  let summary = false;

  for (const a of args) {
    if (a === '--summary') {
      summary = true;
    } else if (a.startsWith('--spec=')) {
      specPaths = a.slice('--spec='.length).split(',').map((s) => s.trim()).filter(Boolean);
    } else if (!a.startsWith('--')) {
      rootDir = a;
    }
  }

  if (!rootDir || specPaths.length === 0) {
    process.stderr.write('Usage: npm run taint-engine:propagate -- <workspacePath> --spec=<yaml>[,<yaml>...] [--summary]\n');
    process.exit(2);
  }

  return { rootDir: path.resolve(rootDir), specPaths: specPaths.map((p) => path.resolve(p)), summary };
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  const specs: FrameworkSpec[] = opts.specPaths.map((p) => loadSpec(p));
  const result = await propagate({
    rootDir: opts.rootDir,
    specs,
    onWarn: (m) => process.stderr.write(`[warn] ${m}\n`),
  });

  if (opts.summary) {
    process.stdout.write(
      JSON.stringify(
        {
          rootDir: opts.rootDir,
          specs: specs.map((s) => `${s.framework}@${s.version}`),
          stats: result.stats,
          callgraph: {
            fileCount: result.callgraph.fileCount,
            functionCount: result.callgraph.nodes.length,
            edgeCount: result.callgraph.edges.length,
            isTypedJsProject: result.callgraph.isTypedJsProject,
            typedFilesPct: result.callgraph.typedFilesPct,
          },
        },
        null,
        2,
      ) + '\n',
    );
    return;
  }

  process.stdout.write(JSON.stringify({ flows: result.flows, stats: result.stats }, null, 2) + '\n');
}

main().catch((err) => {
  process.stderr.write(`propagate failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
