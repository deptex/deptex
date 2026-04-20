#!/usr/bin/env node
/**
 * deptex-scan — local-mode extraction worker CLI.
 *
 * Usage:
 *   deptex-scan run <path> [options]
 *
 * Options:
 *   --output=<dir>        Where to write summary.json + per-finding JSON files
 *                         (default: ./extraction-results)
 *   --ecosystem=<name>    Force ecosystem (npm|pypi|maven|golang|cargo|gem|composer)
 *                         (default: auto-detect from manifest files)
 *   --severity=<list>     Comma-separated filter (e.g. --severity=high,critical)
 *   --fail-on=<sev>       Exit 1 if any finding has severity >= <sev>
 *   --label=<name>        Project label in outputs (default: basename of <path>)
 *   --quiet               Suppress per-step progress output
 *   -h, --help            Print this help
 *
 * Exit codes: 0 = clean, 1 = findings above --fail-on, 2 = pipeline error.
 */

import { parseArgs } from 'node:util';
import { runScan } from './scan';
import type { Ecosystem } from './ecosystem';

const HELP = `deptex-scan — local-mode extraction worker CLI

Usage:
  deptex-scan run <path> [options]

Options:
  --output=<dir>        Where to write summary.json + per-finding JSON files
                        (default: ./extraction-results)
  --ecosystem=<name>    Force ecosystem (npm|pypi|maven|golang|cargo|gem|composer)
  --severity=<list>     Comma-separated filter (e.g. --severity=high,critical)
  --fail-on=<sev>       Exit 1 if any finding has severity >= <sev>
  --label=<name>        Project label in outputs
  --quiet               Suppress per-step progress output
  -h, --help            Print this help

Exit codes:
  0 = no findings above threshold
  1 = findings at or above --fail-on severity
  2 = pipeline error (crash, missing binary, invalid args)
`;

async function main(argv: string[]): Promise<number> {
  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help') {
    process.stdout.write(HELP);
    return 0;
  }

  const [subcommand, ...rest] = argv;

  if (subcommand !== 'run') {
    process.stderr.write(`unknown subcommand: ${subcommand}\n\n${HELP}`);
    return 2;
  }

  let parsed;
  try {
    parsed = parseArgs({
      args: rest,
      options: {
        output: { type: 'string' },
        ecosystem: { type: 'string' },
        severity: { type: 'string' },
        'fail-on': { type: 'string' },
        label: { type: 'string' },
        quiet: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
      allowPositionals: true,
    });
  } catch (e: any) {
    process.stderr.write(`argument error: ${e.message}\n\n${HELP}`);
    return 2;
  }

  if (parsed.values.help) {
    process.stdout.write(HELP);
    return 0;
  }

  const workspacePath = parsed.positionals[0];
  if (!workspacePath) {
    process.stderr.write(`error: missing <path>\n\n${HELP}`);
    return 2;
  }

  const ecosystemArg = parsed.values.ecosystem;
  const severitiesArg = parsed.values.severity;

  try {
    const result = await runScan({
      workspacePath,
      outputDir: parsed.values.output ?? './extraction-results',
      ecosystem: ecosystemArg ? (ecosystemArg as Ecosystem) : undefined,
      severities: severitiesArg
        ? severitiesArg.split(',').map((s) => s.trim()).filter(Boolean)
        : undefined,
      failOn: parsed.values['fail-on'] ?? null,
      label: parsed.values.label,
      verbose: !parsed.values.quiet,
    });

    // Always print a one-line summary so CI logs show what happened.
    const s = result.summary;
    process.stdout.write(
      `[scan] done — deps=${s.dependencies_count} vulns=${s.vulnerabilities_count} ` +
        `semgrep=${s.semgrep_count} secrets=${s.secrets_count} ` +
        `flows=${s.reachable_flows_count} (${s.duration_ms}ms)\n`,
    );
    return result.exitCode;
  } catch (e: any) {
    process.stderr.write(`[scan] pipeline error: ${e.message}\n`);
    if (process.env.DEPTEX_DEBUG === '1' && e.stack) {
      process.stderr.write(`${e.stack}\n`);
    }
    return 2;
  }
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((e) => {
    process.stderr.write(`fatal: ${e.stack ?? e.message ?? e}\n`);
    process.exit(2);
  });
