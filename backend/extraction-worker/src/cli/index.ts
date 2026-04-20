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
import { renderFindingsTable, renderRollup, c, type TableVuln } from './format';

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
  --format=<fmt>        Output format: table (default, tty) or json (default, non-tty)
  --verbose             Show info-level step chatter
  --quiet               Suppress everything except warnings + errors
  --no-color            Disable ANSI color output (NO_COLOR env also respected)
  -h, --help            Print this help

Exit codes:
  0 = no findings above threshold
  1 = findings at or above --fail-on severity
  2 = pipeline error (crash, missing binary, invalid args)
`;

async function main(argv: string[]): Promise<number> {
  // Signal to other pipeline modules (ast-parser, reachability, pipeline) that
  // they should suppress raw console.log chatter in favor of the structured
  // ExtractionLogger output.
  process.env.DEPTEX_CLI_MODE = '1';

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
        format: { type: 'string' },
        quiet: { type: 'boolean' },
        verbose: { type: 'boolean' },
        'no-color': { type: 'boolean' },
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
  const formatArg = (parsed.values.format ?? '').toLowerCase();
  const isTTY = !!process.stdout.isTTY;
  const format: 'table' | 'json' =
    formatArg === 'json' ? 'json' : formatArg === 'table' ? 'table' : isTTY ? 'table' : 'json';
  if (formatArg && formatArg !== 'table' && formatArg !== 'json') {
    process.stderr.write(`error: --format must be 'table' or 'json' (got '${formatArg}')\n`);
    return 2;
  }

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
      verbose: !!parsed.values.verbose,
      quiet: !!parsed.values.quiet,
    });

    if (format === 'json') {
      process.stdout.write(
        JSON.stringify(
          {
            summary: result.summary,
            vulns: result.vulns,
            deps: result.deps,
            semgrep: result.semgrep,
            secrets: result.secrets,
          },
          null,
          2,
        ) + '\n',
      );
    } else {
      renderTableReport(result);
    }
    return result.exitCode;
  } catch (e: any) {
    process.stderr.write(`[scan] pipeline error: ${e.message}\n`);
    if (process.env.DEPTEX_DEBUG === '1' && e.stack) {
      process.stderr.write(`${e.stack}\n`);
    }
    return 2;
  }
}

function renderTableReport(result: Awaited<ReturnType<typeof runScan>>): void {
  const { summary, vulns, deps, semgrep, secrets } = result;

  // Build package lookup from project_dependencies
  const depById = new Map<string, { name: string; version: string }>();
  for (const d of deps) {
    if (d?.id) depById.set(d.id, { name: d.name ?? '?', version: d.version ?? '?' });
  }

  const rows: TableVuln[] = vulns.map((v: any) => {
    const dep = v.project_dependency_id ? depById.get(v.project_dependency_id) : undefined;
    return {
      osv_id: v.osv_id ?? 'UNKNOWN',
      severity: v.severity ?? 'unknown',
      package_name: dep?.name ?? '?',
      package_version: dep?.version ?? '?',
      depscore: typeof v.depscore === 'number' ? v.depscore : Number(v.depscore) || null,
      is_reachable: !!v.is_reachable,
      reachability_level: v.reachability_level ?? null,
      summary: v.summary ?? '',
    };
  });

  const counts = {
    total: rows.length,
    critical: rows.filter((r) => r.severity?.toLowerCase() === 'critical').length,
    high: rows.filter((r) => r.severity?.toLowerCase() === 'high').length,
    medium: rows.filter((r) => ['medium', 'moderate'].includes(r.severity?.toLowerCase())).length,
    low: rows.filter((r) => r.severity?.toLowerCase() === 'low').length,
    reachable: rows.filter((r) => r.is_reachable).length,
    durationMs: summary.duration_ms,
  };

  process.stdout.write('\n');
  process.stdout.write(c.bold(`${summary.project_name}`) + c.gray(`  ·  ${summary.ecosystem}  ·  ${summary.dependencies_count} deps`) + '\n\n');
  process.stdout.write(renderFindingsTable(rows));
  process.stdout.write('\n' + renderRollup(counts) + '\n');

  const extras: string[] = [];
  if (semgrep.length > 0) extras.push(c.yellow(`${semgrep.length} SAST finding${semgrep.length === 1 ? '' : 's'}`));
  if (secrets.length > 0) extras.push(c.red(`${secrets.length} secret${secrets.length === 1 ? '' : 's'}`));
  if (extras.length > 0) {
    process.stdout.write(extras.join(c.gray(' · ')) + '\n');
  }
  process.stdout.write('\n');
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((e) => {
    process.stderr.write(`fatal: ${e.stack ?? e.message ?? e}\n`);
    process.exit(2);
  });
