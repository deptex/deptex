/**
 * Terminal output helpers — ANSI colors (auto-disabled), log formatting,
 * findings table renderer. Trivy/OSV-Scanner-flavored output.
 *
 * No dependencies. Columns are fixed; manual ASCII rendering is enough.
 */

import type { LogLevel, LogStep } from '../logger';

const FORCE_NO_COLOR =
  process.env.NO_COLOR !== undefined ||
  process.env.DEPTEX_NO_COLOR === '1' ||
  process.argv.includes('--no-color');

export const colorsEnabled = (): boolean =>
  !FORCE_NO_COLOR && !!process.stdout.isTTY;

function wrap(code: number, close: number = 39): (s: string) => string {
  return (s: string) => (colorsEnabled() ? `\x1b[${code}m${s}\x1b[${close}m` : s);
}

export const c = {
  dim: wrap(2, 22),
  bold: wrap(1, 22),
  red: wrap(31),
  green: wrap(32),
  yellow: wrap(33),
  blue: wrap(34),
  magenta: wrap(35),
  cyan: wrap(36),
  gray: wrap(90),
  bgRed: wrap(41, 49),
  bgYellow: wrap(43, 49),
  bgBlue: wrap(44, 49),
  bgGreen: wrap(42, 49),
  bgGray: wrap(100, 49),
};

/** strip ANSI codes for width measurement */
const ANSI_RE = /\x1b\[[0-9;]*m/g;
export const visibleLen = (s: string): number => s.replace(ANSI_RE, '').length;

function pad(s: string, width: number, align: 'left' | 'right' = 'left'): string {
  const len = visibleLen(s);
  if (len >= width) return s;
  const padding = ' '.repeat(width - len);
  return align === 'right' ? padding + s : s + padding;
}

function truncate(s: string, width: number): string {
  if (visibleLen(s) <= width) return s;
  if (width <= 1) return s.slice(0, width);
  return s.slice(0, Math.max(0, width - 1)) + '…';
}

// ───────────── log formatting ─────────────

const STEP_DISPLAY: Record<string, string> = {
  semgrep: 'sast',
  trufflehog: 'secrets',
  vuln_scan: 'vulns',
  depscan: 'vulns',
  ast_parsing: 'ast',
  deps_sync: 'deps',
  cloning: 'clone',
  clone: 'clone',
};

const LEVEL_GLYPH: Record<LogLevel, string> = {
  info: 'ℹ',
  success: '✓',
  warning: '⚠',
  error: '✖',
};

const LEVEL_COLOR: Record<LogLevel, (s: string) => string> = {
  info: c.cyan,
  success: c.green,
  warning: c.yellow,
  error: c.red,
};

export function formatLogLine(
  message: string,
  level: LogLevel,
  step: LogStep,
  opts: { verbose?: boolean; quiet?: boolean } = {},
): string | null {
  // Default (neither verbose nor quiet): show success + warn + error.
  //   - info is demoted to verbose-only (step-start chatter is too noisy).
  // --verbose: show all levels.
  // --quiet: only warn + error.
  if (opts.quiet && level !== 'warning' && level !== 'error') return null;
  if (!opts.verbose && level === 'info') return null;

  const label = STEP_DISPLAY[step] ?? step;
  const glyph = LEVEL_GLYPH[level];
  const color = LEVEL_COLOR[level];
  return `${color(glyph)} ${c.gray(`[${label}]`)} ${message}`;
}

// ───────────── severity badges ─────────────

const SEVERITY_BADGE: Record<string, (s: string) => string> = {
  critical: (s) => c.bold(c.bgRed(c.yellow(` ${s} `))),
  high: (s) => c.bold(c.bgRed(` ${s} `)),
  medium: (s) => c.bold(c.bgYellow(` ${s} `)),
  moderate: (s) => c.bold(c.bgYellow(` ${s} `)),
  low: (s) => c.bold(c.bgBlue(` ${s} `)),
  info: (s) => c.bold(c.bgGray(` ${s} `)),
  unknown: (s) => c.bold(c.bgGray(` ${s} `)),
};

function renderSeverity(sev: string): string {
  const key = (sev ?? 'unknown').toLowerCase();
  const word = key === 'moderate' ? 'MED' : key.slice(0, 4).toUpperCase();
  const badge = SEVERITY_BADGE[key] ?? SEVERITY_BADGE.unknown;
  return badge(word.padEnd(4));
}

// ───────────── findings table ─────────────

export interface TableVuln {
  osv_id: string;
  severity: string;
  package_name: string;
  package_version: string;
  depscore: number | null;
  is_reachable: boolean;
  reachability_level: string | null;
  summary: string;
}

export function renderFindingsTable(rows: TableVuln[]): string {
  if (rows.length === 0) {
    return c.green('✓ No vulnerabilities found.') + '\n';
  }

  // Sort by depscore desc, nulls last.
  const sorted = [...rows].sort((a, b) => {
    const av = a.depscore ?? -1;
    const bv = b.depscore ?? -1;
    return bv - av;
  });

  const termWidth = process.stdout.columns && process.stdout.columns > 80
    ? process.stdout.columns
    : 120;

  // Column widths — fixed except summary which absorbs remainder.
  const W = {
    sev: 6,
    score: 5,
    id: 18,
    pkg: 30,
    reach: 9,
  };
  const used = W.sev + W.score + W.id + W.pkg + W.reach + 5 * 3; // 5 separators (" │ ")
  const summaryW = Math.max(20, termWidth - used - 2);

  const header =
    pad(c.bold('SEV'), W.sev) +
    c.gray(' │ ') +
    pad(c.bold('SCORE'), W.score, 'right') +
    c.gray(' │ ') +
    pad(c.bold('ID'), W.id) +
    c.gray(' │ ') +
    pad(c.bold('PACKAGE'), W.pkg) +
    c.gray(' │ ') +
    pad(c.bold('REACH'), W.reach) +
    c.gray(' │ ') +
    c.bold('SUMMARY');

  const sep =
    c.gray('─'.repeat(W.sev)) +
    c.gray('─┼─') +
    c.gray('─'.repeat(W.score)) +
    c.gray('─┼─') +
    c.gray('─'.repeat(W.id)) +
    c.gray('─┼─') +
    c.gray('─'.repeat(W.pkg)) +
    c.gray('─┼─') +
    c.gray('─'.repeat(W.reach)) +
    c.gray('─┼─') +
    c.gray('─'.repeat(summaryW));

  const lines: string[] = [header, sep];
  for (const v of sorted) {
    const reach = v.is_reachable
      ? c.yellow(v.reachability_level ?? 'yes')
      : c.gray('no');
    const score = v.depscore != null ? String(v.depscore) : '—';
    const pkg = `${v.package_name}@${v.package_version}`;

    lines.push(
      pad(renderSeverity(v.severity), W.sev) +
        c.gray(' │ ') +
        pad(score, W.score, 'right') +
        c.gray(' │ ') +
        pad(truncate(v.osv_id, W.id), W.id) +
        c.gray(' │ ') +
        pad(truncate(pkg, W.pkg), W.pkg) +
        c.gray(' │ ') +
        pad(truncate(reach, W.reach), W.reach) +
        c.gray(' │ ') +
        truncate(v.summary ?? '', summaryW),
    );
  }
  return lines.join('\n') + '\n';
}

export interface RollupCounts {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  reachable: number;
  durationMs: number;
}

export function renderRollup(r: RollupCounts): string {
  const parts: string[] = [];
  if (r.critical > 0) parts.push(c.red(`${r.critical} critical`));
  if (r.high > 0) parts.push(c.red(`${r.high} high`));
  if (r.medium > 0) parts.push(c.yellow(`${r.medium} medium`));
  if (r.low > 0) parts.push(c.blue(`${r.low} low`));
  const severityBlurb = parts.length > 0 ? ` (${parts.join(', ')})` : '';
  const reachBlurb =
    r.reachable > 0 ? c.yellow(` · ${r.reachable} reachable`) : '';
  const secs = (r.durationMs / 1000).toFixed(1);
  return `${c.bold(`${r.total} vulnerabilities`)}${severityBlurb}${reachBlurb} ${c.gray(`· ${secs}s`)}`;
}
