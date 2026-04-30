import { runScannerSubprocess, type ScannerSubprocessLogger } from '../with-timeout';
import type { IaCFinding, IaCFramework } from './types';

const CHECKOV_BC_RULE_RE = /^checkov:CKV[A-Z0-9_]+:[\w./@\-+:#=,]+$/;

interface CheckovRawCheck {
  check_id?: string;
  bc_check_id?: string;
  check_name?: string;
  resource?: string;
  resource_address?: string;
  file_path?: string;
  file_line_range?: [number, number];
  severity?: string | null;
  guideline?: string | null;
  details?: string[] | null;
  description?: string | null;
  short_description?: string | null;
  code_block?: Array<[number, string]>;
  metadata?: Record<string, unknown>;
  check_type?: string;
}

interface CheckovRawReport {
  check_type?: string;
  results?: {
    failed_checks?: CheckovRawCheck[];
  };
}

const CHECK_TYPE_TO_FRAMEWORK: Record<string, IaCFramework> = {
  terraform: 'terraform',
  terraform_plan: 'terraform',
  kubernetes: 'kubernetes',
  dockerfile: 'dockerfile',
};

function frameworkOf(raw: CheckovRawCheck, reportType: string | undefined): IaCFramework | null {
  const key = (raw.check_type ?? reportType ?? '').toLowerCase();
  return CHECK_TYPE_TO_FRAMEWORK[key] ?? null;
}

function buildFingerprint(raw: CheckovRawCheck): string | null {
  // Prefer Checkov's canonical CKV_* check_id over the BridgeCrew-mapped
  // bc_check_id. Real Checkov output sets these to different prefixes
  // (CKV_AWS_145 vs BC_AWS_GENERAL_56); only CKV_* satisfies the regex below.
  const ruleId = raw.check_id ?? raw.bc_check_id;
  const target = raw.resource_address || raw.resource;
  if (!ruleId || !target) return null;
  const fp = `checkov:${ruleId}:${target}`;
  // Validate the fingerprint shape so a parser regression that drops chunks of
  // the resource address can't silently emit a degenerate `checkov:CKV::` value
  // that would still satisfy the partial-UNIQUE index.
  if (!CHECKOV_BC_RULE_RE.test(fp)) return null;
  return fp;
}

function snippet(raw: CheckovRawCheck): string | null {
  if (!raw.code_block || raw.code_block.length === 0) return null;
  return raw.code_block.map(([, line]) => line).join('').trimEnd() || null;
}

function normalizeSeverity(raw: CheckovRawCheck): string | null {
  if (!raw.severity) return null;
  const upper = String(raw.severity).toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(upper)) return upper;
  return null;
}

function parseSingleReport(report: CheckovRawReport, version: string): IaCFinding[] {
  const checks = report.results?.failed_checks ?? [];
  const out: IaCFinding[] = [];
  for (const c of checks) {
    const framework = frameworkOf(c, report.check_type);
    if (!framework) continue;
    const ruleId = c.check_id ?? c.bc_check_id;
    if (!ruleId) continue;
    const filePath = (c.file_path ?? '').replace(/^\//, '');
    if (!filePath) continue;
    const range = c.file_line_range ?? [null, null];
    const startLine = typeof range[0] === 'number' ? range[0] : null;
    const endLine = typeof range[1] === 'number' ? range[1] : null;

    out.push({
      scanner: 'checkov',
      scanner_version: version,
      rule_id: ruleId,
      framework,
      file_path: filePath,
      start_line: startLine,
      end_line: endLine,
      severity: normalizeSeverity(c),
      message: c.check_name ?? c.short_description ?? null,
      description:
        c.description ??
        (Array.isArray(c.details) ? c.details.join('\n') : null) ??
        null,
      cwe_ids: [],
      code_snippet: snippet(c),
      rule_doc_url: c.guideline ?? null,
      iac_fingerprint: buildFingerprint(c),
      metadata: c.metadata ?? null,
    });
  }
  return out;
}

/**
 * Parse Checkov's `-o json` output. Checkov emits either a single report
 * object or a JSON array of per-framework reports depending on how many
 * frameworks fired — both shapes are handled.
 */
export function parseCheckovOutput(stdout: string, version: string): IaCFinding[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  if (Array.isArray(parsed)) {
    return parsed.flatMap((r) => parseSingleReport(r as CheckovRawReport, version));
  }
  if (parsed && typeof parsed === 'object') {
    return parseSingleReport(parsed as CheckovRawReport, version);
  }
  return [];
}

export interface RunCheckovOptions {
  repoPath: string;
  frameworks: IaCFramework[];
  signal?: AbortSignal;
  onHeartbeat?: () => Promise<void> | void;
  timeoutMs?: number;
  logger?: ScannerSubprocessLogger;
  verboseLog?: boolean;
}

const FRAMEWORK_TO_CHECKOV: Record<IaCFramework, string> = {
  terraform: 'terraform',
  kubernetes: 'kubernetes',
  dockerfile: 'dockerfile',
};

export async function runCheckov(
  opts: RunCheckovOptions
): Promise<{ findings: IaCFinding[]; version: string; warnings: string[] }> {
  const warnings: string[] = [];
  const checkovFrameworks = opts.frameworks
    .map((f) => FRAMEWORK_TO_CHECKOV[f])
    .filter(Boolean);

  if (checkovFrameworks.length === 0) {
    return { findings: [], version: '', warnings: ['no_supported_frameworks_for_checkov'] };
  }

  // Capture version. `checkov --version` returns just the version on stdout.
  let version = 'unknown';
  try {
    const v = await runScannerSubprocess({
      exe: 'checkov',
      args: ['--version'],
      timeoutMs: 10_000,
    });
    version = v.stdout.trim() || version;
  } catch {
    // non-fatal — version is metadata only
  }

  const args = [
    '-d',
    opts.repoPath,
    '--framework',
    checkovFrameworks.join(','),
    '-o',
    'json',
    '--quiet',
    '--skip-download',
  ];

  const result = await runScannerSubprocess({
    exe: 'checkov',
    args,
    cwd: opts.repoPath,
    signal: opts.signal,
    onHeartbeat: opts.onHeartbeat,
    logger: opts.logger,
    verboseLog: opts.verboseLog,
    verboseLogStep: 'iac_scan',
  });

  // Checkov uses non-zero exit codes to signal "findings found" — treat 0 and
  // 1 as success and parse stdout. Any other code is a real failure.
  if (result.exitCode !== 0 && result.exitCode !== 1) {
    warnings.push(`checkov_exit_${result.exitCode}`);
    return { findings: [], version: `checkov@${version}`, warnings };
  }

  const findings = parseCheckovOutput(result.stdout, `checkov@${version}`);
  return { findings, version: `checkov@${version}`, warnings };
}
