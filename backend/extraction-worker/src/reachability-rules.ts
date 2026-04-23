/**
 * Hand-authored Semgrep taint-tracking rules that upgrade matching
 * vulnerabilities to `confirmed` reachability — the highest-priority signal
 * in depscore. See `reachability-rules/README.md` for rule authoring rules.
 *
 * This module is pure plumbing around the Semgrep CLI: discover rule packs
 * on disk, filter them by the set of CVEs detected in the current extraction
 * run, materialise the selected rules into a temp config dir, invoke Semgrep
 * once, and normalise each finding into a `TaintFinding` the pipeline can
 * write into `project_reachable_flows` with `reachability_source='semgrep_taint'`.
 *
 * Callers: pipeline.ts (new `reachability_rules` step) — runs between
 * vuln_scan and the existing SAST Semgrep pass.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';
import * as yaml from 'js-yaml';
import { StepTimeoutError } from './with-timeout';

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

export interface RuleMetadata {
  cve: string;
  package: string;
  ecosystem: string;
  affectedVersions?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  cwe?: string[];
}

export interface LoadedRule {
  rulePath: string;
  ruleId: string;
  metadata: RuleMetadata;
}

export interface TaintFlowStep {
  file: string;
  line: number;
  content: string;
}

export interface TaintFinding {
  cve: string;
  ruleId: string;
  filePath: string;
  sourceLine: number;
  sourceContent: string | null;
  sinkLine: number;
  sinkMethod: string | null;
  sinkContent: string | null;
  flowSteps: TaintFlowStep[];
  rawSemgrepResult: unknown;
}

export interface RunReachabilityRulesArgs {
  workspaceRoot: string;
  rules: LoadedRule[];
  signal?: AbortSignal;
  timeoutMs: number;
  /** Override the semgrep binary (tests). Defaults to `semgrep` on PATH. */
  semgrepBin?: string;
  /** Override for run-scoped temp dir prefix (tests). */
  runId?: string;
}

// -----------------------------------------------------------------------------
// loadAllRules
// -----------------------------------------------------------------------------

/**
 * Scan `rulesDir` for per-CVE rule folders and load each `rule.yml` that has
 * the required metadata (`cve`, `package`, `ecosystem`). Invalid rule files
 * are skipped with a `console.warn` — we never fail the whole step because
 * one rule pack is malformed.
 *
 * Returns one LoadedRule per valid `rules[0]` entry. Multi-rule files are
 * rejected (we require one rule per CVE folder to keep selection tractable).
 */
export async function loadAllRules(rulesDir: string): Promise<LoadedRule[]> {
  if (!fs.existsSync(rulesDir)) return [];

  const entries = fs.readdirSync(rulesDir, { withFileTypes: true });
  const loaded: LoadedRule[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('.') || entry.name.startsWith('_')) continue;
    if (!entry.name.startsWith('CVE-')) continue;

    const rulePath = path.join(rulesDir, entry.name, 'rule.yml');
    if (!fs.existsSync(rulePath)) {
      console.warn(`[reachability-rules] ${entry.name}: rule.yml missing, skipping`);
      continue;
    }

    let parsed: unknown;
    try {
      parsed = yaml.load(fs.readFileSync(rulePath, 'utf8'));
    } catch (err: any) {
      console.warn(`[reachability-rules] ${entry.name}: YAML parse failed — ${err.message}`);
      continue;
    }

    const doc = parsed as { rules?: unknown };
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.rules) || doc.rules.length !== 1) {
      console.warn(`[reachability-rules] ${entry.name}: expected exactly one rule in 'rules:', skipping`);
      continue;
    }

    const rule = doc.rules[0] as { id?: unknown; metadata?: unknown };
    if (typeof rule.id !== 'string' || !rule.id) {
      console.warn(`[reachability-rules] ${entry.name}: rule.id missing, skipping`);
      continue;
    }

    const metadata = normaliseMetadata(rule.metadata);
    if (!metadata) {
      console.warn(`[reachability-rules] ${entry.name}: metadata missing required cve/package/ecosystem, skipping`);
      continue;
    }

    loaded.push({ rulePath, ruleId: rule.id, metadata });
  }

  return loaded;
}

function normaliseMetadata(raw: unknown): RuleMetadata | null {
  if (!raw || typeof raw !== 'object') return null;
  const m = raw as Record<string, unknown>;
  if (typeof m.cve !== 'string' || !m.cve) return null;
  if (typeof m.package !== 'string' || !m.package) return null;
  if (typeof m.ecosystem !== 'string' || !m.ecosystem) return null;

  const out: RuleMetadata = {
    cve: m.cve,
    package: m.package,
    ecosystem: m.ecosystem,
  };
  if (typeof m.affected_versions === 'string') out.affectedVersions = m.affected_versions;
  if (m.confidence === 'HIGH' || m.confidence === 'MEDIUM' || m.confidence === 'LOW') {
    out.confidence = m.confidence;
  }
  if (Array.isArray(m.cwe)) {
    out.cwe = m.cwe.filter((x): x is string => typeof x === 'string');
  }
  return out;
}

// -----------------------------------------------------------------------------
// selectRulesForCves
// -----------------------------------------------------------------------------

/**
 * Keep only rules whose `metadata.cve` is present in `detectedCves`. The
 * pipeline builds that set from `project_dependency_vulnerabilities` for
 * the current run, so a project with zero known CVEs runs zero reachability
 * rules (free).
 */
export function selectRulesForCves(
  allRules: LoadedRule[],
  detectedCves: Set<string>,
): LoadedRule[] {
  if (detectedCves.size === 0) return [];
  return allRules.filter((r) => detectedCves.has(r.metadata.cve));
}

// -----------------------------------------------------------------------------
// runReachabilityRules
// -----------------------------------------------------------------------------

/**
 * Copies each selected rule.yml into a per-run temp dir, then invokes
 * `semgrep scan --config <tmpDir> --json --dataflow-traces <workspaceRoot>`.
 * Semgrep deduplicates findings per (rule, file, start_line) on its own, so
 * we trust its output directly.
 *
 * The temp dir is cleaned up in `finally` regardless of outcome. Aborting
 * `signal` kills the subprocess with SIGTERM; the caller should wrap this in
 * `withTimeout(..., timeoutMs, 'reachability_rules')` so timeouts propagate
 * through the standard StepTimeoutError path.
 */
export async function runReachabilityRules(
  args: RunReachabilityRulesArgs,
): Promise<TaintFinding[]> {
  if (args.rules.length === 0) return [];

  const runId = args.runId ?? `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tmpDir = path.join(os.tmpdir(), `deptex-reach-rules-${runId}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  try {
    // Semgrep requires globally-unique rule IDs within a single invocation.
    // Our ID convention is `deptex.<package>.<short>` so collisions shouldn't
    // happen, but detect them early with a clear error instead of a cryptic
    // Semgrep failure.
    const seen = new Set<string>();
    for (const rule of args.rules) {
      if (seen.has(rule.ruleId)) {
        throw new Error(`Duplicate Semgrep rule id across selected rules: ${rule.ruleId}`);
      }
      seen.add(rule.ruleId);
      // Use CVE + package as filename so concurrent runs on the same host
      // (dev + test, e2e + smoke) don't clobber each other's temp files.
      const safeSlug = `${rule.metadata.cve}-${rule.metadata.package}`.replace(/[^A-Za-z0-9._-]/g, '_');
      const dest = path.join(tmpDir, `${safeSlug}.yml`);
      fs.copyFileSync(rule.rulePath, dest);
    }

    const rulesById = new Map(args.rules.map((r) => [r.ruleId, r] as const));
    const semgrepJson = await invokeSemgrep({
      semgrepBin: args.semgrepBin ?? 'semgrep',
      configDir: tmpDir,
      workspaceRoot: args.workspaceRoot,
      signal: args.signal,
      timeoutMs: args.timeoutMs,
    });

    return parseTaintOutput(semgrepJson, rulesById);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* non-fatal */
    }
  }
}

interface InvokeSemgrepArgs {
  semgrepBin: string;
  configDir: string;
  workspaceRoot: string;
  signal?: AbortSignal;
  timeoutMs: number;
}

async function invokeSemgrep(args: InvokeSemgrepArgs): Promise<unknown> {
  return await new Promise<unknown>((resolve, reject) => {
    const child = spawn(
      args.semgrepBin,
      [
        'scan',
        '--config',
        args.configDir,
        '--json',
        '--dataflow-traces',
        '--no-git-ignore',
        '--metrics=off',
        '--quiet',
        args.workspaceRoot,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutLen = 0;
    // Semgrep JSON for a handful of rules across a user repo is routinely
    // a few MB. Guard against runaway output pinning the worker's heap —
    // 128 MB is generous but finite.
    const MAX_STDOUT = 128 * 1024 * 1024;
    let truncated = false;

    child.stdout.on('data', (chunk: Buffer) => {
      if (truncated) return;
      stdoutLen += chunk.length;
      if (stdoutLen > MAX_STDOUT) {
        truncated = true;
        try {
          child.kill('SIGTERM');
        } catch {
          /* swallow */
        }
        return;
      }
      stdoutChunks.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

    const onAbort = () => {
      try {
        child.kill('SIGTERM');
      } catch {
        /* swallow */
      }
    };
    if (args.signal) {
      if (args.signal.aborted) {
        onAbort();
      } else {
        args.signal.addEventListener('abort', onAbort, { once: true });
      }
    }

    child.on('error', (err) => {
      if (args.signal) args.signal.removeEventListener('abort', onAbort);
      reject(err);
    });

    child.on('close', (code) => {
      if (args.signal) args.signal.removeEventListener('abort', onAbort);
      if (truncated) {
        reject(new Error(`Semgrep reachability output exceeded ${MAX_STDOUT} bytes, aborting`));
        return;
      }
      // Semgrep exits non-zero when it finds matches — we specifically care
      // about exit 0 (no matches) and exit 1 (matches found). Anything else
      // is a real failure (bad config, crashed engine, killed).
      if (code !== 0 && code !== 1) {
        const stderr = Buffer.concat(stderrChunks).toString('utf8').slice(0, 4000);
        reject(
          new Error(
            `Semgrep exited with code ${code}${stderr ? ` — ${stderr}` : ''}`,
          ),
        );
        return;
      }
      try {
        const body = Buffer.concat(stdoutChunks).toString('utf8');
        resolve(body.length === 0 ? { results: [] } : JSON.parse(body));
      } catch (err: any) {
        reject(new Error(`Failed to parse Semgrep JSON: ${err.message}`));
      }
    });
  });
}

// -----------------------------------------------------------------------------
// parseTaintOutput
// -----------------------------------------------------------------------------

/**
 * Normalise Semgrep's JSON output (with `--dataflow-traces`) into TaintFinding
 * rows. Anything Semgrep emits that we can't attribute back to a known rule id
 * is dropped silently — that usually means the user's workspace had another
 * semgrep config checked in and our subprocess picked it up; not our concern.
 */
export function parseTaintOutput(
  semgrepJson: unknown,
  rulesById: Map<string, LoadedRule>,
): TaintFinding[] {
  if (!semgrepJson || typeof semgrepJson !== 'object') return [];
  const results = (semgrepJson as { results?: unknown }).results;
  if (!Array.isArray(results)) return [];

  const findings: TaintFinding[] = [];
  for (const raw of results) {
    const finding = normaliseOneFinding(raw, rulesById);
    if (finding) findings.push(finding);
  }
  return findings;
}

function normaliseOneFinding(
  raw: unknown,
  rulesById: Map<string, LoadedRule>,
): TaintFinding | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, any>;

  const ruleId = typeof r.check_id === 'string' ? r.check_id : null;
  if (!ruleId) return null;
  const rule = rulesById.get(ruleId);
  if (!rule) return null;

  const filePath = typeof r.path === 'string' ? r.path : null;
  if (!filePath) return null;

  const sinkLine = toInt(r.start?.line);
  if (sinkLine === null) return null;

  const sinkContent = typeof r.extra?.lines === 'string' ? r.extra.lines : null;

  // Semgrep's --dataflow-traces emits taint_source/intermediate_vars/taint_sink
  // inside extra.dataflow_trace. Source CAN be missing if Semgrep widens a
  // non-taint pattern into the sink, but for `mode: taint` rules it should
  // always be populated. Fall back to the sink location so we never lose the
  // finding.
  const trace = r.extra?.dataflow_trace as
    | {
        taint_source?: unknown;
        intermediate_vars?: unknown[];
        taint_sink?: unknown;
      }
    | undefined;

  const source = extractTraceStep(trace?.taint_source) ?? {
    file: filePath,
    line: sinkLine,
    content: sinkContent ?? '',
  };
  const sinkStep = extractTraceStep(trace?.taint_sink);

  const intermediate: TaintFlowStep[] = [];
  if (Array.isArray(trace?.intermediate_vars)) {
    for (const step of trace!.intermediate_vars!) {
      const normalised = extractTraceStep(step);
      if (normalised) intermediate.push(normalised);
    }
  }

  // Sink method is best-effort: parse out the primary function from the
  // highlighted line. Semgrep doesn't hand us the function name directly.
  const sinkMethod = sinkStep?.content ? extractCalleeName(sinkStep.content) : extractCalleeName(sinkContent ?? '');

  return {
    cve: rule.metadata.cve,
    ruleId,
    filePath,
    sourceLine: source.line,
    sourceContent: source.content || null,
    sinkLine,
    sinkMethod,
    sinkContent,
    flowSteps: intermediate,
    rawSemgrepResult: raw,
  };
}

function extractTraceStep(raw: unknown): TaintFlowStep | null {
  if (!raw) return null;
  // Semgrep's trace nodes are shaped like:
  //   [{ "location": { "path": "...", "start": { "line": N }, "end": ... } }, "content..."]
  // or { location: {...}, content: "..." } — normalise both shapes.
  if (Array.isArray(raw)) {
    const loc = raw[0]?.location;
    const content = typeof raw[1] === 'string' ? raw[1] : '';
    const line = toInt(loc?.start?.line);
    const file = typeof loc?.path === 'string' ? loc.path : null;
    if (line === null || !file) return null;
    return { file, line, content };
  }
  if (typeof raw === 'object') {
    const o = raw as Record<string, any>;
    const loc = o.location ?? o;
    const line = toInt(loc?.start?.line);
    const file = typeof loc?.path === 'string' ? loc.path : null;
    const content = typeof o.content === 'string' ? o.content : '';
    if (line === null || !file) return null;
    return { file, line, content };
  }
  return null;
}

function toInt(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === 'string' && /^\d+$/.test(v)) return parseInt(v, 10);
  return null;
}

/**
 * Best-effort: extract the callee name from a highlighted source line. The
 * rule's `pattern-sinks` already encodes which call we matched, but Semgrep
 * doesn't thread that identifier through the JSON output — we scrape it back
 * out of the line text so the DB row has a meaningful `sink_method`.
 */
function extractCalleeName(line: string): string | null {
  if (!line) return null;
  const match = line.match(/([A-Za-z_][\w.]*?)\s*\(/);
  return match ? match[1] : null;
}

// -----------------------------------------------------------------------------
// StepTimeoutError is re-exported so callers only need to import this module.
// -----------------------------------------------------------------------------

export { StepTimeoutError };
