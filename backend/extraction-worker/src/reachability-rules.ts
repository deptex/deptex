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

/**
 * One of the EPD entry-point classes the reachability rule's source is
 * meant to model. Mirrors `EntryPointClassification` in `epd.ts`. Optional
 * — defaults to `PUBLIC_UNAUTH` because every shipped Phase 3 rule pack
 * traces HTTP-request input or env-var-as-attacker-input, which both
 * conservatively map to a public unauthenticated entry point. Override
 * in rule.yml as `metadata.entry_point_class: OFFLINE_WORKER` for rules
 * whose taint sources are background-job-only (e.g. cron payloads).
 */
export type RuleEntryPointClass = 'PUBLIC_UNAUTH' | 'AUTH_INTERNAL' | 'OFFLINE_WORKER';

export interface RuleMetadata {
  cve: string;
  package: string;
  ecosystem: string;
  affectedVersions?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  cwe?: string[];
  entryPointClass?: RuleEntryPointClass;
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

export interface SkippedRule {
  folder: string;
  reason: string;
}

export interface LoadAllRulesResult {
  loaded: LoadedRule[];
  skipped: SkippedRule[];
}

/** Truncate flow content strings to cap project_reachable_flows row size. */
const MAX_CONTENT_BYTES = 2 * 1024;
/** Cap intermediate dataflow steps per finding to avoid pathological traces. */
const MAX_INTERMEDIATE_STEPS = 50;

// -----------------------------------------------------------------------------
// loadAllRules
// -----------------------------------------------------------------------------

/**
 * Scan `rulesDir` for per-CVE rule folders and load each `rule.yml` that has
 * the required metadata (`cve`, `package`, `ecosystem`). Invalid rule files
 * are skipped and returned in `skipped` so the caller can surface them to
 * `extraction_logs`. We never fail the whole step because one rule pack is
 * malformed, but skips must not be silent — the caller is responsible for
 * logging them.
 *
 * Returns one LoadedRule per valid `rules[0]` entry. Multi-rule files are
 * rejected (we require one rule per CVE folder to keep selection tractable).
 *
 * Back-compat wrapper `loadAllRules` returns just the `loaded` array; new
 * callers should prefer `loadAllRulesWithSkipped` so drops are observable.
 */
export async function loadAllRulesWithSkipped(rulesDir: string): Promise<LoadAllRulesResult> {
  if (!fs.existsSync(rulesDir)) return { loaded: [], skipped: [] };

  const entries = fs.readdirSync(rulesDir, { withFileTypes: true });
  const loaded: LoadedRule[] = [];
  const skipped: SkippedRule[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('.') || entry.name.startsWith('_')) continue;
    if (!entry.name.startsWith('CVE-')) continue;

    const rulePath = path.join(rulesDir, entry.name, 'rule.yml');
    if (!fs.existsSync(rulePath)) {
      skipped.push({ folder: entry.name, reason: 'rule.yml missing' });
      continue;
    }

    let parsed: unknown;
    try {
      parsed = yaml.load(fs.readFileSync(rulePath, 'utf8'));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      skipped.push({ folder: entry.name, reason: `YAML parse failed: ${msg}` });
      continue;
    }

    const doc = parsed as { rules?: unknown };
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.rules) || doc.rules.length !== 1) {
      skipped.push({ folder: entry.name, reason: "expected exactly one rule in 'rules:'" });
      continue;
    }

    const firstRule = doc.rules[0];
    if (!firstRule || typeof firstRule !== 'object') {
      skipped.push({ folder: entry.name, reason: 'rules[0] is not an object' });
      continue;
    }
    const rule = firstRule as { id?: unknown; metadata?: unknown };
    if (typeof rule.id !== 'string' || !rule.id) {
      skipped.push({ folder: entry.name, reason: 'rule.id missing' });
      continue;
    }

    const metadata = normaliseMetadata(rule.metadata);
    if (!metadata) {
      skipped.push({ folder: entry.name, reason: 'metadata missing cve/package/ecosystem' });
      continue;
    }

    loaded.push({ rulePath, ruleId: rule.id, metadata });
  }

  return { loaded, skipped };
}

/** Back-compat: returns the loaded rules only. Prefer loadAllRulesWithSkipped. */
export async function loadAllRules(rulesDir: string): Promise<LoadedRule[]> {
  const { loaded } = await loadAllRulesWithSkipped(rulesDir);
  return loaded;
}

// -----------------------------------------------------------------------------
// loadOrgGeneratedRules
// -----------------------------------------------------------------------------

/**
 * Loads an organization's enabled + validated AI-generated reachability rules
 * from the DB and materializes each `rule_yaml` to a file in `tmpDir` so the
 * Semgrep invocation can treat platform-shipped folder rules and DB rules
 * uniformly. The caller owns the lifecycle of `tmpDir`.
 *
 * Phase 5 (rule generation): rows live in `organization_generated_rules`.
 * Only rules with `enabled=true` AND `validation_status IN ('validated',
 * 'manual_override')` are loaded — pending and failed_validation rules are
 * intentionally excluded so a half-generated or ill-formed rule never lands
 * in a customer scan.
 */
export interface OrgRuleRow {
  id: string;
  cve_id: string;
  package_purl: string;
  ecosystem: string;
  affected_version_range: string | null;
  rule_yaml: string;
  entry_point_class: string | null;
}

export async function loadOrgGeneratedRules(
  orgId: string,
  supabase: { from: (table: string) => any },
  tmpDir: string,
): Promise<LoadAllRulesResult> {
  const loaded: LoadedRule[] = [];
  const skipped: SkippedRule[] = [];

  const { data, error } = await supabase
    .from('organization_generated_rules')
    .select('id, cve_id, package_purl, ecosystem, affected_version_range, rule_yaml, entry_point_class')
    .eq('organization_id', orgId)
    .eq('enabled', true)
    .in('validation_status', ['validated', 'manual_override']);

  if (error) {
    // Phase 25 migration not applied → return empty so the pipeline keeps
    // running with platform rules only. The caller is expected to surface
    // the error via extraction_logs at warn-level.
    skipped.push({ folder: '<db>', reason: `DB load failed: ${(error as { message?: string }).message ?? 'unknown'}` });
    return { loaded, skipped };
  }

  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });

  for (const row of (data ?? []) as OrgRuleRow[]) {
    let parsed: unknown;
    try {
      parsed = yaml.load(row.rule_yaml);
    } catch (err) {
      skipped.push({ folder: `org/${row.id}`, reason: `YAML parse failed: ${err instanceof Error ? err.message : String(err)}` });
      continue;
    }
    const doc = parsed as { rules?: unknown };
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.rules) || doc.rules.length !== 1) {
      skipped.push({ folder: `org/${row.id}`, reason: "expected exactly one rule under 'rules:'" });
      continue;
    }
    const rule = doc.rules[0] as { id?: unknown; metadata?: unknown };
    if (typeof rule.id !== 'string' || !rule.id) {
      skipped.push({ folder: `org/${row.id}`, reason: 'rule.id missing' });
      continue;
    }

    const baseMeta = normaliseMetadata(rule.metadata);
    // Even if the YAML's metadata is incomplete, we have the canonical
    // CVE/package/ecosystem on the row itself — use those to fill in.
    const metadata: RuleMetadata = baseMeta ?? {
      cve: row.cve_id,
      package: extractPackageNameFromPurl(row.package_purl) ?? row.id,
      ecosystem: row.ecosystem,
    };
    if (row.affected_version_range && !metadata.affectedVersions) {
      metadata.affectedVersions = row.affected_version_range;
    }
    if (row.entry_point_class && !metadata.entryPointClass) {
      const c = row.entry_point_class;
      if (c === 'PUBLIC_UNAUTH' || c === 'AUTH_INTERNAL' || c === 'OFFLINE_WORKER') {
        metadata.entryPointClass = c;
      }
    }

    const safeSlug = `org-${row.id}`.replace(/[^A-Za-z0-9._-]/g, '_');
    const rulePath = path.join(tmpDir, `${safeSlug}.yml`);
    try {
      fs.writeFileSync(rulePath, row.rule_yaml, 'utf8');
    } catch (err) {
      skipped.push({ folder: `org/${row.id}`, reason: `write failed: ${err instanceof Error ? err.message : String(err)}` });
      continue;
    }

    loaded.push({ rulePath, ruleId: rule.id, metadata });
  }

  return { loaded, skipped };
}

function extractPackageNameFromPurl(purl: string): string | null {
  // pkg:npm/lodash@4.17.20  →  "lodash"
  // pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1  →  "log4j-core"
  const m = purl.match(/^pkg:[^/]+\/(?:[^/@]+\/)?([^@/]+)(?:@.+)?$/);
  return m ? m[1] : null;
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
  if (m.entry_point_class === 'PUBLIC_UNAUTH' || m.entry_point_class === 'AUTH_INTERNAL' || m.entry_point_class === 'OFFLINE_WORKER') {
    out.entryPointClass = m.entry_point_class;
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

  // mkdtempSync is atomic and guarantees a unique directory — a predictable
  // name could race with a pre-created symlink on a shared host, and plain
  // Math.random doesn't guard against that on paper.
  const prefix = args.runId
    ? `deptex-reach-rules-${args.runId}-`
    : 'deptex-reach-rules-';
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));

  try {
    // Semgrep requires globally-unique rule IDs within a single invocation.
    // Our ID convention is `deptex.<package>.<short>` so collisions shouldn't
    // happen, but detect them early with a clear error that names both
    // colliding folders so the author knows where to look.
    const seenById = new Map<string, LoadedRule>();
    for (const rule of args.rules) {
      const prior = seenById.get(rule.ruleId);
      if (prior) {
        throw new Error(
          `Duplicate Semgrep rule id ${rule.ruleId} in ${prior.rulePath} and ${rule.rulePath}`,
        );
      }
      seenById.set(rule.ruleId, rule);
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

/** Semgrep JSON for a handful of rules across a user repo is routinely a few
 * MB. Guard against runaway output pinning the worker's heap — 128 MB is
 * generous but finite. */
const MAX_STDOUT = 128 * 1024 * 1024;
/** Stderr is only used for error-message formatting (first ~4KB). Cap so a
 * verbose semgrep run (per-file parse warnings) can't OOM the worker. */
const MAX_STDERR = 64 * 1024;
/** After SIGTERM, escalate to SIGKILL if the process hasn't exited. */
const SIGKILL_GRACE_MS = 10_000;

/** Redact absolute container paths from a stderr excerpt before it lands in
 * user-visible extraction_logs. Keeps filenames/line numbers but strips the
 * internal mount-point prefix. */
function sanitizeStderr(raw: string): string {
  return raw
    .replace(/\/app\/[^\s:]+/g, '<app>')
    .replace(/\/home\/[^/\s:]+\/[^\s:]+/g, '<home>')
    .replace(/\/tmp\/deptex-[^\s:]+/g, '<tmp>');
}

async function invokeSemgrep(args: InvokeSemgrepArgs): Promise<unknown> {
  return await new Promise<unknown>((resolve, reject) => {
    // detached:true on POSIX puts the child in its own process group so we
    // can signal the whole group (process.kill(-pid, ...)) — pysemgrep forks
    // per-language engines and a bare kill() only hits the parent. Windows
    // doesn't support process groups the same way; behaviour is unchanged
    // there (bare kill still works because Semgrep Windows uses a single
    // process).
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
      {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      },
    );

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutLen = 0;
    let stderrLen = 0;
    let truncated = false;
    let sigkillTimer: NodeJS.Timeout | undefined;

    /** Try to kill the whole process group on POSIX (so pysemgrep workers die
     * with their parent). Falls back to a direct child.kill on Windows or on
     * any error. Schedules a SIGKILL grace so a semgrep that ignores SIGTERM
     * cannot hang the worker forever. */
    const killTree = () => {
      try {
        if (child.pid && process.platform !== 'win32') {
          try {
            process.kill(-child.pid, 'SIGTERM');
          } catch {
            child.kill('SIGTERM');
          }
        } else {
          child.kill('SIGTERM');
        }
      } catch {
        /* child already exited */
      }
      if (!sigkillTimer) {
        sigkillTimer = setTimeout(() => {
          try {
            if (child.pid && process.platform !== 'win32') {
              try {
                process.kill(-child.pid, 'SIGKILL');
              } catch {
                child.kill('SIGKILL');
              }
            } else {
              child.kill('SIGKILL');
            }
          } catch {
            /* already gone */
          }
        }, SIGKILL_GRACE_MS);
        // Don't keep the event loop alive for the grace timer.
        sigkillTimer.unref?.();
      }
    };

    child.stdout.on('data', (chunk: Buffer) => {
      if (truncated) return;
      stdoutLen += chunk.length;
      if (stdoutLen > MAX_STDOUT) {
        truncated = true;
        // Free the buffered output immediately — we've decided to reject, no
        // reason to keep 128 MB pinned while we wait for the child to exit.
        stdoutChunks.length = 0;
        stdoutLen = 0;
        killTree();
        return;
      }
      stdoutChunks.push(chunk);
    });

    child.stderr.on('data', (chunk: Buffer) => {
      if (stderrLen >= MAX_STDERR) return;
      const room = MAX_STDERR - stderrLen;
      const slice = chunk.length <= room ? chunk : chunk.subarray(0, room);
      stderrChunks.push(slice);
      stderrLen += slice.length;
    });

    const onAbort = () => killTree();
    if (args.signal) {
      if (args.signal.aborted) {
        onAbort();
      } else {
        args.signal.addEventListener('abort', onAbort, { once: true });
      }
    }

    const cleanup = () => {
      if (args.signal) args.signal.removeEventListener('abort', onAbort);
      if (sigkillTimer) {
        clearTimeout(sigkillTimer);
        sigkillTimer = undefined;
      }
    };

    child.on('error', (err) => {
      cleanup();
      reject(err);
    });

    child.on('close', (code) => {
      cleanup();
      if (truncated) {
        reject(new Error(`Semgrep reachability output exceeded ${MAX_STDOUT} bytes, aborting`));
        return;
      }
      // Semgrep exits non-zero when it finds matches — we specifically care
      // about exit 0 (no matches) and exit 1 (matches found). Anything else
      // is a real failure (bad config, crashed engine, killed).
      if (code !== 0 && code !== 1) {
        const stderr = sanitizeStderr(
          Buffer.concat(stderrChunks).toString('utf8').slice(0, 4000),
        );
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
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        reject(new Error(`Failed to parse Semgrep JSON: ${msg}`));
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
export interface ParseTaintOutputResult {
  findings: TaintFinding[];
  /** Rule IDs Semgrep emitted that we didn't load — usually an external
   * .semgrep config on the user's workspace bled into our subprocess, or
   * Semgrep changed its check_id formatting. Surface so drops aren't silent. */
  unknownRuleIds: string[];
}

export function parseTaintOutput(
  semgrepJson: unknown,
  rulesById: Map<string, LoadedRule>,
): TaintFinding[] {
  return parseTaintOutputWithDrops(semgrepJson, rulesById).findings;
}

export function parseTaintOutputWithDrops(
  semgrepJson: unknown,
  rulesById: Map<string, LoadedRule>,
): ParseTaintOutputResult {
  if (!semgrepJson || typeof semgrepJson !== 'object') {
    return { findings: [], unknownRuleIds: [] };
  }
  const results = (semgrepJson as { results?: unknown }).results;
  if (!Array.isArray(results)) {
    return { findings: [], unknownRuleIds: [] };
  }

  const findings: TaintFinding[] = [];
  const unknownIds = new Set<string>();
  for (const raw of results) {
    const outcome = normaliseOneFinding(raw, rulesById);
    if (outcome.kind === 'finding') {
      findings.push(outcome.finding);
    } else if (outcome.kind === 'unknown_rule') {
      unknownIds.add(outcome.ruleId);
    }
    // 'malformed' entries are dropped silently — they're not addressable via
    // rule-author action, and surfacing them would just be noise.
  }
  return { findings, unknownRuleIds: [...unknownIds] };
}

/** Truncate a content string to MAX_CONTENT_BYTES with a visible suffix. */
function clampContent(raw: string): string {
  if (raw.length <= MAX_CONTENT_BYTES) return raw;
  return raw.slice(0, MAX_CONTENT_BYTES) + '…[truncated]';
}

type NormaliseOutcome =
  | { kind: 'finding'; finding: TaintFinding }
  | { kind: 'unknown_rule'; ruleId: string }
  | { kind: 'malformed' };

function normaliseOneFinding(
  raw: unknown,
  rulesById: Map<string, LoadedRule>,
): NormaliseOutcome {
  if (!raw || typeof raw !== 'object') return { kind: 'malformed' };
  const r = raw as Record<string, unknown>;

  const ruleId = typeof r.check_id === 'string' ? r.check_id : null;
  if (!ruleId) return { kind: 'malformed' };
  // When `--config` points at a directory, semgrep prefixes check_id with
  // the rule-file's basename (e.g. `tmp.tmp.aBc.deptex.lodash.template-injection`).
  // When `--config` points at a single file, the prefix encodes the path
  // (e.g. `reachability-rules.CVE-2021-23337-lodash-template.deptex...`).
  // Our rulesById keys are the bare ids from rule.yml (`deptex.<pkg>.<x>`),
  // so direct lookup misses every finding. Fall back to a suffix match
  // anchored by the full ruleId — short of an exact collision in the
  // tail, this is unambiguous.
  let rule = rulesById.get(ruleId);
  if (!rule) {
    for (const [knownId, candidate] of rulesById) {
      if (ruleId === knownId || ruleId.endsWith(`.${knownId}`)) {
        rule = candidate;
        break;
      }
    }
  }
  if (!rule) return { kind: 'unknown_rule', ruleId };

  const filePath = typeof r.path === 'string' ? r.path : null;
  if (!filePath) return { kind: 'malformed' };

  const start = (r.start ?? null) as { line?: unknown } | null;
  const sinkLine = toInt(start?.line);
  if (sinkLine === null) return { kind: 'malformed' };

  const extra = (r.extra ?? null) as { lines?: unknown; dataflow_trace?: unknown } | null;
  const sinkContent = typeof extra?.lines === 'string' ? clampContent(extra.lines) : null;

  // Semgrep's --dataflow-traces emits taint_source/intermediate_vars/taint_sink
  // inside extra.dataflow_trace. Source CAN be missing if Semgrep widens a
  // non-taint pattern into the sink, but for `mode: taint` rules it should
  // always be populated. Fall back to the sink location so we never lose the
  // finding.
  const rawTrace = extra?.dataflow_trace;
  const trace =
    rawTrace && typeof rawTrace === 'object'
      ? (rawTrace as {
          taint_source?: unknown;
          intermediate_vars?: unknown;
          taint_sink?: unknown;
        })
      : undefined;

  const source = extractTraceStep(trace?.taint_source) ?? {
    file: filePath,
    line: sinkLine,
    content: sinkContent ?? '',
  };
  const sinkStep = extractTraceStep(trace?.taint_sink);

  const intermediate: TaintFlowStep[] = [];
  if (Array.isArray(trace?.intermediate_vars)) {
    for (const step of trace!.intermediate_vars as unknown[]) {
      if (intermediate.length >= MAX_INTERMEDIATE_STEPS) break;
      const normalised = extractTraceStep(step);
      if (normalised) intermediate.push(normalised);
    }
  }

  // Sink method is best-effort: parse out the primary function from the
  // highlighted line. Semgrep doesn't hand us the function name directly.
  const sinkMethod = sinkStep?.content ? extractCalleeName(sinkStep.content) : extractCalleeName(sinkContent ?? '');

  return {
    kind: 'finding',
    finding: {
      cve: rule.metadata.cve,
      // Emit the canonical bare id from rule.yml, not whatever prefix
      // semgrep stamped onto check_id. Downstream consumers (pipeline.ts
      // resolves rule metadata back via this id) need a stable key.
      ruleId: rule.ruleId,
      filePath,
      sourceLine: source.line,
      sourceContent: source.content || null,
      sinkLine,
      sinkMethod,
      sinkContent,
      flowSteps: intermediate,
      rawSemgrepResult: raw,
    },
  };
}

function extractTraceStep(raw: unknown): TaintFlowStep | null {
  if (!raw) return null;
  // Semgrep's trace nodes are shaped like:
  //   [{ "location": { "path": "...", "start": { "line": N }, "end": ... } }, "content..."]
  // or { location: {...}, content: "..." } — normalise both shapes.
  if (Array.isArray(raw)) {
    const head = raw[0];
    if (!head || typeof head !== 'object') return null;
    const loc = (head as { location?: unknown }).location as
      | { path?: unknown; start?: { line?: unknown } }
      | undefined;
    if (!loc) return null;
    const content = typeof raw[1] === 'string' ? clampContent(raw[1]) : '';
    const line = toInt(loc.start?.line);
    const file = typeof loc.path === 'string' ? loc.path : null;
    if (line === null || !file) return null;
    return { file, line, content };
  }
  if (typeof raw === 'object') {
    const o = raw as Record<string, unknown>;
    const locAny = (o.location ?? o) as Record<string, unknown> | undefined;
    if (!locAny || typeof locAny !== 'object') return null;
    const start = locAny.start as { line?: unknown } | undefined;
    const line = toInt(start?.line);
    const file = typeof locAny.path === 'string' ? locAny.path : null;
    const content = typeof o.content === 'string' ? clampContent(o.content) : '';
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

/** Identifiers that precede real call sites but aren't themselves the callee. */
const CALLEE_SKIP_PREFIXES = new Set(['await', 'new', 'return', 'yield', 'throw', 'typeof', 'void']);

/**
 * Best-effort: extract the callee name from a highlighted source line. The
 * rule's `pattern-sinks` already encodes which call we matched, but Semgrep
 * doesn't thread that identifier through the JSON output — we scrape it back
 * out of the line text so the DB row has a meaningful `sink_method`.
 *
 * Skips leading prefix keywords (`await foo()` → `foo`, `new Class()` → `Class`)
 * by retrying after stripping the first matched token if it's a JS/TS keyword.
 */
function extractCalleeName(line: string): string | null {
  if (!line) return null;
  const regex = /([A-Za-z_][\w.]*?)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(line)) !== null) {
    const name = match[1];
    if (!CALLEE_SKIP_PREFIXES.has(name)) return name;
  }
  return null;
}

// -----------------------------------------------------------------------------
// StepTimeoutError is re-exported so callers only need to import this module.
// -----------------------------------------------------------------------------

export { StepTimeoutError };
