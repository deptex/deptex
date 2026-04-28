/**
 * Validates a generated Semgrep rule against:
 *   1. YAML parse — fails fast on malformed yaml.
 *   2. Fixture round-trip — rule MUST hit vulnerable_fixture, must NOT hit
 *      safe_fixture. This is a cheap local sanity check that catches the
 *      "rule matches nothing" / "rule matches everything" failure modes.
 *   3. Diff-targeted patch round-trip — autogrep-inspired: run Semgrep against
 *      each changed file's pre-patch (`before`) and post-patch (`after`)
 *      blob from the OSV fix commit. We use the per-file blobs already
 *      fetched by patch-fetch.ts — no clone needed.
 *
 * Patch round-trip semantics (note: relaxed from the autogrep paper):
 *   - `patch_post_clean` (post-fix matches must be 0) — HARD gate. If the
 *     rule fires on the fixed code, the rule is wrong by definition: it's
 *     matching code that the upstream maintainers consider safe.
 *   - `patch_pre_match` (≥1 pre-fix match across changed files) — ADVISORY.
 *     We generate app-callsite-aware rules whose sources are HTTP request
 *     shapes (`req.body`) and whose sinks are user-side calls
 *     (`_.toNumber($INPUT)`). Library-internal patches (e.g. lodash fixing
 *     a regex inside `_.toNumber`'s implementation) don't contain any
 *     `req.*` callers, so a correctly-shaped app-callsite rule will
 *     legitimately get pre_match=0 against such patches. Treating that as
 *     a hard fail is structurally wrong for our use case. We log it for
 *     telemetry / future prompt iteration but don't block validation.
 *
 * Step (3) is gated behind `args.runPatchValidation`. When skipped (no
 * applicable changed files in the rule's language, or explicitly disabled),
 * fixture validation alone is sufficient.
 *
 * All temp files are torn down in finally blocks regardless of outcome.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';
import * as yaml from 'js-yaml';
import type { GeneratedPayload } from './generate';
import type { ChangedFileBlob } from './patch-fetch';
import { semgrepLanguageFor } from './prompt-builder';

const SIGKILL_GRACE_MS = 10_000;
const MAX_STDOUT = 32 * 1024 * 1024;
const MAX_STDERR = 32 * 1024;

export interface ValidateRuleArgs {
  payload: GeneratedPayload;
  cveId: string;
  ecosystem: string;
  /** Per-file before/after blobs from the OSV fix commit (via patch-fetch).
   *  When provided, validate.ts runs the rule against the pre-patch and
   *  post-patch text of every applicable file and aggregates the matches. */
  changedFiles?: ChangedFileBlob[];
  workDir: string;
  signal?: AbortSignal;
  semgrepBin?: string;
  /** Run the diff-targeted patch round-trip in addition to fixture round-trip.
   *  Defaults to true when changedFiles is provided. */
  runPatchValidation?: boolean;
}

export interface PerFileValidationBreakdown {
  path: string;
  pre: number;
  post: number;
}

/**
 * Funnel-style per-CVE summary of which validation gates passed. Aggregated
 * across all candidates in a run by rule-generation-step into the
 * `extraction_jobs.reachability_validation_breakdown` JSONB column.
 *
 * `schema_pass` is always true on a breakdown produced by validateRule —
 * reaching validate means the AI's JSON already passed Zod. Pre-validate
 * failure modes (parse_failed / invalid_schema / no_advisory etc.) get a
 * synthesized breakdown in index.ts where schema_pass=false.
 */
export interface ValidationBreakdown {
  schema_pass: boolean;
  fixture_pre_match: boolean;
  fixture_safe_clean: boolean;
  patch_pre_match: boolean | null;
  patch_post_clean: boolean | null;
  semgrep_parse_error: string | null;
}

export interface ValidationLog {
  fixture_pre_matches: number;
  fixture_post_matches: number;
  patch_pre_matches: number | null;
  patch_post_matches: number | null;
  semgrep_stderr_excerpt: string | null;
  errors: string[];
  took_ms: number;
  patch_validation_skipped_reason?: string;
  /** Per-file pre/post match counts from the diff-targeted run. Populated
   *  whenever patch validation actually ran (even with zero applicable files,
   *  in which case it's an empty array). */
  patch_per_file?: PerFileValidationBreakdown[];
  /** Per-CVE pass/fail breakdown rolled up into step-level telemetry. */
  validation_breakdown: ValidationBreakdown;
}

export interface ValidationResult {
  status: 'validated' | 'failed_validation';
  log: ValidationLog;
}

export class RuleValidationError extends Error {
  readonly stage: 'yaml_parse' | 'fixture_run' | 'patch_run' | 'semgrep' | 'unexpected';

  constructor(stage: RuleValidationError['stage'], message: string) {
    super(message);
    this.name = 'RuleValidationError';
    this.stage = stage;
  }
}

export async function validateRule(args: ValidateRuleArgs): Promise<ValidationResult> {
  const start = Date.now();
  const errors: string[] = [];
  let stderrExcerpt: string | null = null;

  // --- 1. YAML parse + ruleId/language sanity ---
  // Apply a deterministic quote-fixing pre-pass to rescue rules where the AI
  // forgot to single-quote pattern values containing YAML-special characters
  // ({}[]:,*?!|> or the Semgrep ellipsis ...). Empirically lifts Gemini's
  // validation rate by ~+5pp on the npm corpus and is provider-agnostic. The
  // pre-pass only rewrites `pattern:` lines; `message:` and other scalars are
  // untouched. Rule_yaml that's already well-formed passes through unchanged.
  const normalizedYaml = quotePatternsInYaml(args.payload.rule_yaml);
  const normalizedPayload: GeneratedPayload = normalizedYaml === args.payload.rule_yaml
    ? args.payload
    : { ...args.payload, rule_yaml: normalizedYaml };
  let parsedRule: { id: string; language: string };
  try {
    parsedRule = parseRuleYaml(normalizedPayload.rule_yaml);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      status: 'failed_validation',
      log: {
        fixture_pre_matches: 0,
        fixture_post_matches: 0,
        patch_pre_matches: null,
        patch_post_matches: null,
        semgrep_stderr_excerpt: null,
        errors: [`yaml_parse: ${msg}`],
        took_ms: Date.now() - start,
        validation_breakdown: {
          // Schema (Zod) passed upstream; the rule_yaml string itself is what
          // failed to parse here, which is a separate downstream gate. Surface
          // it through semgrep_parse_error so the funnel reflects "the YAML
          // the AI emitted wasn't a valid Semgrep config".
          schema_pass: true,
          fixture_pre_match: false,
          fixture_safe_clean: false,
          patch_pre_match: null,
          patch_post_clean: null,
          semgrep_parse_error: msg.slice(0, 500),
        },
      },
    };
  }

  const ext = sourceExtensionFor(args.ecosystem);

  // --- 1.5. semgrep --validate (real schema gate) ---
  // YAML parse only catches structural problems. Semgrep itself owns the
  // grammar of pattern-either / focus-metavariable / pattern-not / etc., and
  // refuses to load rules with bugs the YAML layer can't see. Running
  // `semgrep scan --validate --config <rule>` is fast (no targets to scan)
  // and surfaces a clean parser error we can feed back to the model in M1's
  // retry loop. Without this gate, broken rules waste two full fixture
  // docker invocations before failing with a cryptic stderr excerpt.
  const semgrepValidateRoot = fs.mkdtempSync(path.join(args.workDir, `rulegen-vlt-`));
  let semgrepValidateError: string | null = null;
  try {
    const ruleFile = path.join(semgrepValidateRoot, 'rule.yml');
    fs.writeFileSync(ruleFile, normalizedPayload.rule_yaml, 'utf8');
    const validateRun = await runSemgrepValidate({
      ruleFile,
      signal: args.signal,
      semgrepBin: args.semgrepBin,
    });
    if (!validateRun.ok) {
      semgrepValidateError = validateRun.errorExcerpt;
    }
  } catch (err) {
    // semgrep validate itself crashed (docker missing, etc.). Don't fail the
    // rule for our infra problem — fall through to fixture run, which will
    // surface the real issue or succeed.
  } finally {
    safeRm(semgrepValidateRoot);
  }
  if (semgrepValidateError) {
    return {
      status: 'failed_validation',
      log: {
        fixture_pre_matches: 0,
        fixture_post_matches: 0,
        patch_pre_matches: null,
        patch_post_matches: null,
        semgrep_stderr_excerpt: semgrepValidateError,
        errors: [`semgrep_validate: ${semgrepValidateError}`],
        took_ms: Date.now() - start,
        validation_breakdown: {
          schema_pass: true,
          fixture_pre_match: false,
          fixture_safe_clean: false,
          patch_pre_match: null,
          patch_post_clean: null,
          semgrep_parse_error: semgrepValidateError.slice(0, 500),
        },
      },
    };
  }

  // --- 2. Fixture round-trip ---
  const fixtureRoot = fs.mkdtempSync(path.join(args.workDir, `rulegen-fix-`));
  let fixturePre = 0;
  let fixturePost = 0;
  try {
    const ruleFile = path.join(fixtureRoot, 'rule.yml');
    fs.writeFileSync(ruleFile, normalizedPayload.rule_yaml, 'utf8');
    const vulnDir = path.join(fixtureRoot, 'vulnerable');
    const safeDir = path.join(fixtureRoot, 'safe');
    fs.mkdirSync(vulnDir, { recursive: true });
    fs.mkdirSync(safeDir, { recursive: true });
    fs.writeFileSync(path.join(vulnDir, `index.${ext}`), normalizedPayload.vulnerable_fixture, 'utf8');
    fs.writeFileSync(path.join(safeDir, `index.${ext}`), normalizedPayload.safe_fixture, 'utf8');

    const vulnRun = await runSemgrep({ ruleFile, target: vulnDir, signal: args.signal, semgrepBin: args.semgrepBin });
    const safeRun = await runSemgrep({ ruleFile, target: safeDir, signal: args.signal, semgrepBin: args.semgrepBin });
    fixturePre = vulnRun.matches;
    fixturePost = safeRun.matches;
    if (vulnRun.stderr) stderrExcerpt = vulnRun.stderr;
    if (!stderrExcerpt && safeRun.stderr) stderrExcerpt = safeRun.stderr;
  } catch (err) {
    errors.push(`fixture_run: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    safeRm(fixtureRoot);
  }

  // --- 3. Diff-targeted patch round-trip (optional) ---
  let patchPre: number | null = null;
  let patchPost: number | null = null;
  let patchPerFile: PerFileValidationBreakdown[] | undefined;
  let patchSkipReason: string | undefined;

  const hasChangedFiles = !!args.changedFiles && args.changedFiles.length > 0;
  const shouldRunPatch = (args.runPatchValidation ?? true) && hasChangedFiles && errors.length === 0;
  if (shouldRunPatch && args.changedFiles) {
    try {
      const applicable = filterApplicableChangedFiles(args.changedFiles, parsedRule.language);
      if (applicable.length === 0) {
        patchSkipReason = 'no_applicable_changed_files';
      } else {
        const result = await runDiffTargetedValidation({
          ruleYaml: normalizedPayload.rule_yaml,
          files: applicable,
          language: parsedRule.language,
          workDir: args.workDir,
          signal: args.signal,
          semgrepBin: args.semgrepBin,
        });
        patchPre = result.preMatches;
        patchPost = result.postMatches;
        patchPerFile = result.perFile;
        if (!stderrExcerpt && result.stderr) stderrExcerpt = result.stderr;
      }
    } catch (err) {
      // Patch validation is best-effort — surface the reason but don't
      // throw out of validateRule. The verdict logic below will treat null
      // patch counts as "skipped" rather than failing the rule outright.
      const msg = err instanceof Error ? err.message : String(err);
      if (err instanceof RuleValidationError) {
        patchSkipReason = `${err.stage}: ${msg}`;
      } else {
        patchSkipReason = `unexpected: ${msg}`;
      }
    }
  } else if (!hasChangedFiles) {
    patchSkipReason = 'no_changed_files_provided';
  } else if (errors.length > 0) {
    patchSkipReason = 'fixture_validation_failed';
  } else if (args.runPatchValidation === false) {
    patchSkipReason = 'disabled_by_caller';
  }

  // --- Verdict ---
  const fixturePass = fixturePre > 0 && fixturePost === 0;
  if (!fixturePass) {
    if (errors.length === 0) {
      errors.push(`fixture_round_trip_failed: pre=${fixturePre} post=${fixturePost} (require pre>0 and post=0)`);
    }
  }
  if (patchPre !== null && patchPost !== null) {
    // patch_pre_match is advisory only — see file header. App-callsite rules
    // legitimately get pre_match=0 against library-internal patches, and
    // failing on that excludes exactly the rules we want. Surface it through
    // patch_validation_skipped_reason so telemetry still captures the signal.
    if (patchPre <= 0 && !patchSkipReason) {
      patchSkipReason = 'patch_pre_match_zero_advisory';
    }
    // patch_post_clean stays a hard gate: if the rule fires on the fixed
    // code, the rule is matching what upstream considers safe.
    if (patchPost > 0) errors.push(`patch_round_trip_failed: post-patch matches=${patchPost} (require 0)`);
  }

  const status = errors.length === 0 && fixturePass ? 'validated' : 'failed_validation';

  // Heuristic: if Semgrep emitted stderr AND the fixture didn't fire, the
  // stderr is likely a rule-parse / config-load error rather than a benign
  // deprecation warning. Surface a short excerpt for the funnel telemetry.
  //
  // The regex deliberately excludes "Parsed" — Semgrep prints "Parsed lines:
  // ~100.0%" on every successful scan, which used to false-positive this
  // heuristic and trigger the M1 retry loop on rules that loaded fine but
  // simply didn't match the fixture. With M2's `semgrep --validate` gate
  // running upstream, real parse errors get caught there, so this heuristic
  // is now belt-and-braces — keep it tight.
  const looksLikeParseError =
    !!stderrExcerpt &&
    fixturePre === 0 &&
    /\b(error|invalid|failed|cannot|could not|couldn't load|ruleparse)\b/i.test(stderrExcerpt);

  return {
    status,
    log: {
      fixture_pre_matches: fixturePre,
      fixture_post_matches: fixturePost,
      patch_pre_matches: patchPre,
      patch_post_matches: patchPost,
      semgrep_stderr_excerpt: stderrExcerpt,
      errors,
      took_ms: Date.now() - start,
      patch_validation_skipped_reason: patchSkipReason,
      patch_per_file: patchPerFile,
      validation_breakdown: {
        schema_pass: true,
        fixture_pre_match: fixturePre > 0,
        fixture_safe_clean: fixturePost === 0,
        patch_pre_match: patchPre === null ? null : patchPre > 0,
        patch_post_clean: patchPost === null ? null : patchPost === 0,
        semgrep_parse_error: looksLikeParseError ? stderrExcerpt!.slice(0, 500) : null,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// YAML parse helpers
// ---------------------------------------------------------------------------

function parseRuleYaml(yamlText: string): { id: string; language: string } {
  let parsed: unknown;
  try {
    parsed = yaml.load(yamlText);
  } catch (err) {
    throw new Error(`YAML parse failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  const doc = parsed as { rules?: unknown };
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.rules) || doc.rules.length !== 1) {
    throw new Error("expected exactly one rule under 'rules:'");
  }
  const rule = doc.rules[0] as { id?: unknown; languages?: unknown };
  if (typeof rule.id !== 'string' || rule.id.length === 0) {
    throw new Error('rule.id is missing');
  }
  const langs = Array.isArray(rule.languages) ? rule.languages.filter((x): x is string => typeof x === 'string') : [];
  if (langs.length === 0) {
    throw new Error("rule.languages is missing or empty");
  }
  return { id: rule.id, language: langs[0] };
}

const EXT_BY_ECOSYSTEM: Record<string, string> = {
  npm: 'js',
  pypi: 'py',
  maven: 'java',
  golang: 'go',
  go: 'go',
  rubygems: 'rb',
  packagist: 'php',
  cargo: 'rs',
  nuget: 'cs',
};

function sourceExtensionFor(ecosystem: string): string {
  const lang = semgrepLanguageFor(ecosystem);
  // Sanity-tie the file extension to the prompt's chosen language so a rule
  // targeting `javascript` gets a `.js` fixture file even if the ecosystem
  // string is unfamiliar.
  if (lang === 'javascript' || lang === 'typescript') return 'js';
  if (lang === 'python') return 'py';
  if (lang === 'java') return 'java';
  if (lang === 'go') return 'go';
  if (lang === 'ruby') return 'rb';
  if (lang === 'php') return 'php';
  if (lang === 'rust') return 'rs';
  if (lang === 'csharp') return 'cs';
  return EXT_BY_ECOSYSTEM[ecosystem.toLowerCase()] ?? 'txt';
}

function safeRm(p: string): void {
  try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* non-fatal */ }
}

// ---------------------------------------------------------------------------
// Diff-targeted patch round-trip
//
// For each changed file in the rule's language with both `before` and `after`
// blobs, we write the two snapshots to tmp files and run Semgrep against
// each. Aggregate pre/post match counts decide the verdict: pass iff
// preMatches > 0 and postMatches === 0.
//
// This replaced the previous clone-based path. Reasons:
//   - App-level rules target callsite shapes (e.g. `_.template(req.body)`)
//     that don't appear inside the upstream library repo. Whole-repo
//     validation false-rejected such rules even when the rule was correct.
//   - Network-free: no clone, no LFS, no submodules, no rate limits.
//   - Bounded cost: changedFiles is already capped by patch-fetch.ts at
//     8 files × 64KB, so worst-case validation is 16 small Semgrep runs.
// ---------------------------------------------------------------------------

interface DiffTargetedArgs {
  ruleYaml: string;
  files: ChangedFileBlob[];
  language: string;
  workDir: string;
  signal?: AbortSignal;
  semgrepBin?: string;
}

async function runDiffTargetedValidation(args: DiffTargetedArgs): Promise<{
  preMatches: number;
  postMatches: number;
  perFile: PerFileValidationBreakdown[];
  stderr: string | null;
}> {
  const root = fs.mkdtempSync(path.join(args.workDir, `rulegen-diff-`));
  try {
    const ruleFile = path.join(root, 'rule.yml');
    fs.writeFileSync(ruleFile, args.ruleYaml, 'utf8');

    const ext = sourceExtensionForLanguage(args.language);
    let preTotal = 0;
    let postTotal = 0;
    let stderr: string | null = null;
    const perFile: PerFileValidationBreakdown[] = [];

    for (let i = 0; i < args.files.length; i++) {
      const file = args.files[i];
      const before = file.before ?? '';
      const after = file.after ?? '';

      const beforeDir = path.join(root, `before-${i}`);
      const afterDir = path.join(root, `after-${i}`);
      fs.mkdirSync(beforeDir, { recursive: true });
      fs.mkdirSync(afterDir, { recursive: true });

      // Write both snapshots under the rule-language extension. Original
      // path is preserved as the basename so error messages stay meaningful,
      // but we override the extension to whatever Semgrep expects for the
      // declared rule language.
      const baseName = path.basename(file.path).replace(/\.[^./]+$/, '') || 'snippet';
      const beforeFile = path.join(beforeDir, `${baseName}.${ext}`);
      const afterFile = path.join(afterDir, `${baseName}.${ext}`);
      fs.writeFileSync(beforeFile, before, 'utf8');
      fs.writeFileSync(afterFile, after, 'utf8');

      const preRun = await runSemgrep({ ruleFile, target: beforeDir, signal: args.signal, semgrepBin: args.semgrepBin });
      const postRun = await runSemgrep({ ruleFile, target: afterDir, signal: args.signal, semgrepBin: args.semgrepBin });

      preTotal += preRun.matches;
      postTotal += postRun.matches;
      perFile.push({ path: file.path, pre: preRun.matches, post: postRun.matches });
      if (!stderr && preRun.stderr) stderr = preRun.stderr;
      if (!stderr && postRun.stderr) stderr = postRun.stderr;
    }

    return { preMatches: preTotal, postMatches: postTotal, perFile, stderr };
  } finally {
    safeRm(root);
  }
}

/**
 * Filter changedFiles down to ones the rule's language can actually run on:
 *   - file extension matches the rule language (so Semgrep can parse it)
 *   - both before and after blobs are present
 * If `before === null` the file was added by the fix (can't test pre-patch).
 * If `after === null` the file was deleted (can't test post-patch).
 */
export function filterApplicableChangedFiles(
  files: ChangedFileBlob[],
  language: string,
): ChangedFileBlob[] {
  const accepted = expectedExtensionsForLanguage(language);
  return files.filter((f) => {
    if (f.before === null || f.after === null) return false;
    const ext = path.extname(f.path).toLowerCase().replace(/^\./, '');
    return accepted.has(ext);
  });
}

function expectedExtensionsForLanguage(language: string): Set<string> {
  switch (language) {
    case 'javascript': return new Set(['js', 'jsx', 'mjs', 'cjs']);
    case 'typescript': return new Set(['ts', 'tsx']);
    case 'python':     return new Set(['py']);
    case 'java':       return new Set(['java']);
    case 'go':         return new Set(['go']);
    case 'ruby':       return new Set(['rb']);
    case 'php':        return new Set(['php']);
    case 'rust':       return new Set(['rs']);
    case 'csharp':     return new Set(['cs']);
    default:           return new Set();
  }
}

function sourceExtensionForLanguage(language: string): string {
  switch (language) {
    case 'javascript': return 'js';
    case 'typescript': return 'ts';
    case 'python':     return 'py';
    case 'java':       return 'java';
    case 'go':         return 'go';
    case 'ruby':       return 'rb';
    case 'php':        return 'php';
    case 'rust':       return 'rs';
    case 'csharp':     return 'cs';
    default:           return 'txt';
  }
}

// ---------------------------------------------------------------------------
// Semgrep invocation
// ---------------------------------------------------------------------------

interface RunSemgrepArgs {
  ruleFile: string;
  target: string;
  signal?: AbortSignal;
  semgrepBin?: string;
}

interface SemgrepRunResult {
  matches: number;
  stderr: string | null;
}

async function runSemgrep(args: RunSemgrepArgs): Promise<SemgrepRunResult> {
  return await new Promise<SemgrepRunResult>((resolve, reject) => {
    const semgrepBin = args.semgrepBin ?? 'semgrep';
    // --quiet hides stderr too, which makes "exit code 7" diagnostics
    // useless when a generated rule is malformed. Drop --quiet so we still
    // capture the real config-load error message; --metrics=off keeps the
    // network noise out.
    //
    // Docker fallback (DEPTEX_SEMGREP_DOCKER_IMAGE env): when set, run
    // semgrep inside the named container instead of on the host. Required on
    // Windows host where the Python launcher Semgrep is a non-functional stub
    // — every scan returns exit=1 with no output. The deptex-cli image ships
    // a working semgrep (1.160+), so we mount the workdir as /work and
    // translate the rule + target paths into container space.
    const dockerImage = process.env.DEPTEX_SEMGREP_DOCKER_IMAGE?.trim();
    let cmd: string;
    let cmdArgs: string[];
    if (dockerImage) {
      const common = commonAncestor(args.ruleFile, args.target);
      const ruleInContainer = '/work/' + posixRelative(common, args.ruleFile);
      const targetInContainer = '/work/' + posixRelative(common, args.target);
      cmd = 'docker';
      cmdArgs = [
        'run', '--rm',
        '-v', `${common}:/work`,
        '--entrypoint', 'semgrep',
        dockerImage,
        'scan',
        '--config', ruleInContainer,
        '--json',
        '--no-git-ignore',
        '--metrics=off',
        targetInContainer,
      ];
    } else {
      cmd = semgrepBin;
      cmdArgs = [
        'scan',
        '--config', args.ruleFile,
        '--json',
        '--no-git-ignore',
        '--metrics=off',
        args.target,
      ];
    }
    const child = spawn(
      cmd,
      cmdArgs,
      {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
        // Suppress Git-Bash path translation when invoking docker on Windows;
        // the Linux paths we pass (/work/...) must reach docker verbatim.
        env: dockerImage ? { ...process.env, MSYS_NO_PATHCONV: '1', MSYS2_ARG_CONV_EXCL: '*' } : process.env,
      },
    );

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutLen = 0;
    let stderrLen = 0;
    let truncated = false;
    let sigkillTimer: NodeJS.Timeout | undefined;

    const killTree = () => {
      try {
        if (child.pid && process.platform !== 'win32') {
          try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
        } else {
          child.kill('SIGTERM');
        }
      } catch { /* gone */ }
      if (!sigkillTimer) {
        sigkillTimer = setTimeout(() => {
          try {
            if (child.pid && process.platform !== 'win32') {
              try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
            } else {
              child.kill('SIGKILL');
            }
          } catch { /* gone */ }
        }, SIGKILL_GRACE_MS);
        sigkillTimer.unref?.();
      }
    };

    child.stdout.on('data', (chunk: Buffer) => {
      if (truncated) return;
      stdoutLen += chunk.length;
      if (stdoutLen > MAX_STDOUT) {
        truncated = true;
        stdoutChunks.length = 0;
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
      if (args.signal.aborted) onAbort();
      else args.signal.addEventListener('abort', onAbort, { once: true });
    }

    const cleanup = () => {
      if (args.signal) args.signal.removeEventListener('abort', onAbort);
      if (sigkillTimer) { clearTimeout(sigkillTimer); sigkillTimer = undefined; }
    };

    child.on('error', (err) => { cleanup(); reject(new RuleValidationError('semgrep', err.message)); });
    child.on('close', (code) => {
      cleanup();
      if (truncated) {
        reject(new RuleValidationError('semgrep', `stdout exceeded ${MAX_STDOUT} bytes`));
        return;
      }
      const stderrText = Buffer.concat(stderrChunks).toString('utf8').slice(0, MAX_STDERR);
      // Semgrep exits 0 (no match) or 1 (match found) for valid configs.
      // 2+ is a real error (bad rule, parse failure).
      if (code !== 0 && code !== 1) {
        reject(new RuleValidationError('semgrep', `semgrep exited ${code}: ${stderrText.slice(0, 500)}`));
        return;
      }
      try {
        const body = Buffer.concat(stdoutChunks).toString('utf8');
        const parsed = body.length === 0 ? { results: [] } : JSON.parse(body) as { results?: unknown[] };
        resolve({
          matches: Array.isArray(parsed.results) ? parsed.results.length : 0,
          stderr: stderrText.length > 0 ? sanitizeStderr(stderrText) : null,
        });
      } catch (err) {
        reject(new RuleValidationError('semgrep', `semgrep JSON parse failed: ${err instanceof Error ? err.message : String(err)}`));
      }
    });
  });
}

// ---------------------------------------------------------------------------
// semgrep --validate (rule grammar gate)
//
// Runs `semgrep scan --validate --config <rule>` and reports whether the rule
// loaded cleanly. We use the same docker fallback as runSemgrep — on Windows
// hosts where the python-launcher Semgrep is a stub, validate-mode also
// requires the deptex-cli image. Validate completes in <1s on the small rules
// we generate (no targets, just parse + grammar check).
// ---------------------------------------------------------------------------

interface RunSemgrepValidateArgs {
  ruleFile: string;
  signal?: AbortSignal;
  semgrepBin?: string;
}

interface SemgrepValidateResult {
  ok: boolean;
  errorExcerpt: string | null;
}

async function runSemgrepValidate(args: RunSemgrepValidateArgs): Promise<SemgrepValidateResult> {
  return await new Promise<SemgrepValidateResult>((resolve, reject) => {
    const semgrepBin = args.semgrepBin ?? 'semgrep';
    const dockerImage = process.env.DEPTEX_SEMGREP_DOCKER_IMAGE?.trim();
    let cmd: string;
    let cmdArgs: string[];
    if (dockerImage) {
      const ruleDir = path.dirname(path.resolve(args.ruleFile));
      const ruleBase = path.basename(args.ruleFile);
      cmd = 'docker';
      cmdArgs = [
        'run', '--rm',
        '-v', `${ruleDir}:/work`,
        '--entrypoint', 'semgrep',
        dockerImage,
        'scan',
        '--validate',
        '--config', `/work/${ruleBase}`,
        '--metrics=off',
      ];
    } else {
      cmd = semgrepBin;
      cmdArgs = [
        'scan',
        '--validate',
        '--config', args.ruleFile,
        '--metrics=off',
      ];
    }
    const child = spawn(cmd, cmdArgs, {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
      env: dockerImage ? { ...process.env, MSYS_NO_PATHCONV: '1', MSYS2_ARG_CONV_EXCL: '*' } : process.env,
    });
    const stderrChunks: Buffer[] = [];
    const stdoutChunks: Buffer[] = [];
    let stderrLen = 0;
    let sigkillTimer: NodeJS.Timeout | undefined;

    const killTree = () => {
      try {
        if (child.pid && process.platform !== 'win32') {
          try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
        } else {
          child.kill('SIGTERM');
        }
      } catch { /* gone */ }
      if (!sigkillTimer) {
        sigkillTimer = setTimeout(() => {
          try {
            if (child.pid && process.platform !== 'win32') {
              try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
            } else {
              child.kill('SIGKILL');
            }
          } catch { /* gone */ }
        }, SIGKILL_GRACE_MS);
        sigkillTimer.unref?.();
      }
    };

    child.stdout.on('data', (chunk: Buffer) => { stdoutChunks.push(chunk); });
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderrLen >= MAX_STDERR) return;
      const room = MAX_STDERR - stderrLen;
      const slice = chunk.length <= room ? chunk : chunk.subarray(0, room);
      stderrChunks.push(slice);
      stderrLen += slice.length;
    });

    const onAbort = () => killTree();
    if (args.signal) {
      if (args.signal.aborted) onAbort();
      else args.signal.addEventListener('abort', onAbort, { once: true });
    }

    const cleanup = () => {
      if (args.signal) args.signal.removeEventListener('abort', onAbort);
      if (sigkillTimer) { clearTimeout(sigkillTimer); sigkillTimer = undefined; }
    };

    child.on('error', (err) => { cleanup(); reject(new RuleValidationError('semgrep', err.message)); });
    child.on('close', (code) => {
      cleanup();
      const stderrText = Buffer.concat(stderrChunks).toString('utf8').slice(0, MAX_STDERR);
      const stdoutText = Buffer.concat(stdoutChunks).toString('utf8');
      // Semgrep returns 0 when the config is valid. Non-zero means a parse /
      // grammar error — extract a concise message for the model.
      if (code === 0) {
        resolve({ ok: true, errorExcerpt: null });
      } else {
        const combined = [stderrText, stdoutText].filter(Boolean).join('\n');
        const excerpt = sanitizeStderr(combined).trim().slice(0, 500) || `semgrep validate exited ${code}`;
        resolve({ ok: false, errorExcerpt: excerpt });
      }
    });
  });
}

// ---------------------------------------------------------------------------
// YAML quote-fixer
//
// AI-generated rules frequently emit `pattern:` values containing characters
// YAML treats as flow-mapping syntax (`{`, `}`, `[`, `]`, `:`, `,`, `&`, `*`,
// `?`, `!`, `|`, `>`) or the Semgrep ellipsis `...`. The prompt warns about
// this but models still forget on a fraction of cases. This pre-pass walks
// the rule_yaml line-by-line and force-single-quotes any unquoted `pattern:`
// scalar that contains those characters — recovering rules that would
// otherwise fail YAML parse with "bad indentation of a mapping entry".
//
// Scope: only `pattern:` lines. `message:` and other scalars are left alone
// (their YAML preserves block-scalar markers like `|` and `>-` that the rewrite
// would corrupt). Block-scalar `pattern:` lines (rare) are skipped too.
// ---------------------------------------------------------------------------

const NEEDS_QUOTING = /[\{\}\[\]:,&*?!|>]|\.\.\./;

function quotePatternsInYaml(yamlText: string): string {
  const lines = yamlText.split(/\r?\n/);
  const out: string[] = [];
  const re = /^(\s*-?\s*pattern\s*:\s+)([^\r\n]*)$/;
  for (const line of lines) {
    const m = line.match(re);
    if (!m) { out.push(line); continue; }
    const head = m[1];
    let value = m[2];
    const t = value.trim();
    // Empty / block-scalar markers: leave as-is.
    if (t === '' || t === '|' || t === '>' || t === '|-' || t === '>-' || t === '|+' || t === '>+') {
      out.push(line);
      continue;
    }
    // Strip trailing inline comment so we don't quote it inside the value.
    let comment = '';
    const ci = findInlineCommentStart(value);
    if (ci >= 0) {
      comment = value.slice(ci);
      value = value.slice(0, ci).trimEnd();
    }
    out.push(`${head}${quotePatternValue(value)}${comment ? '  ' + comment : ''}`);
  }
  return out.join('\n');
}

function quotePatternValue(raw: string): string {
  const trimmed = raw.trimEnd();
  if (trimmed.length === 0) return raw;
  // Already quoted (single or double) — leave alone.
  const first = trimmed[0];
  const last = trimmed[trimmed.length - 1];
  if ((first === "'" && last === "'") || (first === '"' && last === '"')) return raw;
  if (!NEEDS_QUOTING.test(trimmed)) return raw;
  // Single-quote it; inner single quotes are escaped as '' per YAML's
  // single-quoted-scalar rules.
  const inner = trimmed.replace(/'/g, "''");
  const trailingWs = raw.slice(trimmed.length);
  return `'${inner}'${trailingWs}`;
}

function findInlineCommentStart(s: string): number {
  // Honor quote state — `#` inside a quoted scalar is not a comment.
  let inS = false, inD = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "'" && !inD) inS = !inS;
    else if (ch === '"' && !inS) inD = !inD;
    else if (ch === '#' && !inS && !inD) {
      if (i === 0 || /\s/.test(s[i - 1])) return i;
    }
  }
  return -1;
}

/** Longest common parent directory of two absolute paths. */
function commonAncestor(a: string, b: string): string {
  const segA = path.resolve(a).split(path.sep);
  const segB = path.resolve(b).split(path.sep);
  const out: string[] = [];
  for (let i = 0; i < Math.min(segA.length, segB.length); i++) {
    if (segA[i] !== segB[i]) break;
    out.push(segA[i]);
  }
  // Strip the file basename if the common prefix included the full path of one
  // of the inputs (e.g. ruleFile lives directly under target's parent).
  const joined = out.join(path.sep);
  return path.dirname(joined) === joined || /\.[^./]+$/.test(joined) ? path.dirname(joined) : joined;
}

/** Path relative from `from` to `to`, with platform separators normalised to '/'. */
function posixRelative(from: string, to: string): string {
  return path.relative(from, to).split(path.sep).filter(Boolean).join('/');
}

function sanitizeStderr(raw: string): string {
  return raw
    .replace(/\/app\/[^\s:]+/g, '<app>')
    .replace(/\/home\/[^/\s:]+\/[^\s:]+/g, '<home>')
    .replace(/\/tmp\/[^\s:]+/g, '<tmp>');
}

// ---------------------------------------------------------------------------
// Workdir helper
// ---------------------------------------------------------------------------

export function makeRuleGenWorkdir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-rulegen-'));
}
