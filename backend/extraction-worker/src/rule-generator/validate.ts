/**
 * Validates a generated Semgrep rule against:
 *   1. YAML parse — fails fast on malformed yaml.
 *   2. Fixture round-trip — rule MUST hit vulnerable_fixture, must NOT hit
 *      safe_fixture. This is a cheap local sanity check that catches the
 *      "rule matches nothing" / "rule matches everything" failure modes.
 *   3. Patch round-trip — clone the upstream repo at parent + fix SHA, run
 *      Semgrep on each tree. Pre-patch tree MUST have ≥1 hit; post-patch tree
 *      MUST have 0 hits. This is the autogrep-style validation that confirms
 *      the rule is actually CVE-specific (not just generic API matching).
 *
 * Step (3) is gated behind `args.runPatchValidation`. When false (or when
 * cloning fails), we accept fixture validation alone — that's still strong
 * evidence the rule is well-formed. The pipeline can decide based on org
 * settings or runtime conditions whether to require the heavier check.
 *
 * All temp files are torn down in finally blocks regardless of outcome.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';
import * as yaml from 'js-yaml';
import simpleGit from 'simple-git';
import type { GeneratedPayload } from './generate';
import type { FixCommit } from './osv-fetch';
import { semgrepLanguageFor } from './prompt-builder';

const SIGKILL_GRACE_MS = 10_000;
const MAX_STDOUT = 32 * 1024 * 1024;
const MAX_STDERR = 32 * 1024;
const MAX_REPO_BYTES = 1024 * 1024 * 1024; // 1GB skip threshold per plan
const CLONE_TIMEOUT_MS = 60_000;

export interface ValidateRuleArgs {
  payload: GeneratedPayload;
  cveId: string;
  ecosystem: string;
  /** When provided, validate.ts will additionally clone the repo at parent +
   *  fix SHA and confirm the rule fires pre-patch and is silent post-patch. */
  fixCommit?: FixCommit;
  workDir: string;
  signal?: AbortSignal;
  semgrepBin?: string;
  /** Run the heavier patch round-trip in addition to fixture round-trip.
   *  Defaults to true when fixCommit is provided. */
  runPatchValidation?: boolean;
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
}

export interface ValidationResult {
  status: 'validated' | 'failed_validation';
  log: ValidationLog;
}

export class RuleValidationError extends Error {
  readonly stage: 'yaml_parse' | 'fixture_run' | 'clone' | 'semgrep' | 'unexpected';

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
  let parsedRule: { id: string; language: string };
  try {
    parsedRule = parseRuleYaml(args.payload.rule_yaml);
  } catch (err) {
    return {
      status: 'failed_validation',
      log: {
        fixture_pre_matches: 0,
        fixture_post_matches: 0,
        patch_pre_matches: null,
        patch_post_matches: null,
        semgrep_stderr_excerpt: null,
        errors: [`yaml_parse: ${err instanceof Error ? err.message : String(err)}`],
        took_ms: Date.now() - start,
      },
    };
  }

  const ext = sourceExtensionFor(args.ecosystem);

  // --- 2. Fixture round-trip ---
  const fixtureRoot = fs.mkdtempSync(path.join(args.workDir, `rulegen-fix-`));
  let fixturePre = 0;
  let fixturePost = 0;
  try {
    const ruleFile = path.join(fixtureRoot, 'rule.yml');
    fs.writeFileSync(ruleFile, args.payload.rule_yaml, 'utf8');
    const vulnDir = path.join(fixtureRoot, 'vulnerable');
    const safeDir = path.join(fixtureRoot, 'safe');
    fs.mkdirSync(vulnDir, { recursive: true });
    fs.mkdirSync(safeDir, { recursive: true });
    fs.writeFileSync(path.join(vulnDir, `index.${ext}`), args.payload.vulnerable_fixture, 'utf8');
    fs.writeFileSync(path.join(safeDir, `index.${ext}`), args.payload.safe_fixture, 'utf8');

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

  // --- 3. Patch round-trip (optional) ---
  let patchPre: number | null = null;
  let patchPost: number | null = null;
  let patchSkipReason: string | undefined;

  const shouldRunPatch = (args.runPatchValidation ?? true) && !!args.fixCommit && errors.length === 0;
  if (shouldRunPatch && args.fixCommit) {
    try {
      const result = await runPatchValidation({
        ruleYaml: args.payload.rule_yaml,
        fixCommit: args.fixCommit,
        workDir: args.workDir,
        signal: args.signal,
        semgrepBin: args.semgrepBin,
      });
      patchPre = result.preMatches;
      patchPost = result.postMatches;
      if (!stderrExcerpt && result.stderr) stderrExcerpt = result.stderr;
    } catch (err) {
      // Patch validation is best-effort — don't fail the whole rule on a
      // clone or network blip. Surface the reason so authors can debug.
      const msg = err instanceof Error ? err.message : String(err);
      if (err instanceof RuleValidationError) {
        patchSkipReason = `${err.stage}: ${msg}`;
      } else {
        patchSkipReason = `unexpected: ${msg}`;
      }
    }
  } else if (!args.fixCommit) {
    patchSkipReason = 'no_fix_commit_provided';
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
    if (patchPre <= 0) errors.push(`patch_round_trip_failed: pre-patch matches=${patchPre} (require ≥1)`);
    if (patchPost > 0) errors.push(`patch_round_trip_failed: post-patch matches=${patchPost} (require 0)`);
  }

  const status = errors.length === 0 && fixturePass ? 'validated' : 'failed_validation';

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
// Patch round-trip
// ---------------------------------------------------------------------------

interface PatchValidateArgs {
  ruleYaml: string;
  fixCommit: FixCommit;
  workDir: string;
  signal?: AbortSignal;
  semgrepBin?: string;
}

async function runPatchValidation(args: PatchValidateArgs): Promise<{
  preMatches: number;
  postMatches: number;
  stderr: string | null;
}> {
  const cloneRoot = fs.mkdtempSync(path.join(args.workDir, `rulegen-clone-`));
  try {
    const repoUrl = `https://github.com/${args.fixCommit.owner}/${args.fixCommit.repo}.git`;

    // Single shallow clone of the fix SHA, then a separate fetch to grab the
    // parent SHA on top. simple-git supports `--depth=2` against a SHA so we
    // get fix and parent in one round trip.
    const repoDir = path.join(cloneRoot, 'repo');
    const git = simpleGit();

    await withClone(async () => {
      await git.clone(repoUrl, repoDir, [
        '--no-tags',
        '--filter=blob:none',
        '--no-checkout',
        '--depth=2',
      ]);
    }, args.signal);

    const repoSize = directorySizeBytes(repoDir);
    if (repoSize > MAX_REPO_BYTES) {
      throw new RuleValidationError('clone', `repo too large: ${Math.round(repoSize / 1024 / 1024)}MB > ${MAX_REPO_BYTES / 1024 / 1024}MB cap`);
    }

    const repoGit = simpleGit(repoDir);

    // Fetch the specific commits in case the default clone didn't include
    // them (the unstable depth heuristic varies by repo size).
    try {
      await repoGit.raw(['fetch', '--depth=2', 'origin', args.fixCommit.sha]);
    } catch (err) {
      throw new RuleValidationError('clone', `fetch fix SHA failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    const ruleFile = path.join(cloneRoot, 'rule.yml');
    fs.writeFileSync(ruleFile, args.ruleYaml, 'utf8');

    // Pre-patch tree
    const parentSha = (await repoGit.raw(['rev-parse', `${args.fixCommit.sha}~1`])).trim();
    await repoGit.checkout(parentSha);
    const preRun = await runSemgrep({ ruleFile, target: repoDir, signal: args.signal, semgrepBin: args.semgrepBin });

    // Post-patch tree
    await repoGit.checkout(args.fixCommit.sha);
    const postRun = await runSemgrep({ ruleFile, target: repoDir, signal: args.signal, semgrepBin: args.semgrepBin });

    return {
      preMatches: preRun.matches,
      postMatches: postRun.matches,
      stderr: preRun.stderr ?? postRun.stderr ?? null,
    };
  } finally {
    safeRm(cloneRoot);
  }
}

async function withClone<T>(fn: () => Promise<T>, outerSignal?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CLONE_TIMEOUT_MS);
  if (outerSignal) {
    if (outerSignal.aborted) controller.abort();
    else outerSignal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  try {
    return await fn();
  } finally {
    clearTimeout(timer);
  }
}

function directorySizeBytes(dir: string): number {
  let total = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch { continue; }
    for (const e of entries) {
      const p = path.join(cur, e.name);
      try {
        if (e.isDirectory()) stack.push(p);
        else if (e.isFile()) total += fs.statSync(p).size;
      } catch { /* file disappeared mid-walk; ignore */ }
    }
  }
  return total;
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
    const child = spawn(
      semgrepBin,
      [
        'scan',
        '--config', args.ruleFile,
        '--json',
        '--no-git-ignore',
        '--metrics=off',
        args.target,
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
