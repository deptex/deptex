/**
 * Offline benchmark for the AI rule-generation validation pipeline.
 *
 * Iterates a hand-curated CVE set (mix of ecosystems), treats each platform
 * rule in `reachability-rules/<CVE>/` as the "canned AI payload", fetches the
 * OSV advisory + GitHub patch (cached on disk after first fetch), and runs
 * the real validateRule with Semgrep against the patch's changed files.
 *
 * Acts as both an iteration harness (rerun cheaply while tweaking validation
 * logic) and a regression sentinel (the platform rules are known-good, so
 * validation rate should stay near 100%; a drop signals validate.ts broke
 * something).
 *
 * Usage:
 *   npm run bench:rule-generation
 *   npm run bench:rule-generation -- --refresh           # force re-fetch OSV + patch
 *   npm run bench:rule-generation -- --no-network        # cache-only; fail on miss
 *   npm run bench:rule-generation -- --limit=3           # run first N
 *   npm run bench:rule-generation -- --threshold=15      # exit 1 if rate < N%
 *   npm run bench:rule-generation -- --prompt-version=v3 # label only — for future head-to-head
 *
 * Cache lives under test/fixtures/bench-cache/<CVE>/{osv.json,patch.json}.
 *
 * Requires Semgrep on PATH (`pip install semgrep`). On Windows the host's
 * Python launcher install often ships a non-functional stub; run from WSL,
 * a Linux dev box, or inside the deptex-cli Docker image instead.
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import * as yaml from 'js-yaml';
import {
  fetchOsvAdvisory,
  extractFixCommits,
  type OsvAdvisory,
  type FixCommit,
} from '../src/rule-generator/osv-fetch';
import { fetchPatchInfo, type PatchInfo } from '../src/rule-generator/patch-fetch';
import { validateRule, makeRuleGenWorkdir } from '../src/rule-generator/validate';
import type { GeneratedPayload } from '../src/rule-generator/generate';

const REPO_ROOT = path.resolve(__dirname, '..');
const RULES_DIR = path.join(REPO_ROOT, 'reachability-rules');
const CACHE_DIR = path.join(REPO_ROOT, 'test', 'fixtures', 'bench-cache');
const REPORT_PATH = path.join(CACHE_DIR, 'last-run.md');

interface BenchCase {
  /** CVE folder name under reachability-rules/. */
  ruleDirName: string;
}

/**
 * Curated set: 8 CVEs spanning npm/pypi/maven/golang. Each is a known-good
 * platform rule, so the bench should report close to 100% validation when
 * everything works. A drop pinpoints which validation gate regressed.
 */
const BENCH_CASES: BenchCase[] = [
  { ruleDirName: 'CVE-2021-23337-lodash-template' },
  { ruleDirName: 'CVE-2021-44906-minimist-proto-pollution' },
  { ruleDirName: 'CVE-2022-23529-jsonwebtoken-key-confusion' },
  { ruleDirName: 'CVE-2020-14343-pyyaml-unsafe-load' },
  { ruleDirName: 'CVE-2024-22195-jinja2-xmlattr-ssti' },
  { ruleDirName: 'CVE-2021-44228-log4j-log4shell' },
  { ruleDirName: 'CVE-2022-42889-commons-text-text4shell' },
  { ruleDirName: 'CVE-2022-32149-golang-text-parse-dos' },
];

interface CliFlags {
  refresh: boolean;
  noNetwork: boolean;
  limit: number;
  threshold: number;
  /** Optional label surfaced in the report header. Reserved for the future
   *  prompt-vs-prompt comparison pass — accepted but not consumed yet because
   *  this milestone bypasses the AI call entirely (canned payloads). */
  promptVersion: string | null;
}

function parseFlags(argv: string[]): CliFlags {
  const flags: CliFlags = { refresh: false, noNetwork: false, limit: Infinity, threshold: 0, promptVersion: null };
  for (const arg of argv) {
    if (arg === '--refresh') flags.refresh = true;
    else if (arg === '--no-network') flags.noNetwork = true;
    else if (arg.startsWith('--limit=')) flags.limit = parseInt(arg.slice('--limit='.length), 10);
    else if (arg.startsWith('--threshold=')) flags.threshold = parseFloat(arg.slice('--threshold='.length));
    else if (arg.startsWith('--prompt-version=')) flags.promptVersion = arg.slice('--prompt-version='.length);
  }
  return flags;
}

interface CannedPayload {
  cveId: string;
  packageName: string;
  ecosystem: string;
  payload: GeneratedPayload;
}

/**
 * Read a platform rule pack and synthesize a GeneratedPayload identical in
 * shape to what the AI would produce. The platform rules don't carry the
 * AI-specific fields (reachability_level, entry_point_class), so we default
 * them — they're only used for persistence, not validation.
 */
function loadCannedPayload(ruleDirName: string): CannedPayload | null {
  const dir = path.join(RULES_DIR, ruleDirName);
  const rulePath = path.join(dir, 'rule.yml');
  const fixturesDir = path.join(dir, '__fixtures__');
  if (!fs.existsSync(rulePath) || !fs.existsSync(fixturesDir)) return null;

  const ruleYaml = fs.readFileSync(rulePath, 'utf8');
  const parsed = yaml.load(ruleYaml) as { rules?: Array<{ metadata?: Record<string, unknown> }> } | null;
  const meta = parsed?.rules?.[0]?.metadata ?? {};
  const cveId = String(meta.cve ?? '');
  const packageName = String(meta.package ?? '');
  const ecosystem = String(meta.ecosystem ?? '');
  if (!cveId || !packageName || !ecosystem) return null;

  const vulnerable = readFirstFixture(fixturesDir, 'vulnerable');
  const safe = readFirstFixture(fixturesDir, 'safe');
  if (vulnerable === null || safe === null) return null;

  return {
    cveId,
    packageName,
    ecosystem,
    payload: {
      rule_yaml: ruleYaml,
      vulnerable_fixture: vulnerable,
      safe_fixture: safe,
      reachability_level: 'function',
      entry_point_class: 'PUBLIC_UNAUTH',
      rationale: '',
    },
  };
}

const FIXTURE_EXTS = ['js', 'ts', 'py', 'java', 'go', 'rb', 'php', 'rs', 'cs'];
function readFirstFixture(fixturesDir: string, baseName: string): string | null {
  for (const ext of FIXTURE_EXTS) {
    const p = path.join(fixturesDir, `${baseName}.${ext}`);
    if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
  }
  return null;
}

async function loadAdvisory(cveId: string, flags: CliFlags): Promise<OsvAdvisory | null> {
  const cacheFile = path.join(CACHE_DIR, cveId, 'osv.json');
  if (!flags.refresh && fs.existsSync(cacheFile)) {
    return JSON.parse(fs.readFileSync(cacheFile, 'utf8')) as OsvAdvisory;
  }
  if (flags.noNetwork) {
    throw new Error(`OSV cache miss for ${cveId} and --no-network is set`);
  }
  const advisory = await fetchOsvAdvisory(cveId);
  if (advisory) {
    fs.mkdirSync(path.dirname(cacheFile), { recursive: true });
    fs.writeFileSync(cacheFile, JSON.stringify(advisory, null, 2), 'utf8');
  }
  return advisory;
}

async function loadPatch(cveId: string, fixCommit: FixCommit, flags: CliFlags): Promise<PatchInfo> {
  const cacheFile = path.join(CACHE_DIR, cveId, 'patch.json');
  if (!flags.refresh && fs.existsSync(cacheFile)) {
    return JSON.parse(fs.readFileSync(cacheFile, 'utf8')) as PatchInfo;
  }
  if (flags.noNetwork) {
    throw new Error(`Patch cache miss for ${cveId} and --no-network is set`);
  }
  const patch = await fetchPatchInfo(fixCommit, { githubToken: process.env.GITHUB_TOKEN });
  fs.mkdirSync(path.dirname(cacheFile), { recursive: true });
  fs.writeFileSync(cacheFile, JSON.stringify(patch, null, 2), 'utf8');
  return patch;
}

interface BenchResult {
  cveId: string;
  ecosystem: string;
  status: 'validated' | 'failed_validation' | 'no_advisory' | 'no_fix_commit' | 'fetch_failed' | 'load_failed';
  schemaPass: boolean;
  fixturePre: number | null;
  fixtureSafe: boolean | null;
  patchPre: number | null;
  patchPost: number | null;
  reason: string;
  durationMs: number;
}

/**
 * On Windows, Node's spawn doesn't apply PATHEXT to resolve the executable, so
 * `spawn('semgrep', ...)` fails to launch even when `semgrep` is on PATH.
 * `semgrep.exe` (the actual binary) resolves cleanly. On macOS/Linux 'semgrep'
 * is correct.
 */
function resolveSemgrepBin(): string {
  return process.platform === 'win32' ? 'semgrep.exe' : 'semgrep';
}

function checkSemgrepInstalled(bin: string): void {
  const probe = spawnSync(bin, ['--version'], { encoding: 'utf8' });
  if (probe.error || probe.status !== 0) {
    console.error(`${bin} is not on PATH. Install it first:`);
    console.error('  pip install semgrep   # or:   brew install semgrep');
    process.exit(2);
  }
}

async function runOne(caseItem: BenchCase, flags: CliFlags, workDir: string, semgrepBin: string): Promise<BenchResult> {
  const start = Date.now();
  const canned = loadCannedPayload(caseItem.ruleDirName);
  if (!canned) {
    return {
      cveId: caseItem.ruleDirName,
      ecosystem: 'unknown',
      status: 'load_failed',
      schemaPass: false,
      fixturePre: null,
      fixtureSafe: null,
      patchPre: null,
      patchPost: null,
      reason: 'failed to load rule.yml or fixtures',
      durationMs: Date.now() - start,
    };
  }

  let advisory: OsvAdvisory | null;
  try {
    advisory = await loadAdvisory(canned.cveId, flags);
  } catch (err) {
    return {
      cveId: canned.cveId,
      ecosystem: canned.ecosystem,
      status: 'fetch_failed',
      schemaPass: false,
      fixturePre: null,
      fixtureSafe: null,
      patchPre: null,
      patchPost: null,
      reason: `osv: ${err instanceof Error ? err.message : String(err)}`,
      durationMs: Date.now() - start,
    };
  }
  if (!advisory) {
    return {
      cveId: canned.cveId,
      ecosystem: canned.ecosystem,
      status: 'no_advisory',
      schemaPass: false,
      fixturePre: null,
      fixtureSafe: null,
      patchPre: null,
      patchPost: null,
      reason: 'osv returned 404',
      durationMs: Date.now() - start,
    };
  }

  const fixCommit = extractFixCommits(advisory)[0];
  let changedFiles: PatchInfo['changedFiles'] = [];
  let patchSkipReason = '';
  if (!fixCommit) {
    patchSkipReason = 'no_fix_commit';
  } else {
    try {
      const patchInfo = await loadPatch(canned.cveId, fixCommit, flags);
      changedFiles = patchInfo.changedFiles;
    } catch (err) {
      patchSkipReason = `patch: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  const validation = await validateRule({
    payload: canned.payload,
    cveId: canned.cveId,
    ecosystem: canned.ecosystem,
    changedFiles: changedFiles.length > 0 ? changedFiles : undefined,
    workDir,
    semgrepBin,
  });

  const log = validation.log;
  const breakdown = log.validation_breakdown;

  const reason =
    validation.status === 'validated'
      ? '—'
      : log.errors.slice(0, 2).join(' | ').slice(0, 180) ||
        patchSkipReason ||
        'unknown';

  return {
    cveId: canned.cveId,
    ecosystem: canned.ecosystem,
    status: validation.status,
    schemaPass: breakdown.schema_pass,
    fixturePre: log.fixture_pre_matches,
    fixtureSafe: breakdown.fixture_safe_clean,
    patchPre: log.patch_pre_matches,
    patchPost: log.patch_post_matches,
    reason,
    durationMs: Date.now() - start,
  };
}

function renderReport(results: BenchResult[], flags: CliFlags): string {
  const validated = results.filter((r) => r.status === 'validated').length;
  const rate = results.length > 0 ? (validated / results.length) * 100 : 0;
  const totalMs = results.reduce((s, r) => s + r.durationMs, 0);

  const lines: string[] = [];
  lines.push(`# Rule-generation bench — ${new Date().toISOString()}`);
  lines.push('');
  lines.push(`- Cases: **${results.length}**`);
  lines.push(`- Validated: **${validated}** (**${rate.toFixed(1)}%**)`);
  lines.push(`- Total duration: ${(totalMs / 1000).toFixed(1)}s`);
  lines.push(`- Threshold: ${flags.threshold > 0 ? `${flags.threshold}%` : 'none'}`);
  if (flags.promptVersion) lines.push(`- Prompt version label: ${flags.promptVersion}`);
  lines.push('');
  lines.push('| CVE | ecosystem | status | schema | fix_pre | safe_clean | patch_pre | patch_post | dur | reason |');
  lines.push('|---|---|---|---|---|---|---|---|---|---|');
  for (const r of results) {
    const dur = `${(r.durationMs / 1000).toFixed(1)}s`;
    const fmt = (v: number | boolean | null) =>
      v === null ? '—' : typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v);
    lines.push(
      `| ${r.cveId} | ${r.ecosystem} | ${r.status} | ${fmt(r.schemaPass)} | ${fmt(r.fixturePre)} | ${fmt(r.fixtureSafe)} | ${fmt(r.patchPre)} | ${fmt(r.patchPost)} | ${dur} | ${r.reason.replace(/\|/g, '\\|')} |`,
    );
  }
  lines.push('');
  return lines.join('\n');
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const semgrepBin = resolveSemgrepBin();
  checkSemgrepInstalled(semgrepBin);

  const cases = BENCH_CASES.slice(0, flags.limit);
  console.log(`Running ${cases.length} bench case(s)…`);
  if (flags.refresh) console.log('  --refresh: re-fetching OSV + patch from network');
  if (flags.noNetwork) console.log('  --no-network: cache-only mode');

  fs.mkdirSync(CACHE_DIR, { recursive: true });
  const workDir = makeRuleGenWorkdir();

  const results: BenchResult[] = [];
  try {
    for (const c of cases) {
      const r = await runOne(c, flags, workDir, semgrepBin);
      const tag = r.status === 'validated' ? 'OK' : 'FAIL';
      console.log(`  [${tag}] ${r.cveId} (${r.ecosystem}) — ${r.status} — ${(r.durationMs / 1000).toFixed(1)}s`);
      results.push(r);
    }
  } finally {
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch { /* non-fatal */ }
  }

  const report = renderReport(results, flags);
  fs.writeFileSync(REPORT_PATH, report, 'utf8');
  console.log('\n' + report);
  console.log(`\nReport written to ${path.relative(REPO_ROOT, REPORT_PATH)}`);

  const validated = results.filter((r) => r.status === 'validated').length;
  const rate = results.length > 0 ? (validated / results.length) * 100 : 0;
  if (flags.threshold > 0 && rate < flags.threshold) {
    console.error(`\nFAIL: validation rate ${rate.toFixed(1)}% < threshold ${flags.threshold}%`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('bench crashed:', err);
  process.exit(1);
});
