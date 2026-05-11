/**
 * OSS corpus runner — clones N public repos, runs the local depscanner CLI
 * against each, then computes recall / noise / cost / duration metrics
 * against a ground-truth CVE list.
 *
 * Continuous testing harness for the depscanner hardening marathon. The
 * previous marathon shipped zero OSS corpus scans — this script is the
 * mechanism that closes that gap. Future ticks rerun it after engine
 * changes to measure delta.
 *
 * Usage (from the depscanner/ directory):
 *
 *   npm run scan:oss-corpus -- --repos=scripts/oss-corpus.yaml \
 *     --output=oss-corpus-runs/$(date +%Y-%m-%d) \
 *     [--parallel=3] [--only=express,gin] [--skip-clone]
 *
 * Flags:
 *   --repos=<path>   Required. YAML or JSON corpus file (see oss-corpus.yaml).
 *   --output=<dir>   Required. Where per-repo artifacts + report.json land.
 *   --parallel=<n>   How many scans to run concurrently (default 2). Docker
 *                    is the bottleneck — going much past 3 thrashes.
 *   --only=<csv>     Restrict to a subset by `name`. Useful for re-running
 *                    a single repo after a fix.
 *   --skip-clone     Reuse an existing workspace dir under
 *                    <output>/workspaces/<name>/ . Saves ~5min on reruns.
 *   --no-rule-gen    Disable AI rule generation (DEPTEX_RULE_GENERATION_ENABLED).
 *                    Default: on if DEEPINFRA_API_KEY is set.
 *   --scan-timeout=<sec>
 *                    Per-scan wall-time cap (default 600s). On timeout the
 *                    repo is marked as a failure mode in the report.
 *
 * Output layout:
 *   <output>/
 *     workspaces/<repo>/              # shallow clone
 *     runs/<repo>/                    # depscanner --output dir
 *       summary.json, vulns.json, reachable_flows.json, ...
 *       stdout.json, stderr.log       # captured streams
 *     report.json                     # aggregated metrics
 *     report.md                       # human-readable summary
 *
 * Exit codes: 0 = harness ran (per-repo failures are captured, not fatal),
 *             2 = harness misconfigured (bad YAML, missing depscanner image).
 */

import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import * as os from 'node:os';

// ---------------------------------------------------------------------------
// Corpus schema
// ---------------------------------------------------------------------------

interface GroundTruthCve {
  id: string;
  expected_reachability: 'confirmed' | 'data_flow' | 'function' | 'module';
  source: string;
}

interface CorpusRepo {
  name: string;
  repo_url: string;
  ecosystem: 'npm' | 'pypi' | 'maven' | 'golang' | 'cargo' | 'gem' | 'composer';
  framework?: string;
  ref?: string;
  ground_truth_cves: GroundTruthCve[];
  expected_min_findings?: number;
  skip?: string;
  notes?: string;
}

interface Corpus {
  repos: CorpusRepo[];
}

interface RepoResult {
  name: string;
  ecosystem: string;
  framework?: string;
  ref?: string;
  status: 'ok' | 'clone_failed' | 'scan_failed' | 'scan_timeout' | 'skipped';
  failure_reason?: string;
  scan_duration_ms?: number;
  total_findings?: number;
  reachable_findings?: number;
  ai_cost_usd?: number;
  ground_truth_total: number;
  ground_truth_matched: GroundTruthMatch[];
  recall_pct?: number;
  noise_count?: number;
  noise_examples?: NoiseExample[];
  missed_examples?: MissedExample[];
  // Forensic raw counts so report.md can sanity-check.
  dependencies_count?: number;
  semgrep_count?: number;
  secrets_count?: number;
}

interface GroundTruthMatch {
  cve: string;
  observed: boolean;
  observed_reachability?: string | null;
  observed_severity?: string | null;
  expected_reachability: string;
}

interface NoiseExample {
  osv_id: string;
  package: string;
  reachability_level: string | null;
  reason: string;
}

interface MissedExample {
  cve: string;
  expected_reachability: string;
  source: string;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseFlags(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (const a of argv) {
    if (!a.startsWith('--')) continue;
    const eq = a.indexOf('=');
    if (eq < 0) out[a.slice(2)] = true;
    else out[a.slice(2, eq)] = a.slice(eq + 1);
  }
  return out;
}

function die(msg: string, code = 2): never {
  process.stderr.write(`[oss-corpus] ${msg}\n`);
  process.exit(code);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadCorpus(file: string): Corpus {
  const text = fs.readFileSync(file, 'utf8');
  const parsed = file.endsWith('.json') ? JSON.parse(text) : (yaml.load(text) as any);
  if (!parsed || !Array.isArray(parsed.repos)) {
    die(`corpus file has no 'repos' array: ${file}`);
  }
  return parsed as Corpus;
}

function execCapture(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number } = {},
): Promise<{ code: number; stdout: string; stderr: string; durationMs: number; timedOut: boolean }> {
  return new Promise((resolve) => {
    const start = Date.now();
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const proc = spawn(cmd, args, {
      cwd: opts.cwd,
      env: { ...process.env, ...(opts.env ?? {}) },
      // Use shell on Windows so `./bin/deptex-scan` (a bash script) resolves
      // through Git Bash. Without shell, spawn looks for an .exe on PATH.
      shell: process.platform === 'win32',
    });

    proc.stdout.on('data', (b) => (stdout += b.toString()));
    proc.stderr.on('data', (b) => (stderr += b.toString()));

    let timer: NodeJS.Timeout | undefined;
    if (opts.timeoutMs) {
      timer = setTimeout(() => {
        timedOut = true;
        try {
          proc.kill('SIGKILL');
        } catch {
          /* noop */
        }
      }, opts.timeoutMs);
    }

    proc.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({
        code: code ?? -1,
        stdout,
        stderr,
        durationMs: Date.now() - start,
        timedOut,
      });
    });
  });
}

async function cloneRepo(
  repo: CorpusRepo,
  workspaceDir: string,
  skipIfPresent: boolean,
): Promise<{ ok: boolean; reason?: string }> {
  if (skipIfPresent && fs.existsSync(path.join(workspaceDir, '.git'))) {
    return { ok: true };
  }
  if (fs.existsSync(workspaceDir)) {
    fs.rmSync(workspaceDir, { recursive: true, force: true });
  }
  fs.mkdirSync(path.dirname(workspaceDir), { recursive: true });

  // Always shallow clone. If a ref is pinned, fetch that ref specifically.
  const args = ['clone', '--depth=1'];
  if (repo.ref) args.push('--branch', repo.ref);
  args.push(repo.repo_url, workspaceDir);

  const res = await execCapture('git', args, { timeoutMs: 180_000 });
  if (res.code !== 0) {
    return {
      ok: false,
      reason: `git clone exited ${res.code}: ${res.stderr.split('\n').slice(-3).join(' | ')}`,
    };
  }
  return { ok: true };
}

function loadEnvFromBackend(): NodeJS.ProcessEnv {
  // Forward AI keys from backend/.env so the in-container pipeline can run
  // rule generation + EPD without a separate worktree-level .env file.
  const envPath = path.resolve(__dirname, '../../backend/.env');
  const out: NodeJS.ProcessEnv = {};
  if (!fs.existsSync(envPath)) return out;
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = /^([A-Z_][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (!m) continue;
    const [, key, rawVal] = m;
    if (
      key === 'OPENAI_API_KEY' ||
      key === 'ANTHROPIC_API_KEY' ||
      key === 'DEEPINFRA_API_KEY' ||
      key === 'GOOGLE_AI_API_KEY' ||
      key === 'GITHUB_TOKEN' ||
      key === 'GITHUB_PAT'
    ) {
      out[key] = rawVal.replace(/^"|"$/g, '');
    }
  }
  return out;
}

async function runDepscanner(
  repo: CorpusRepo,
  workspaceDir: string,
  outputDir: string,
  env: NodeJS.ProcessEnv,
  timeoutMs: number,
): Promise<{
  status: 'ok' | 'scan_failed' | 'scan_timeout';
  reason?: string;
  durationMs: number;
}> {
  fs.mkdirSync(outputDir, { recursive: true });

  const repoRoot = path.resolve(__dirname, '..');
  const scanBin = path.resolve(repoRoot, 'bin/deptex-scan');
  const args = [
    'run',
    workspaceDir,
    `--output=${outputDir}`,
    `--ecosystem=${repo.ecosystem}`,
    `--label=${repo.name}`,
    '--quiet',
    '--format=json',
  ];

  const res = await execCapture(scanBin, args, { env, timeoutMs });

  // Mirror raw streams to disk for forensic review.
  fs.writeFileSync(path.join(outputDir, 'stdout.json'), res.stdout);
  fs.writeFileSync(path.join(outputDir, 'stderr.log'), res.stderr);

  if (res.timedOut) {
    return {
      status: 'scan_timeout',
      reason: `scan exceeded ${(timeoutMs / 1000) | 0}s`,
      durationMs: res.durationMs,
    };
  }
  // Exit 0 = clean. Exit 1 = findings above --fail-on (we don't set one, so
  // shouldn't occur). Exit 2 = pipeline error. We treat any non-zero as
  // "scan ran but produced something we should look at" rather than fatal,
  // since the per-finding JSON may still be partially populated.
  if (res.code !== 0 && !fs.existsSync(path.join(outputDir, 'summary.json'))) {
    return {
      status: 'scan_failed',
      reason: `scan exited ${res.code}: ${res.stderr.split('\n').filter(Boolean).slice(-3).join(' | ')}`,
      durationMs: res.durationMs,
    };
  }
  return { status: 'ok', durationMs: res.durationMs };
}

function readJson<T = any>(file: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
  } catch {
    return fallback;
  }
}

interface AnalysisInput {
  repo: CorpusRepo;
  outputDir: string;
  scanDurationMs: number;
  status: 'ok' | 'scan_failed' | 'scan_timeout' | 'clone_failed' | 'skipped';
  failureReason?: string;
}

function analyse(input: AnalysisInput): RepoResult {
  const base: RepoResult = {
    name: input.repo.name,
    ecosystem: input.repo.ecosystem,
    framework: input.repo.framework,
    ref: input.repo.ref,
    status: input.status,
    failure_reason: input.failureReason,
    scan_duration_ms: input.scanDurationMs,
    ground_truth_total: input.repo.ground_truth_cves.length,
    ground_truth_matched: input.repo.ground_truth_cves.map((gt) => ({
      cve: gt.id,
      observed: false,
      expected_reachability: gt.expected_reachability,
    })),
  };

  if (input.status !== 'ok') {
    base.missed_examples = input.repo.ground_truth_cves.map((gt) => ({
      cve: gt.id,
      expected_reachability: gt.expected_reachability,
      source: gt.source,
    }));
    return base;
  }

  const vulns = readJson<any[]>(path.join(input.outputDir, 'vulns.json'), []);
  const flows = readJson<any[]>(path.join(input.outputDir, 'reachable_flows.json'), []);
  const deps = readJson<any[]>(path.join(input.outputDir, 'deps.json'), []);
  const semgrep = readJson<any[]>(path.join(input.outputDir, 'semgrep.json'), []);
  const secrets = readJson<any[]>(path.join(input.outputDir, 'secrets.json'), []);
  const summary = readJson<any>(path.join(input.outputDir, 'summary.json'), {});
  const ruleGenTel = readJson<any[]>(
    path.join(input.outputDir, 'rule_generation_telemetry.json'),
    [],
  );

  base.total_findings = vulns.length;
  base.reachable_findings = vulns.filter((v) => v?.is_reachable).length;
  base.dependencies_count = deps.length;
  base.semgrep_count = semgrep.length;
  base.secrets_count = secrets.length;
  base.ai_cost_usd = ruleGenTel.reduce(
    (acc: number, t: any) => acc + (Number(t?.generation_cost_usd) || 0),
    0,
  );

  // Index vulns by CVE / alias for ground-truth matching.
  const observedByCve = new Map<string, any>();
  for (const v of vulns) {
    const ids: string[] = [];
    if (v?.osv_id) ids.push(String(v.osv_id));
    if (Array.isArray(v?.aliases)) ids.push(...v.aliases.map(String));
    for (const id of ids) {
      if (/^CVE-\d{4}-\d+$/i.test(id)) observedByCve.set(id.toUpperCase(), v);
    }
  }

  const missed: MissedExample[] = [];
  for (const match of base.ground_truth_matched) {
    const v = observedByCve.get(match.cve.toUpperCase());
    if (v) {
      match.observed = true;
      match.observed_reachability = v.reachability_level ?? null;
      match.observed_severity = v.severity ?? null;
    } else {
      const gt = input.repo.ground_truth_cves.find((g) => g.id === match.cve)!;
      missed.push({
        cve: match.cve,
        expected_reachability: match.expected_reachability,
        source: gt.source,
      });
    }
  }
  base.missed_examples = missed;

  const observedSet = new Set(
    Array.from(observedByCve.keys()).map((k) => k.toUpperCase()),
  );
  const expectedSet = new Set(
    input.repo.ground_truth_cves.map((g) => g.id.toUpperCase()),
  );

  base.recall_pct =
    expectedSet.size === 0
      ? 100
      : Math.round(
          (Array.from(expectedSet).filter((c) => observedSet.has(c)).length /
            expectedSet.size) *
            10000,
        ) / 100;

  // Noise = high-severity reachable findings NOT in ground truth. This is a
  // proxy: real noise requires manual triage. We surface the top 5 as
  // examples to seed the docs/oss-corpus-*.md report.
  const noiseCandidates = vulns
    .filter((v) => v?.is_reachable && !expectedSet.has(String(v?.osv_id || '').toUpperCase()))
    .filter((v) => ['critical', 'high'].includes(String(v?.severity || '').toLowerCase()));
  base.noise_count = noiseCandidates.length;

  const depById = new Map<string, { name: string; version: string }>();
  for (const d of deps) {
    if (d?.id) depById.set(d.id, { name: d.name, version: d.version });
  }
  base.noise_examples = noiseCandidates.slice(0, 5).map((v) => {
    const dep = v?.project_dependency_id ? depById.get(v.project_dependency_id) : undefined;
    return {
      osv_id: v.osv_id ?? 'UNKNOWN',
      package: dep ? `${dep.name}@${dep.version}` : '?',
      reachability_level: v.reachability_level ?? null,
      reason: 'reachable + high/critical but not in ground-truth allowlist',
    };
  });

  return base;
}

// ---------------------------------------------------------------------------
// Aggregate reporting
// ---------------------------------------------------------------------------

function aggregate(results: RepoResult[]): {
  total_repos: number;
  scanned: number;
  failed: number;
  avg_recall_pct: number;
  total_ground_truth: number;
  total_matched: number;
  total_noise: number;
  total_ai_cost_usd: number;
  total_duration_ms: number;
  per_ecosystem: Record<string, { scanned: number; recall_pct: number; ground_truth: number; matched: number }>;
} {
  const scanned = results.filter((r) => r.status === 'ok');
  const totalGt = results.reduce((s, r) => s + r.ground_truth_total, 0);
  const totalMatched = results.reduce(
    (s, r) => s + r.ground_truth_matched.filter((m) => m.observed).length,
    0,
  );
  const perEco: Record<string, { scanned: number; recall_pct: number; ground_truth: number; matched: number }> = {};
  for (const r of results) {
    if (!perEco[r.ecosystem]) {
      perEco[r.ecosystem] = { scanned: 0, recall_pct: 0, ground_truth: 0, matched: 0 };
    }
    perEco[r.ecosystem].ground_truth += r.ground_truth_total;
    perEco[r.ecosystem].matched += r.ground_truth_matched.filter((m) => m.observed).length;
    if (r.status === 'ok') perEco[r.ecosystem].scanned += 1;
  }
  for (const eco of Object.keys(perEco)) {
    const g = perEco[eco];
    g.recall_pct = g.ground_truth === 0 ? 0 : Math.round((g.matched / g.ground_truth) * 10000) / 100;
  }
  return {
    total_repos: results.length,
    scanned: scanned.length,
    failed: results.length - scanned.length,
    avg_recall_pct: totalGt === 0 ? 0 : Math.round((totalMatched / totalGt) * 10000) / 100,
    total_ground_truth: totalGt,
    total_matched: totalMatched,
    total_noise: results.reduce((s, r) => s + (r.noise_count ?? 0), 0),
    total_ai_cost_usd: Math.round(results.reduce((s, r) => s + (r.ai_cost_usd ?? 0), 0) * 10000) / 10000,
    total_duration_ms: results.reduce((s, r) => s + (r.scan_duration_ms ?? 0), 0),
    per_ecosystem: perEco,
  };
}

function renderMarkdown(results: RepoResult[], agg: ReturnType<typeof aggregate>): string {
  const lines: string[] = [];
  lines.push('# OSS corpus baseline');
  lines.push('');
  lines.push(`- Date: ${new Date().toISOString()}`);
  lines.push(`- Repos: ${agg.total_repos} (${agg.scanned} scanned ok, ${agg.failed} failed)`);
  lines.push(`- Aggregate recall: **${agg.avg_recall_pct}%** (${agg.total_matched}/${agg.total_ground_truth} ground-truth CVEs)`);
  lines.push(`- Noise (reachable + high/critical, not in ground-truth): ${agg.total_noise}`);
  lines.push(`- Total scan duration: ${(agg.total_duration_ms / 60_000).toFixed(1)} min`);
  lines.push(`- Total AI cost: $${agg.total_ai_cost_usd.toFixed(4)}`);
  lines.push('');
  lines.push('## Per-ecosystem');
  lines.push('');
  lines.push('| Ecosystem | Scanned | Ground-truth | Matched | Recall |');
  lines.push('|---|---|---|---|---|');
  for (const eco of Object.keys(agg.per_ecosystem).sort()) {
    const g = agg.per_ecosystem[eco];
    lines.push(`| ${eco} | ${g.scanned} | ${g.ground_truth} | ${g.matched} | ${g.recall_pct}% |`);
  }
  lines.push('');
  lines.push('## Per-repo');
  lines.push('');
  lines.push('| Repo | Eco | Framework | Status | Findings | Reachable | GT match | Recall | Noise | Duration | AI cost |');
  lines.push('|---|---|---|---|---|---|---|---|---|---|---|');
  for (const r of results) {
    const matched = r.ground_truth_matched.filter((m) => m.observed).length;
    lines.push(
      [
        r.name,
        r.ecosystem,
        r.framework ?? '-',
        r.status,
        r.total_findings ?? '-',
        r.reachable_findings ?? '-',
        `${matched}/${r.ground_truth_total}`,
        r.recall_pct != null ? `${r.recall_pct}%` : '-',
        r.noise_count ?? '-',
        r.scan_duration_ms != null ? `${(r.scan_duration_ms / 1000).toFixed(0)}s` : '-',
        r.ai_cost_usd != null ? `$${r.ai_cost_usd.toFixed(4)}` : '-',
      ]
        .map((v) => `| ${v} `)
        .join('') + '|',
    );
  }
  lines.push('');
  lines.push('## Failure modes');
  lines.push('');
  const failures = results.filter((r) => r.status !== 'ok');
  if (failures.length === 0) {
    lines.push('_None._');
  } else {
    for (const f of failures) {
      lines.push(`- **${f.name}** (${f.status}): ${f.failure_reason ?? '-'}`);
    }
  }
  lines.push('');
  lines.push('## Missed (in ground-truth, not flagged)');
  lines.push('');
  const allMissed = results.flatMap((r) =>
    (r.missed_examples ?? []).map((m) => ({ repo: r.name, ...m })),
  );
  if (allMissed.length === 0) {
    lines.push('_None._');
  } else {
    for (const m of allMissed) {
      lines.push(`- **${m.cve}** in \`${m.repo}\` (expected ${m.expected_reachability}) — ${m.source}`);
    }
  }
  lines.push('');
  lines.push('## Noise examples (reachable + high/critical, not in ground-truth)');
  lines.push('');
  const allNoise = results.flatMap((r) =>
    (r.noise_examples ?? []).map((n) => ({ repo: r.name, ...n })),
  );
  if (allNoise.length === 0) {
    lines.push('_None._');
  } else {
    for (const n of allNoise) {
      lines.push(`- ${n.osv_id} in \`${n.repo}\` :: ${n.package} (reachability=${n.reachability_level ?? '?'}) — ${n.reason}`);
    }
  }
  lines.push('');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const flags = parseFlags(process.argv.slice(2));
  if (!flags.repos) die('--repos=<corpus.yaml> is required');
  if (!flags.output) die('--output=<dir> is required');

  const corpusPath = path.resolve(String(flags.repos));
  const outputRoot = path.resolve(String(flags.output));
  fs.mkdirSync(outputRoot, { recursive: true });

  const parallel = Number(flags.parallel ?? 2);
  const scanTimeoutMs = Number(flags['scan-timeout'] ?? 600) * 1000;
  const onlyFilter = typeof flags.only === 'string'
    ? new Set(flags.only.split(',').map((s) => s.trim()))
    : null;
  const skipClone = !!flags['skip-clone'];

  const corpus = loadCorpus(corpusPath);
  const queue = corpus.repos.filter((r) => !onlyFilter || onlyFilter.has(r.name));
  if (queue.length === 0) die('no repos selected — check --only=...');

  const env = loadEnvFromBackend();
  // Rule generation: opt-out via --no-rule-gen. Default on if a DeepInfra
  // key is available (matches the marathon's existing rule-gen plumbing).
  if (!flags['no-rule-gen'] && env.DEEPINFRA_API_KEY) {
    env.DEPTEX_RULE_GENERATION_ENABLED = '1';
    env.DEPTEX_RULE_PROVIDER = process.env.DEPTEX_RULE_PROVIDER ?? 'openai_compatible';
    env.DEPTEX_RULE_BASE_URL =
      process.env.DEPTEX_RULE_BASE_URL ?? 'https://api.deepinfra.com/v1/openai';
    env.DEPTEX_RULE_MODEL = process.env.DEPTEX_RULE_MODEL ?? 'Qwen/Qwen2.5-Coder-32B-Instruct';
    env.DEPTEX_RULE_BUDGET_USD = process.env.DEPTEX_RULE_BUDGET_USD ?? '0.50';
  }

  process.stdout.write(
    `[oss-corpus] running ${queue.length} repos (parallel=${parallel}, scan-timeout=${scanTimeoutMs / 1000}s)\n`,
  );

  const results: RepoResult[] = [];
  // Simple promise pool — no `p-limit` dep needed at this scale.
  const inflight: Promise<void>[] = [];
  let idx = 0;

  async function runOne(repo: CorpusRepo): Promise<void> {
    if (repo.skip) {
      results.push({
        name: repo.name,
        ecosystem: repo.ecosystem,
        framework: repo.framework,
        ref: repo.ref,
        status: 'skipped',
        failure_reason: repo.skip,
        ground_truth_total: repo.ground_truth_cves.length,
        ground_truth_matched: repo.ground_truth_cves.map((gt) => ({
          cve: gt.id,
          observed: false,
          expected_reachability: gt.expected_reachability,
        })),
        missed_examples: repo.ground_truth_cves.map((gt) => ({
          cve: gt.id,
          expected_reachability: gt.expected_reachability,
          source: gt.source,
        })),
      });
      return;
    }

    const wsDir = path.join(outputRoot, 'workspaces', repo.name);
    const runDir = path.join(outputRoot, 'runs', repo.name);
    fs.mkdirSync(runDir, { recursive: true });

    process.stdout.write(`[oss-corpus] ${repo.name}: cloning ${repo.repo_url}${repo.ref ? `@${repo.ref}` : ''}\n`);
    const clone = await cloneRepo(repo, wsDir, skipClone);
    if (!clone.ok) {
      results.push(
        analyse({
          repo,
          outputDir: runDir,
          scanDurationMs: 0,
          status: 'clone_failed',
          failureReason: clone.reason,
        }),
      );
      process.stdout.write(`[oss-corpus] ${repo.name}: CLONE FAILED — ${clone.reason}\n`);
      return;
    }

    process.stdout.write(`[oss-corpus] ${repo.name}: scanning (timeout ${scanTimeoutMs / 1000}s)\n`);
    const scanRes = await runDepscanner(repo, wsDir, runDir, env, scanTimeoutMs);
    results.push(
      analyse({
        repo,
        outputDir: runDir,
        scanDurationMs: scanRes.durationMs,
        status: scanRes.status,
        failureReason: scanRes.reason,
      }),
    );
    process.stdout.write(
      `[oss-corpus] ${repo.name}: ${scanRes.status.toUpperCase()} in ${(scanRes.durationMs / 1000).toFixed(0)}s\n`,
    );
  }

  while (idx < queue.length || inflight.length > 0) {
    while (inflight.length < parallel && idx < queue.length) {
      const repo = queue[idx++];
      const p = runOne(repo).catch((e) => {
        process.stderr.write(`[oss-corpus] ${repo.name}: harness error: ${e?.message}\n`);
        results.push(
          analyse({
            repo,
            outputDir: path.join(outputRoot, 'runs', repo.name),
            scanDurationMs: 0,
            status: 'scan_failed',
            failureReason: `harness error: ${e?.message}`,
          }),
        );
      });
      inflight.push(p);
      p.finally(() => {
        const i = inflight.indexOf(p);
        if (i >= 0) inflight.splice(i, 1);
      });
    }
    if (inflight.length > 0) await Promise.race(inflight);
  }

  // Preserve corpus order in the report.
  results.sort((a, b) => {
    const ai = corpus.repos.findIndex((r) => r.name === a.name);
    const bi = corpus.repos.findIndex((r) => r.name === b.name);
    return ai - bi;
  });

  const agg = aggregate(results);
  const reportJson = {
    generated_at: new Date().toISOString(),
    corpus_file: path.relative(path.resolve(__dirname, '..'), corpusPath),
    host: { platform: process.platform, node: process.version, cpus: os.cpus().length },
    aggregate: agg,
    results,
  };
  fs.writeFileSync(path.join(outputRoot, 'report.json'), JSON.stringify(reportJson, null, 2));
  fs.writeFileSync(path.join(outputRoot, 'report.md'), renderMarkdown(results, agg));

  process.stdout.write(
    `\n[oss-corpus] done — ${agg.scanned}/${agg.total_repos} scanned, recall ${agg.avg_recall_pct}%, ` +
      `cost $${agg.total_ai_cost_usd.toFixed(4)}, ${(agg.total_duration_ms / 60_000).toFixed(1)} min wall\n` +
      `report: ${path.join(outputRoot, 'report.md')}\n`,
  );
}

main().catch((e) => {
  process.stderr.write(`[oss-corpus] fatal: ${e?.stack ?? e}\n`);
  process.exit(2);
});
