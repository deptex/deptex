/**
 * Assemble a reachability-corpus `report.json` from a set of ALREADY-SCANNED
 * per-repo run dirs, so `reachability-corpus.ts --report=<file>` can score a
 * corpus stitched together across multiple scan sessions WITHOUT re-cloning.
 *
 * Why: the full-corpus batch (`oss-corpus.ts` over all repos) is fragile on a
 * resource-constrained host — a `git init exited 3221225794` clone-exhaustion
 * partway through fails the whole run, and long single scans get killed. But
 * individual per-repo scans succeed. This tool lets you score whatever repos
 * DID scan (from any oss-corpus output dirs) as one corpus, then feed the result
 * to the real gate/silence scorer — sidestepping the flaky multi-clone.
 *
 * Each run dir is an oss-corpus per-repo output dir (contains vulns.json). The
 * repo NAME is the dir basename, matched against reachability-corpus.yaml for
 * `ecosystem` + `ground_truth_cves` (so labelled gates/precision still work for
 * repos that carry ground truth; unlabelled repos contribute only to the
 * all-findings noise-reduction number).
 *
 * Usage:
 *   npx tsx scripts/build-report-from-runs.ts --runs=<dir1,dir2,...> --out=<report.json>
 *   npx tsx scripts/reachability-corpus.ts --report=<report.json>
 *
 * The emitted report is byte-compatible with the CorpusReport shape the scorer
 * reads (name / ecosystem / status / by_reachability / ground_truth_matched).
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

function flag(name: string): string | undefined {
  const pref = `--${name}=`;
  const a = process.argv.find((x) => x.startsWith(pref));
  return a ? a.slice(pref.length) : undefined;
}

interface GroundTruthCve {
  id: string;
  expected_reachability: string;
}
interface CorpusRepo {
  name: string;
  ecosystem: string;
  ground_truth_cves?: GroundTruthCve[];
}

function readJson(p: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function vulnsOf(dir: string): any[] {
  const v = readJson(path.join(dir, 'vulns.json')) as any;
  if (!v) return [];
  return Array.isArray(v) ? v : v.vulnerabilities ?? v.vulns ?? [];
}

function main(): void {
  const runsArg = flag('runs');
  const outArg = flag('out');
  if (!runsArg || !outArg) {
    process.stderr.write('Usage: --runs=<dir1,dir2,...> --out=<report.json>\n');
    process.exit(2);
  }
  const runDirs = runsArg.split(',').map((s) => s.trim()).filter(Boolean);

  const corpusPath = path.resolve(__dirname, 'reachability-corpus.yaml');
  const corpus = yaml.load(fs.readFileSync(corpusPath, 'utf8')) as { repos: CorpusRepo[] };
  const byName = new Map<string, CorpusRepo>();
  for (const r of corpus.repos) byName.set(r.name, r);

  const results: any[] = [];
  for (const dir of runDirs) {
    const name = path.basename(dir.replace(/[\\/]+$/, ''));
    const repo = byName.get(name);
    if (!repo) {
      process.stderr.write(`WARN: '${name}' not found in reachability-corpus.yaml — skipping\n`);
      continue;
    }
    if (!fs.existsSync(path.join(dir, 'vulns.json'))) {
      process.stderr.write(`WARN: '${name}' has no vulns.json at ${dir} — skipping (clone/scan failed?)\n`);
      continue;
    }
    const vulns = vulnsOf(dir);
    // Dedupe by PDV id (mirrors the scorer's unique-finding basis).
    const seen = new Set<string>();
    const uniq: any[] = [];
    for (const x of vulns) {
      const k = String(x.id ?? `${x.osv_id}|${x.project_dependency_id}`);
      if (seen.has(k)) continue;
      seen.add(k);
      uniq.push(x);
    }
    const by_reachability: Record<string, number> = {};
    for (const x of uniq) {
      const l = String(x.reachability_level ?? 'unknown');
      by_reachability[l] = (by_reachability[l] ?? 0) + 1;
    }
    // Observed CVE index (osv_id + CVE aliases) → verdict, for ground-truth matching.
    const observed = new Map<string, any>();
    for (const x of uniq) {
      const ids = [x.osv_id, ...(Array.isArray(x.aliases) ? x.aliases : [])].filter(Boolean);
      for (const id of ids) {
        if (/^CVE-\d{4}-\d+$/i.test(String(id))) observed.set(String(id).toUpperCase(), x);
      }
    }
    const gt = Array.isArray(repo.ground_truth_cves) ? repo.ground_truth_cves : [];
    const ground_truth_matched = gt.map((g) => {
      const v = observed.get(String(g.id).toUpperCase());
      return {
        cve: g.id,
        observed: !!v,
        observed_reachability: v ? (v.reachability_level ?? null) : null,
        expected_reachability: g.expected_reachability,
      };
    });
    results.push({ name, ecosystem: repo.ecosystem, status: 'ok', by_reachability, ground_truth_matched });
  }

  const report = { generated_at: 'assembled-from-runs', assembled: true, results };
  fs.writeFileSync(path.resolve(outArg), JSON.stringify(report, null, 2));
  process.stdout.write(
    `wrote ${results.length} repos to ${outArg}: ${results.map((r) => r.name).join(', ')}\n`,
  );
}

main();
