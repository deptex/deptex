/**
 * Cross-run reachability DIFF TRIPWIRE — the automated guard against silence
 * false-negatives introduced by an engine change (stress-plan C5 / max-plan
 * Arc 0a). Compares two corpus scans (per-repo oss-corpus run dirs) finding-by-
 * finding and classifies every reachability transition:
 *
 *   ALARM   VISIBLE → SILENCED   (function/data_flow/confirmed → module/unreachable)
 *           — a previously-shown finding is now hidden. The worst error class.
 *           Any unexplained occurrence blocks the image. Exit code 1.
 *   REVIEW  module → unreachable — product-invisible (both silenced) but a
 *           confidence claim strengthened; list for adjudication (expected when
 *           a new demotion gate ships, wrong when a gatherer mis-parses).
 *   INFO    SILENCED → VISIBLE / unreachable → module — surfacing; expected
 *           when a promotion ships.
 *   VDB     only-in-old / only-in-new — dep-scan vulnerability-DB volatility
 *           (counts only; not an engine property).
 *
 * Usage:
 *   npx tsx scripts/corpus-diff.ts --old=<runsParent|dir1,dir2,...> --new=<runsParent|dir1,...>
 *
 * Each side accepts either a PARENT dir containing per-repo run dirs (each with
 * vulns.json) or a comma-separated list of run dirs. Repos are matched by dir
 * basename; a repo present on only one side is skipped with a warning.
 * Findings are keyed `dep-name@osv_id` (joined via deps.json — PDV UUIDs are
 * run-specific and useless across runs).
 *
 * Run this on EVERY image bump: old = last-good image's corpus runs, new = the
 * candidate's. Zero unexplained ALARMs is a merge/deploy precondition.
 */

import * as fs from 'fs';
import * as path from 'path';

function flag(name: string): string | undefined {
  const pref = `--${name}=`;
  const a = process.argv.find((x) => x.startsWith(pref));
  return a ? a.slice(pref.length) : undefined;
}

const TIER: Record<string, number> = {
  unreachable: 0,
  module: 1,
  function: 2,
  data_flow: 3,
  confirmed: 4,
};
const visible = (level: string): boolean => (TIER[level] ?? 1) >= 2;

function readJson(p: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function asArray(v: unknown): any[] {
  if (!v) return [];
  if (Array.isArray(v)) return v;
  const o = v as any;
  return o.vulnerabilities ?? o.vulns ?? o.dependencies ?? o.deps ?? [];
}

/** Resolve a side arg into repo-name → run-dir. */
function resolveRunDirs(arg: string): Map<string, string> {
  const out = new Map<string, string>();
  const entries = arg.includes(',')
    ? arg.split(',').map((s) => s.trim()).filter(Boolean)
    : [arg.trim()];
  for (const e of entries) {
    if (!fs.existsSync(e)) continue;
    if (fs.existsSync(path.join(e, 'vulns.json'))) {
      out.set(path.basename(e.replace(/[\\/]+$/, '')), e);
      continue;
    }
    // Parent dir: every subdir with a vulns.json is a repo run.
    for (const ent of fs.readdirSync(e, { withFileTypes: true })) {
      if (ent.isDirectory() && fs.existsSync(path.join(e, ent.name, 'vulns.json'))) {
        out.set(ent.name, path.join(e, ent.name));
      }
    }
  }
  return out;
}

interface Finding { level: string; summary: string }

/** Load a run dir into key(`dep@osv`) → finding, joining names via deps.json. */
function loadRun(dir: string): Map<string, Finding> {
  const nameById = new Map<string, string>();
  for (const d of asArray(readJson(path.join(dir, 'deps.json')))) {
    if (d.id && d.name) nameById.set(String(d.id), String(d.name).toLowerCase());
  }
  const out = new Map<string, Finding>();
  for (const v of asArray(readJson(path.join(dir, 'vulns.json')))) {
    const dep = nameById.get(String(v.project_dependency_id)) ?? String(v.project_dependency_id);
    const key = `${dep}@${String(v.osv_id).toUpperCase()}`;
    const level = String(v.reachability_level ?? 'module');
    // Keep the WORST (most visible) verdict for duplicate keys — conservative
    // for the ALARM direction (a dup that stays visible must not mask one that
    // got silenced... and vice-versa keeping max-visibility on both sides makes
    // the comparison symmetric).
    const prev = out.get(key);
    if (!prev || (TIER[level] ?? 1) > (TIER[prev.level] ?? 1)) {
      out.set(key, { level, summary: String(v.summary ?? '').slice(0, 90) });
    }
  }
  return out;
}

function main(): void {
  const oldArg = flag('old');
  const newArg = flag('new');
  if (!oldArg || !newArg) {
    process.stderr.write('Usage: --old=<runsParent|dir1,dir2,...> --new=<runsParent|dir1,...>\n');
    process.exit(2);
  }
  const oldRuns = resolveRunDirs(oldArg);
  const newRuns = resolveRunDirs(newArg);

  let totalAlarms = 0;
  const repos = [...new Set([...oldRuns.keys(), ...newRuns.keys()])].sort();
  for (const repo of repos) {
    const od = oldRuns.get(repo);
    const nd = newRuns.get(repo);
    if (!od || !nd) {
      process.stdout.write(`\n== ${repo}: SKIPPED (present only in ${od ? 'old' : 'new'})\n`);
      continue;
    }
    const o = loadRun(od);
    const n = loadRun(nd);

    const alarms: string[] = [];
    const reviews: string[] = [];
    const promotions: string[] = [];
    let confidencePromotions = 0;
    let onlyOld = 0;
    let onlyNew = 0;

    for (const [key, ov] of o) {
      const nv = n.get(key);
      if (!nv) { onlyOld++; continue; }
      if (ov.level === nv.level) continue;
      const line = `${key}: ${ov.level} -> ${nv.level}  (${ov.summary})`;
      if (visible(ov.level) && !visible(nv.level)) alarms.push(line);
      else if (ov.level === 'module' && nv.level === 'unreachable') reviews.push(line);
      else if (!visible(ov.level) && visible(nv.level)) promotions.push(line);
      else if (ov.level === 'unreachable' && nv.level === 'module') confidencePromotions++;
      else if (visible(ov.level) && visible(nv.level)) promotions.push(line); // tier shift within visible
    }
    for (const key of n.keys()) if (!o.has(key)) onlyNew++;

    process.stdout.write(
      `\n== ${repo}: old=${o.size} new=${n.size} | ALARM=${alarms.length} review(module->unreachable)=${reviews.length} ` +
      `promoted=${promotions.length} unreachable->module=${confidencePromotions} vdb(only-old=${onlyOld}, only-new=${onlyNew})\n`,
    );
    for (const a of alarms) process.stdout.write(`  !! ALARM  ${a}\n`);
    for (const r of reviews) process.stdout.write(`   ~ review ${r}\n`);
    for (const p of promotions) process.stdout.write(`   + shown  ${p}\n`);
    totalAlarms += alarms.length;
  }

  process.stdout.write(
    `\n${totalAlarms === 0 ? 'TRIPWIRE CLEAN — no visible->silenced transitions.' : `TRIPWIRE FIRED — ${totalAlarms} visible->silenced transition(s). Adjudicate every one before shipping this image.`}\n`,
  );
  process.exit(totalAlarms === 0 ? 0 : 1);
}

main();
