/**
 * Benchmark report generator (JSON + HTML).
 *
 * Emits two artifacts side by side:
 *   - report.json  — machine-readable, consumed by the retirement-gates CLI
 *   - report.html  — single-file dashboard for human review
 *
 * The HTML is intentionally template-string-only (no React, no build step) so
 * the harness can be run from a vanilla Node install with no extra setup.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { BenchmarkCorpus } from './corpus';
import type { CorpusRecall, ProjectRecall } from './compare';

export interface BenchmarkReport {
  schemaVersion: 1;
  generatedAt: string;
  corpus: { name: string; projectCount: number; ecosystems: string[] };
  recall: {
    atom: { expected: number; matched: number; pct: number };
    taintEngine: { expected: number; matched: number; pct: number };
    deltaPp: number; // percentage-point delta (engine − atom)
  };
  perProject: Array<{
    id: string;
    ecosystem: string;
    expected: number;
    atomMatched: number;
    engineMatched: number;
    findings: Array<{
      cve: string;
      vulnClass: string | null;
      atom: 'hit' | 'miss';
      engine: 'hit' | 'miss';
    }>;
  }>;
  newDetections: Array<{ projectId: string; cve: string; vulnClass: string | null }>;
  regressions: Array<{ projectId: string; cve: string; vulnClass: string | null }>;
  /** Per-project run timings — useful for catching engine perf regressions. */
  timings?: Array<{
    projectId: string;
    atomMs: number | null;
    engineMs: number | null;
    engineFlowsEmitted: number;
    atomFlowsEmitted: number;
  }>;
}

export interface BuildReportInput {
  corpus: BenchmarkCorpus;
  recall: CorpusRecall;
  timings?: BenchmarkReport['timings'];
}

export function buildReport(input: BuildReportInput): BenchmarkReport {
  const { corpus, recall, timings } = input;
  const ecosystems = corpus.ecosystems ?? unique(corpus.projects.map((p) => p.ecosystem));
  const atomPct = pct(recall.atom.matched, recall.atom.expected);
  const enginePct = pct(recall.taintEngine.matched, recall.taintEngine.expected);

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    corpus: { name: corpus.name, projectCount: corpus.projects.length, ecosystems },
    recall: {
      atom: { ...recall.atom, pct: Number(atomPct.toFixed(2)) },
      taintEngine: { ...recall.taintEngine, pct: Number(enginePct.toFixed(2)) },
      deltaPp: Number((enginePct - atomPct).toFixed(2)),
    },
    perProject: corpus.projects.map((project, i) => {
      const atomP = recall.atom.perProject[i];
      const engineP = recall.taintEngine.perProject[i];
      return {
        id: project.id,
        ecosystem: project.ecosystem,
        expected: atomP.expected,
        atomMatched: atomP.matched,
        engineMatched: engineP.matched,
        findings: project.expectedFindings.map((f, idx) => ({
          cve: f.cve,
          vulnClass: f.vulnClass ?? null,
          atom: atomP.findings[idx].matched ? 'hit' : 'miss',
          engine: engineP.findings[idx].matched ? 'hit' : 'miss',
        })),
      };
    }),
    newDetections: recall.newDetections.map((d) => ({
      projectId: d.project.id,
      cve: d.finding.cve,
      vulnClass: d.finding.vulnClass ?? null,
    })),
    regressions: recall.regressions.map((d) => ({
      projectId: d.project.id,
      cve: d.finding.cve,
      vulnClass: d.finding.vulnClass ?? null,
    })),
    timings,
  };
}

export function writeJsonReport(outDir: string, report: BenchmarkReport): string {
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, 'report.json');
  fs.writeFileSync(file, JSON.stringify(report, null, 2), 'utf8');
  return file;
}

export function writeHtmlReport(outDir: string, report: BenchmarkReport): string {
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, 'report.html');
  fs.writeFileSync(file, renderHtml(report), 'utf8');
  return file;
}

function pct(matched: number, expected: number): number {
  if (expected === 0) return 100;
  return (matched / expected) * 100;
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

// ---------------------------------------------------------------------------
// HTML rendering — single-file, no external dependencies
// ---------------------------------------------------------------------------

function renderHtml(report: BenchmarkReport): string {
  const totalRows = report.perProject.flatMap((p) =>
    p.findings.map((f) => ({ projectId: p.id, ecosystem: p.ecosystem, ...f })),
  );
  const deltaCls = report.recall.deltaPp >= 0 ? 'pos' : 'neg';
  const deltaSign = report.recall.deltaPp >= 0 ? '+' : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Taint Engine vs atom — ${escapeHtml(report.corpus.name)}</title>
<style>
  :root { color-scheme: light; }
  body { font: 14px/1.5 -apple-system, system-ui, sans-serif; margin: 0; padding: 24px; color: #111; background: #f7f7f8; }
  h1 { margin: 0 0 4px; }
  .meta { color: #666; margin-bottom: 24px; font-size: 13px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card { background: #fff; border: 1px solid #e3e3e8; border-radius: 8px; padding: 16px; }
  .card h2 { margin: 0 0 8px; font-size: 13px; text-transform: uppercase; color: #666; letter-spacing: 0.05em; }
  .num { font-size: 32px; font-weight: 600; }
  .sub { color: #777; font-size: 12px; margin-top: 4px; }
  .pos { color: #1f7a3a; }
  .neg { color: #b3261e; }
  .neutral { color: #555; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e3e3e8; border-radius: 8px; overflow: hidden; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #f0f0f3; font-size: 13px; }
  th { background: #fafafb; color: #444; font-weight: 600; }
  tr:last-child td { border-bottom: 0; }
  .hit { color: #1f7a3a; font-weight: 600; }
  .miss { color: #b3261e; font-weight: 600; }
  h3 { margin: 24px 0 8px; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #eef; color: #335; font-size: 11px; }
  .empty { color: #888; font-style: italic; }
</style>
</head>
<body>
<h1>Taint Engine vs atom</h1>
<div class="meta">
  Corpus: <strong>${escapeHtml(report.corpus.name)}</strong> · ${report.corpus.projectCount} projects ·
  ecosystems: ${report.corpus.ecosystems.map(escapeHtml).join(', ')} · generated ${escapeHtml(report.generatedAt)}
</div>

<div class="cards">
  <div class="card">
    <h2>atom recall</h2>
    <div class="num">${report.recall.atom.pct.toFixed(1)}%</div>
    <div class="sub">${report.recall.atom.matched} / ${report.recall.atom.expected} findings</div>
  </div>
  <div class="card">
    <h2>taint engine recall</h2>
    <div class="num">${report.recall.taintEngine.pct.toFixed(1)}%</div>
    <div class="sub">${report.recall.taintEngine.matched} / ${report.recall.taintEngine.expected} findings</div>
  </div>
  <div class="card">
    <h2>delta (engine − atom)</h2>
    <div class="num ${deltaCls}">${deltaSign}${report.recall.deltaPp.toFixed(1)}pp</div>
    <div class="sub">${report.newDetections.length} new · ${report.regressions.length} regressions</div>
  </div>
</div>

<h3>Per-finding results</h3>
<table>
  <thead><tr><th>Project</th><th>Ecosystem</th><th>CVE</th><th>Vuln class</th><th>atom</th><th>taint engine</th></tr></thead>
  <tbody>
  ${totalRows.length === 0
    ? '<tr><td colspan="6" class="empty">No findings in corpus</td></tr>'
    : totalRows
        .map(
          (row) => `<tr>
      <td>${escapeHtml(row.projectId)}</td>
      <td><span class="pill">${escapeHtml(row.ecosystem)}</span></td>
      <td>${escapeHtml(row.cve)}</td>
      <td>${escapeHtml(row.vulnClass ?? '—')}</td>
      <td class="${row.atom}">${row.atom}</td>
      <td class="${row.engine}">${row.engine}</td>
    </tr>`,
        )
        .join('')}
  </tbody>
</table>

${
  report.regressions.length > 0
    ? `<h3>Regressions <span class="pill neg" style="background:#fde7e9;color:#b3261e">${report.regressions.length}</span></h3>
<table>
  <thead><tr><th>Project</th><th>CVE</th><th>Vuln class</th></tr></thead>
  <tbody>
    ${report.regressions
      .map(
        (r) => `<tr><td>${escapeHtml(r.projectId)}</td><td>${escapeHtml(r.cve)}</td><td>${escapeHtml(r.vulnClass ?? '—')}</td></tr>`,
      )
      .join('')}
  </tbody>
</table>`
    : ''
}

${
  report.newDetections.length > 0
    ? `<h3>New detections <span class="pill pos" style="background:#e6f5ec;color:#1f7a3a">${report.newDetections.length}</span></h3>
<table>
  <thead><tr><th>Project</th><th>CVE</th><th>Vuln class</th></tr></thead>
  <tbody>
    ${report.newDetections
      .map(
        (r) => `<tr><td>${escapeHtml(r.projectId)}</td><td>${escapeHtml(r.cve)}</td><td>${escapeHtml(r.vulnClass ?? '—')}</td></tr>`,
      )
      .join('')}
  </tbody>
</table>`
    : ''
}
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
