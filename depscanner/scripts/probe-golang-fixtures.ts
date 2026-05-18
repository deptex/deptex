/**
 * One-shot probe: render each golang CVE fixture from the bench report to a temp
 * dir and run propagateGo() with bundled Go specs (gin+echo+go-stdlib). Prints,
 * per CVE, whether any source / sink / flow was emitted.
 *
 * Usage: npx tsx scripts/probe-golang-fixtures.ts [path/to/report.json]
 *
 * Default report path: bench-iterate/v_base/2026-05-12T14-23-03/report.json
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadSpec } from '../src/taint-engine/spec-loader';
import { propagateGo } from '../src/taint-engine/go/propagate';
import type { FrameworkSpec } from '../src/taint-engine';

interface PerCveEntry {
  cveId: string;
  packagePurl?: string;
  status?: string;
  vulnerableFixture?: string;
  safeFixture?: string;
}

async function main(): Promise<void> {
  const reportPath = process.argv[2] ?? path.resolve(__dirname, '..', 'bench-iterate/v_base/2026-05-12T14-23-03/report.json');
  if (!fs.existsSync(reportPath)) {
    process.stderr.write(`report not found: ${reportPath}\n`);
    process.exit(1);
  }
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8')) as { perCve: PerCveEntry[] };
  const golang = (report.perCve ?? []).filter((c) => (c.packagePurl ?? '').startsWith('pkg:golang/'));

  const modelDir = path.resolve(__dirname, '..', 'src/taint-engine/framework-models');
  const yamlPaths = ['gin.yaml', 'echo.yaml', 'go-stdlib.yaml']
    .map((n) => path.join(modelDir, n));

  // Optionally include extra specs (e.g. go-jose.yaml) via env var.
  const extra = (process.env.EXTRA_SPECS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const e of extra) yamlPaths.push(path.resolve(e));

  const specs: FrameworkSpec[] = yamlPaths.map((p) => loadSpec(p));
  process.stderr.write(`Loaded specs: ${specs.map((s) => s.framework).join(', ')}\n`);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'go-probe-'));
  process.stderr.write(`tmp root: ${tmpRoot}\n`);

  const results: Array<{
    cve: string;
    purl: string;
    status: string;
    parseable: boolean;
    fileCount: number;
    functionCount: number;
    sourcesFound: number;
    sinksHit: number;
    flowsEmitted: number;
    flows: Array<{ vc: string; pattern: string; len: number }>;
  }> = [];

  for (const c of golang) {
    if (!c.vulnerableFixture) {
      results.push({
        cve: c.cveId,
        purl: c.packagePurl ?? '',
        status: c.status ?? '',
        parseable: false,
        fileCount: 0,
        functionCount: 0,
        sourcesFound: 0,
        sinksHit: 0,
        flowsEmitted: 0,
        flows: [],
      });
      continue;
    }
    const dir = path.join(tmpRoot, c.cveId);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'go.mod'),
      `module example.com/${c.cveId.toLowerCase()}\n\ngo 1.21\n`,
      'utf8',
    );
    fs.writeFileSync(path.join(dir, 'main.go'), c.vulnerableFixture, 'utf8');

    try {
      const r = await propagateGo({ rootDir: dir, specs, onWarn: () => undefined });
      results.push({
        cve: c.cveId,
        purl: c.packagePurl ?? '',
        status: c.status ?? '',
        parseable: true,
        fileCount: r.callgraph.fileCount,
        functionCount: r.callgraph.nodes.length,
        sourcesFound: r.stats.sourcesFound,
        sinksHit: r.stats.sinksHit,
        flowsEmitted: r.flows.length,
        flows: r.flows.map((f) => ({ vc: f.vuln_class, pattern: f.sink_pattern, len: f.flow_length })),
      });
    } catch (e) {
      results.push({
        cve: c.cveId,
        purl: c.packagePurl ?? '',
        status: c.status ?? '',
        parseable: false,
        fileCount: 0,
        functionCount: 0,
        sourcesFound: 0,
        sinksHit: 0,
        flowsEmitted: 0,
        flows: [{ vc: 'error', pattern: (e as Error).message, len: 0 }],
      });
    }
  }

  process.stdout.write(JSON.stringify(results, null, 2) + '\n');
}

main().catch((err) => {
  process.stderr.write(`probe failed: ${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
