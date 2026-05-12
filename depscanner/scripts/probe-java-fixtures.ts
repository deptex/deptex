/**
 * One-shot probe: render each maven CVE fixture from a bench-iterate report to
 * a temp dir, run propagateJava() with bundled java specs, and print per CVE
 * the source/sink/flow counts plus any flows emitted.
 *
 * Usage: npx tsx scripts/probe-java-fixtures.ts [path/to/report.json]
 *
 * Default: bench-iterate/v_base/2026-05-12T17-41-24/report.json
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadSpec } from '../src/taint-engine/spec-loader';
import { propagateJava } from '../src/taint-engine/java/propagate';
import type { FrameworkSpec } from '../src/taint-engine';

interface PerCveEntry {
  cveId: string;
  packagePurl?: string;
  status?: string;
  vulnerableFixture?: string;
  safeFixture?: string;
}

function pickJavaSpecs(modelDir: string): string[] {
  // All YAML files whose `language: java` line is present. Cheap text check
  // avoids loading + filtering — but loadAllSpecs() in the prod engine just
  // grabs every yaml in the dir, so for parity we do the same.
  return fs
    .readdirSync(modelDir)
    .filter((n) => n.endsWith('.yaml') || n.endsWith('.yml'))
    .map((n) => path.join(modelDir, n));
}

async function main(): Promise<void> {
  const reportPath =
    process.argv[2] ?? path.resolve(__dirname, '..', 'bench-iterate/v_base/2026-05-12T17-41-24/report.json');
  if (!fs.existsSync(reportPath)) {
    process.stderr.write(`report not found: ${reportPath}\n`);
    process.exit(1);
  }
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8')) as { perCve: PerCveEntry[] };
  const maven = (report.perCve ?? []).filter((c) => (c.packagePurl ?? '').startsWith('pkg:maven/'));

  const modelDir = path.resolve(__dirname, '..', 'src/taint-engine/framework-models');
  const allYamlPaths = pickJavaSpecs(modelDir);
  const specs: FrameworkSpec[] = allYamlPaths.map((p) => loadSpec(p));
  const javaSpecs = specs.filter((s) => s.language === 'java');
  process.stderr.write(
    `Loaded ${specs.length} specs total; java-tagged: ${javaSpecs.map((s) => s.framework).join(', ')}\n`,
  );

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'java-probe-'));
  process.stderr.write(`tmp root: ${tmpRoot}\n`);

  const onlyCve = process.env.ONLY_CVE;
  const targets = onlyCve ? maven.filter((c) => c.cveId === onlyCve) : maven;

  const rows: Array<{
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
    warnings: string[];
    error?: string;
  }> = [];

  for (const c of targets) {
    if (!c.vulnerableFixture) {
      rows.push({
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
        warnings: ['no vulnerableFixture in report'],
      });
      continue;
    }
    // Layout like real maven repo: src/main/java/com/example/Probe.java
    const dir = path.join(tmpRoot, c.cveId);
    const srcDir = path.join(dir, 'src', 'main', 'java', 'com', 'example');
    fs.mkdirSync(srcDir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'pom.xml'),
      `<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>${c.cveId.toLowerCase()}</artifactId><version>0</version></project>\n`,
      'utf8',
    );
    // Inject `package com.example;` if the AI fixture didn't write one (most
    // don't). Production engine doesn't require a package decl, but it keeps
    // the file layout consistent.
    let body = c.vulnerableFixture;
    if (!/^\s*package\s+/.test(body)) {
      body = `package com.example;\n\n${body}`;
    }
    fs.writeFileSync(path.join(srcDir, 'Probe.java'), body, 'utf8');

    const warnings: string[] = [];
    try {
      const r = await propagateJava({
        rootDir: dir,
        specs,
        onWarn: (m) => warnings.push(m),
      });
      rows.push({
        cve: c.cveId,
        purl: c.packagePurl ?? '',
        status: c.status ?? '',
        parseable: true,
        fileCount: r.callgraph.fileCount,
        functionCount: r.callgraph.nodes.length,
        sourcesFound: r.stats.sourcesFound,
        sinksHit: r.stats.sinksHit,
        flowsEmitted: r.flows.length,
        flows: r.flows.map((f) => ({
          vc: f.vuln_class,
          pattern: f.sink_pattern,
          len: f.flow_length,
        })),
        warnings,
      });
    } catch (err) {
      rows.push({
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
        warnings,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
  const flipped = rows.filter((r) => r.flowsEmitted > 0).length;
  process.stderr.write(`\nFlows emitted: ${flipped}/${rows.length}\n`);
}

main().catch((err) => {
  process.stderr.write(`probe failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
