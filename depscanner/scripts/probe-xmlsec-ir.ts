/**
 * Diagnostic probe: render the xmlsec CVE-2023-44483 AI fixture and dump
 * the lowered IR step list for the signDocument method. Used during the
 * 2026-05-12 maven recall hardening to figure out why a *.sign(*) sink
 * was not firing on a `signature.sign(keyData.getBytes())` shape.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadSpec } from '../src/taint-engine/spec-loader';
import { propagateJava } from '../src/taint-engine/java/propagate';
import { buildJavaCallgraphContext } from '../src/taint-engine/java/callgraph';
import { lowerJavaMethod } from '../src/taint-engine/java/ir';
import type { FrameworkSpec } from '../src/taint-engine';

async function main(): Promise<void> {
  const reportPath = path.resolve(__dirname, '..', 'bench-iterate/v_base/2026-05-12T17-41-24/report.json');
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8')) as { perCve: Array<{ cveId: string; vulnerableFixture?: string }> };
  const cve = report.perCve.find((c) => c.cveId === 'CVE-2023-44483');
  if (!cve?.vulnerableFixture) throw new Error('fixture missing');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'xmlsec-ir-'));
  const srcDir = path.join(tmpRoot, 'src', 'main', 'java', 'com', 'example');
  fs.mkdirSync(srcDir, { recursive: true });
  fs.writeFileSync(path.join(tmpRoot, 'pom.xml'), '<project/>');
  let body = cve.vulnerableFixture;
  if (!/^\s*package\s+/.test(body)) body = `package com.example;\n\n${body}`;
  fs.writeFileSync(path.join(srcDir, 'Probe.java'), body, 'utf8');

  const modelDir = path.resolve(__dirname, '..', 'src/taint-engine/framework-models');
  const specs: FrameworkSpec[] = fs
    .readdirSync(modelDir)
    .filter((n) => n.endsWith('.yaml') || n.endsWith('.yml'))
    .map((n) => loadSpec(path.join(modelDir, n)));

  const ctx = await buildJavaCallgraphContext(tmpRoot);
  console.log('Java callgraph nodes:');
  for (const node of ctx.callgraph.nodes) {
    console.log(`  ${node.id}  (${node.classFqn ?? '?'} :: ${node.name})  ${node.filePath}:${node.startLine}`);
  }

  for (const node of ctx.callgraph.nodes) {
    const entry = ctx.methodById.get(node.id);
    if (!entry) continue;
    const fileIndex = ctx.files.find((f) => f.relativePath === node.filePath);
    if (!fileIndex) continue;
    console.log(`\nIR for ${node.name}:`);
    const lowered = lowerJavaMethod(entry.node, { ctx, fileIndex, entry });
    for (const step of lowered.steps) {
      const fragments: string[] = [step.kind];
      if (step.kind === 'call') {
        fragments.push(`callee=${step.callee.calleeText}`);
        fragments.push(`target=${step.target ?? '-'}`);
        fragments.push(`args=[${step.args.map((a) => a ?? '-').join(', ')}]`);
        fragments.push(`argTexts=[${step.argTexts.join(' || ')}]`);
        fragments.push(`kind=${step.callee.kind}`);
      } else if (step.kind === 'param') {
        fragments.push(`name=${step.name} idx=${step.index}`);
      } else if (step.kind === 'assign') {
        fragments.push(`target=${step.target ?? '-'} from=${step.from ?? '-'}`);
      } else if (step.kind === 'return') {
        fragments.push(`from=${step.from ?? '-'}`);
      }
      console.log('  ' + fragments.join(' | '));
    }
  }

  const r = await propagateJava({ rootDir: tmpRoot, specs });
  console.log('\nflows:', r.flows.length, 'sinks:', r.stats.sinksHit, 'sources:', r.stats.sourcesFound);
  for (const f of r.flows) console.log('  flow', f.vuln_class, f.sink_pattern);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
