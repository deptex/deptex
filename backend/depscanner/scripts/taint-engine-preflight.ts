/**
 * Pre-merge preflight orchestrator for the cross-file taint engine.
 *
 * Runs every test surface that gates merge confidence in one go and emits a
 * single PASS / FAIL summary with per-stage timing. Intended as the
 * "should I merge this?" green-light check — every assertion across the
 * engine's regression matrix has to pass before the branch is mergeable.
 *
 * Stages (in order, bail-out on first failure):
 *   1. invariants          — language-agnostic core invariants (53+)
 *   2. failure-modes       — empty/recursion/4-hop/8-hop/malformed-yaml
 *   3. callgraph           — TS callgraph construction
 *   4. propagator          — JS worklist propagation
 *   5. python              — Python substrate
 *   6. java                — Java substrate
 *   7. go                  — Go substrate
 *   8. ruby                — Ruby substrate
 *   9. php                 — PHP substrate
 *  10. rust                — Rust substrate
 *  11. csharp              — C# substrate
 *  12. validate            — all framework specs against fixture matrix
 *  13. sanitizer-audit     — every -safe fixture exercises its sanitizer
 *  14. cve-targeted        — Phase 6.5 cross-file CVE-tagged fixture suite
 *  15. recall              — global recall % across all -vulns/ fixture pairs
 *
 * Run: npm run test:taint-engine-all
 *
 * Exit 0 = mergeable, 1 = at least one stage failed.
 */

import { spawnSync } from 'child_process';
import * as path from 'path';

interface Stage {
  name: string;
  cmd: string;
  args: string[];
}

const STAGES: Stage[] = [
  { name: 'invariants',       cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-invariants'] },
  { name: 'failure-modes',    cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-failure-modes'] },
  { name: 'callgraph',        cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-callgraph'] },
  { name: 'propagator',       cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-propagator'] },
  { name: 'python',           cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-python'] },
  { name: 'java',             cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-java'] },
  { name: 'go',               cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-go'] },
  { name: 'ruby',             cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-ruby'] },
  { name: 'php',              cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-php'] },
  { name: 'rust',             cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-rust'] },
  { name: 'csharp',           cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-csharp'] },
  { name: 'validate',         cmd: 'npm', args: ['run', '--silent', 'taint-engine:validate', '--', 'all'] },
  { name: 'sanitizer-audit',  cmd: 'npm', args: ['run', '--silent', 'taint-engine:sanitizer-audit'] },
  { name: 'cve-targeted',     cmd: 'npm', args: ['run', '--silent', 'test:taint-engine-cve-targeted-fixtures'] },
  { name: 'recall',           cmd: 'npm', args: ['run', '--silent', 'taint-engine:recall'] },
];

interface StageResult {
  stage: string;
  pass: boolean;
  durationMs: number;
  lastLine: string;
}

function runStage(stage: Stage, cwd: string): StageResult {
  const start = Date.now();
  const r = spawnSync(stage.cmd, stage.args, {
    cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: true,
    encoding: 'utf8',
  });
  const durationMs = Date.now() - start;
  const stdout = r.stdout ?? '';
  const stderr = r.stderr ?? '';
  const lines = (stdout + stderr).split('\n').map((s) => s.trim()).filter(Boolean);
  const lastLine = lines[lines.length - 1] ?? '(no output)';
  return { stage: stage.name, pass: r.status === 0, durationMs, lastLine };
}

function fmtMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

async function main(): Promise<void> {
  const cwd = path.resolve(__dirname, '..');
  process.stdout.write('=== taint-engine pre-merge preflight ===\n');
  const results: StageResult[] = [];
  for (const stage of STAGES) {
    process.stdout.write(`\n[${stage.name}] ...`);
    const result = runStage(stage, cwd);
    results.push(result);
    process.stdout.write(
      `\r[${result.pass ? 'PASS' : 'FAIL'}] ${stage.name.padEnd(20)} ${fmtMs(result.durationMs).padStart(8)}  ${result.lastLine.slice(0, 80)}\n`,
    );
    if (!result.pass) {
      process.stdout.write('\nfirst failure — bailing out.\n');
      break;
    }
  }

  const passed = results.filter((r) => r.pass).length;
  const totalMs = results.reduce((sum, r) => sum + r.durationMs, 0);

  process.stdout.write(`\n=== summary ===\n`);
  process.stdout.write(`stages: ${passed}/${STAGES.length} passed (${fmtMs(totalMs)} total)\n`);
  if (passed < STAGES.length) {
    const failed = results.find((r) => !r.pass);
    process.stdout.write(`failed stage: ${failed?.stage}\n`);
    process.exit(1);
  } else {
    process.stdout.write('engine is mergeable.\n');
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('preflight crashed:', err instanceof Error ? err.stack ?? err.message : err);
  process.exit(2);
});
