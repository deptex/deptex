/**
 * runNucleiWithControlPlane exit-outcome mapping tests.
 *
 * Proves the wrapper translates the Nuclei process outcome into the right
 * DastPipelineAbortError vocabulary:
 *   1. exit 0            → success, findings returned, no throw.
 *   2. exit non-zero     → engine_crash.
 *   3. null exit code    → engine_crash (signal kill that was NOT our abort()).
 *                          This is the regression the critical review caught:
 *                          a signal-killed run must NOT ship as a clean scan.
 *   4. cancellation      → DastPipelineAbortError('unknown').
 *   5. scan timeout      → DastPipelineAbortError('timeout').
 *
 * Run: npx tsx test/dast-nuclei-exit-mapping.test.ts
 */

import { EventEmitter } from 'events';
import { runNucleiWithControlPlane, DastPipelineAbortError } from '../src/dast/pipeline';

let failures = 0;
let passed = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passed++;
  }
}

const TOMCAT_RESULT = JSON.stringify({
  'template-id': 'CVE-2017-12615',
  info: { name: 'Apache Tomcat RCE', severity: 'critical' },
  type: 'http',
  'matched-at': 'https://app.example.com/evil.jsp',
});

/**
 * Fake `spawn`: emits the given stdout then `close` with (code, signal) after
 * `closeAfterMs`. The control-plane group-kill targets the OS process group,
 * never this fake child, so for the abort/timeout cases the spontaneous close
 * is what resolves the run — `aborted`/`abortReason` are already latched by
 * the time it fires.
 */
function makeFakeSpawn(opts: {
  stdout?: string;
  code: number | null;
  signal?: string | null;
  closeAfterMs?: number;
}): any {
  return () => {
    const child: any = new EventEmitter();
    child.pid = 4242;
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => true;
    setTimeout(() => {
      if (opts.stdout) child.stdout.emit('data', Buffer.from(opts.stdout, 'utf-8'));
      child.emit('close', opts.code, opts.signal ?? null);
    }, opts.closeAfterMs ?? 5);
    return child;
  };
}

const quietControl = {
  onHeartbeat: async () => undefined,
  isCancelled: async () => false,
  pollIntervalMs: 100_000, // never fires within these tests
};

/** Run `fn`, return the thrown error (or null). */
async function caught(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e;
  }
}

async function main(): Promise<void> {
  const t0 = Date.now();
  console.log('runNucleiWithControlPlane exit-mapping tests\n');

  console.log('[1] exit 0 → success, findings returned');
  {
    const out = await runNucleiWithControlPlane(
      { targetUrl: 'https://app.example.com/', scanTimeoutMinutes: 5,
        spawnImpl: makeFakeSpawn({ stdout: `${TOMCAT_RESULT}\n`, code: 0 }) },
      quietControl,
    );
    assert(out.findings.length === 1, `[1] one finding parsed (got ${out.findings.length})`);
    assert(typeof out.durationMs === 'number', `[1] durationMs returned`);
  }

  console.log('\n[2] exit 2 → engine_crash');
  {
    const err = await caught(() =>
      runNucleiWithControlPlane(
        { targetUrl: 'https://app.example.com/', scanTimeoutMinutes: 5,
          spawnImpl: makeFakeSpawn({ code: 2 }) },
        quietControl,
      ),
    );
    assert(err instanceof DastPipelineAbortError, `[2] throws DastPipelineAbortError`);
    assert(
      err instanceof DastPipelineAbortError && err.errorCategory === 'engine_crash',
      `[2] errorCategory = engine_crash (got ${(err as DastPipelineAbortError)?.errorCategory})`,
    );
    assert(
      err instanceof DastPipelineAbortError && err.errorPayload?.exit_code === 2,
      `[2] errorPayload carries exit_code 2`,
    );
  }

  console.log('\n[3] null exit code (signal kill, not aborted) → engine_crash');
  {
    const err = await caught(() =>
      runNucleiWithControlPlane(
        { targetUrl: 'https://app.example.com/', scanTimeoutMinutes: 5,
          spawnImpl: makeFakeSpawn({ code: null, signal: 'SIGKILL' }) },
        quietControl,
      ),
    );
    assert(
      err instanceof DastPipelineAbortError && err.errorCategory === 'engine_crash',
      `[3] null exit → engine_crash, NOT a silent 0-findings success ` +
        `(got ${(err as DastPipelineAbortError)?.errorCategory ?? 'no throw'})`,
    );
    assert(
      err instanceof Error && /signal/i.test(err.message),
      `[3] message names the signal kill (got ${(err as Error)?.message})`,
    );
  }

  console.log('\n[4] cancellation → DastPipelineAbortError(unknown)');
  {
    const err = await caught(() =>
      runNucleiWithControlPlane(
        { targetUrl: 'https://app.example.com/', scanTimeoutMinutes: 5,
          spawnImpl: makeFakeSpawn({ code: null, signal: 'SIGTERM', closeAfterMs: 60 }) },
        { onHeartbeat: async () => undefined, isCancelled: async () => true, pollIntervalMs: 5 },
      ),
    );
    assert(
      err instanceof DastPipelineAbortError && err.errorCategory === 'unknown',
      `[4] cancellation → errorCategory unknown (got ${(err as DastPipelineAbortError)?.errorCategory})`,
    );
  }

  console.log('\n[5] scan timeout → DastPipelineAbortError(timeout)');
  {
    const err = await caught(() =>
      runNucleiWithControlPlane(
        // 0.001 min ≈ 60ms control-plane timeout; the fake closes after that.
        { targetUrl: 'https://app.example.com/', scanTimeoutMinutes: 0.001,
          spawnImpl: makeFakeSpawn({ code: null, signal: 'SIGKILL', closeAfterMs: 160 }) },
        quietControl,
      ),
    );
    assert(
      err instanceof DastPipelineAbortError && err.errorCategory === 'timeout',
      `[5] timeout → errorCategory timeout (got ${(err as DastPipelineAbortError)?.errorCategory})`,
    );
  }

  console.log(
    `\nrunNucleiWithControlPlane exit-mapping tests ${failures === 0 ? 'PASSED' : 'FAILED'} in ` +
      `${Date.now() - t0}ms (${passed} passed, ${failures} failure${failures === 1 ? '' : 's'})`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
