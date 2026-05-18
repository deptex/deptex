// Phase 24a (v2.1a): control-plane unit tests.
//
// We exercise spawnExternal against a fake spawn impl that simulates a
// long-running child via EventEmitter + Readable streams. The real fork()
// path (detached:true + process.kill(-pid, ...)) is exercised by the
// real-Docker e2e in Task 10 — tests here verify the abort/auth-lost
// orchestration logic, not the OS-level group-kill semantics.

import { EventEmitter } from 'events';
import { Readable } from 'stream';
import {
  spawnExternal,
  createAuthLostWatcher,
  DEFAULT_AUTH_LOST_THRESHOLD,
  DEFAULT_AUTH_LOST_WINDOW_MS,
  SIGTERM_GRACE_MS,
} from '../dast/control-plane';

// ---------------------------------------------------------------------------
// Fake child_process.spawn — emits stdout/stderr deterministically and lets
// the test trigger 'close' / 'error' on demand.
// ---------------------------------------------------------------------------

interface FakeChild extends EventEmitter {
  pid?: number;
  stdout: Readable;
  stderr: Readable;
  killed: boolean;
  killCalls: Array<NodeJS.Signals | number | undefined>;
  kill: (signal?: NodeJS.Signals | number) => boolean;
  finishWith: (exitCode: number, signal?: NodeJS.Signals | null) => void;
  emitStderr: (s: string) => void;
}

function makeFakeChild(): FakeChild {
  const ee = new EventEmitter() as FakeChild;
  ee.pid = 99999;
  ee.killed = false;
  ee.killCalls = [];
  ee.stdout = new Readable({ read() {} });
  ee.stderr = new Readable({ read() {} });
  ee.kill = (signal) => {
    ee.killed = true;
    ee.killCalls.push(signal);
    return true;
  };
  ee.finishWith = (exitCode, signal = null) => {
    ee.emit('close', exitCode, signal);
  };
  ee.emitStderr = (s) => {
    ee.stderr.push(Buffer.from(s, 'utf-8'));
  };
  return ee;
}

function makeFakeSpawnImpl(child: FakeChild) {
  return ((_command: string, _args: readonly string[]) => child) as unknown as typeof import('child_process').spawn;
}

// Suppress process.kill side effects in the test runner. spawnExternal calls
// process.kill(-pid, signal) on Unix; we replace it with a spy.
const originalKill = process.kill;
afterEach(() => {
  process.kill = originalKill;
});

function mockProcessKill(): jest.Mock {
  const spy = jest.fn().mockReturnValue(true);
  // process.kill has a tighter signature than jest.Mock — cast through unknown.
  process.kill = spy as unknown as typeof process.kill;
  return spy;
}

// ---------------------------------------------------------------------------
// spawnExternal
// ---------------------------------------------------------------------------

describe('spawnExternal — clean exit', () => {
  it('resolves with exitCode 0 and aborted=false when child exits cleanly', async () => {
    mockProcessKill();
    const child = makeFakeChild();
    const handle = spawnExternal({
      command: '/bin/true',
      args: [],
      timeoutMs: 60_000,
      spawnImpl: makeFakeSpawnImpl(child),
    });

    setImmediate(() => {
      child.emitStderr('zap finished\n');
      child.finishWith(0);
    });

    const result = await handle.done;
    expect(result.exitCode).toBe(0);
    expect(result.aborted).toBe(false);
    expect(result.abortReason).toBeNull();
    expect(result.stderr).toContain('zap finished');
  });

  it('captures stdout and stderr text', async () => {
    mockProcessKill();
    const child = makeFakeChild();
    const handle = spawnExternal({
      command: '/bin/true',
      args: [],
      timeoutMs: 60_000,
      spawnImpl: makeFakeSpawnImpl(child),
    });

    setImmediate(() => {
      child.stdout.push(Buffer.from('hello stdout\n'));
      child.emitStderr('hello stderr\n');
      child.finishWith(1);
    });

    const result = await handle.done;
    expect(result.stdout).toContain('hello stdout');
    expect(result.stderr).toContain('hello stderr');
    expect(result.exitCode).toBe(1);
  });

  it('forwards stdout/stderr chunks to onStdout/onStderr callbacks', async () => {
    mockProcessKill();
    const child = makeFakeChild();
    const onStderr = jest.fn();
    const onStdout = jest.fn();
    const handle = spawnExternal({
      command: '/bin/true',
      args: [],
      timeoutMs: 60_000,
      spawnImpl: makeFakeSpawnImpl(child),
      onStderr,
      onStdout,
    });

    setImmediate(() => {
      child.stdout.push(Buffer.from('one'));
      child.emitStderr('two');
      child.finishWith(0);
    });

    await handle.done;
    expect(onStdout).toHaveBeenCalledWith('one');
    expect(onStderr).toHaveBeenCalledWith('two');
  });
});

describe('spawnExternal — abort()', () => {
  // We assert observable behavior (result.aborted + abortReason) rather than
  // which OS-level kill API was used. The actual `process.kill(-pid, sig)`
  // group-kill on Linux is exercised by the real-Docker e2e in Task 10.

  it('marks result.aborted=true with the requested reason on first abort()', async () => {
    mockProcessKill();
    const child = makeFakeChild();
    const handle = spawnExternal({
      command: '/bin/sleep',
      args: ['600'],
      timeoutMs: 60_000,
      spawnImpl: makeFakeSpawnImpl(child),
    });

    handle.abort('cancellation_requested');
    setImmediate(() => child.finishWith(null, 'SIGTERM'));
    const result = await handle.done;
    expect(result.aborted).toBe(true);
    expect(result.abortReason).toBe('cancellation_requested');
  });

  it('is idempotent — second abort() with a different reason keeps the original reason', async () => {
    mockProcessKill();
    const child = makeFakeChild();
    const handle = spawnExternal({
      command: '/bin/sleep',
      args: ['600'],
      timeoutMs: 60_000,
      spawnImpl: makeFakeSpawnImpl(child),
    });

    handle.abort('cancellation_requested');
    handle.abort('auth_lost_threshold');
    setImmediate(() => child.finishWith(null, 'SIGTERM'));
    const result = await handle.done;
    expect(result.abortReason).toBe('cancellation_requested');
  });
});

describe('spawnExternal — scan_timeout', () => {
  it('auto-aborts with reason scan_timeout when timeoutMs elapses', async () => {
    mockProcessKill();
    const child = makeFakeChild();
    const handle = spawnExternal({
      command: '/bin/sleep',
      args: ['600'],
      timeoutMs: 30, // 30ms — short for tests
      spawnImpl: makeFakeSpawnImpl(child),
    });

    await new Promise((r) => setTimeout(r, 60));
    child.finishWith(null, 'SIGTERM');
    const result = await handle.done;
    expect(result.aborted).toBe(true);
    expect(result.abortReason).toBe('scan_timeout');
  });
});

describe('spawnExternal — Windows tree-kill via taskkill', () => {
  // The Linux path uses `process.kill(-pid, sig)` to group-kill. On Windows
  // there's no process group; child.kill() alone leaves descendants running
  // (e.g. ZAP-spawned Java + Firefox after we abort the parent). We shell out
  // to `taskkill /F /T /PID` to walk the tree. Verify it gets dispatched.
  const realPlatform = Object.getOwnPropertyDescriptor(process, 'platform');

  afterEach(() => {
    if (realPlatform) Object.defineProperty(process, 'platform', realPlatform);
  });

  function setPlatformWin32(): void {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
  }

  it('spawns `taskkill /F /T /PID <pid>` on win32 when abort() fires', async () => {
    setPlatformWin32();
    mockProcessKill();
    const child = makeFakeChild();
    const taskkill = makeFakeChild();
    taskkill.pid = 4242;

    const spawnCalls: Array<{ command: string; args: readonly string[] }> = [];
    const spawnImpl = ((command: string, args: readonly string[]) => {
      spawnCalls.push({ command, args });
      return command === 'taskkill' ? taskkill : child;
    }) as unknown as typeof import('child_process').spawn;

    const handle = spawnExternal({
      command: 'C:\\zap\\zap.bat',
      args: [],
      timeoutMs: 60_000,
      spawnImpl,
    });

    handle.abort('cancellation_requested');
    setImmediate(() => {
      taskkill.finishWith(0);
      child.finishWith(null, 'SIGTERM');
    });
    const result = await handle.done;

    expect(result.aborted).toBe(true);
    expect(child.killCalls).toContain('SIGTERM');
    const tk = spawnCalls.find((c) => c.command === 'taskkill');
    expect(tk).toBeDefined();
    expect(tk!.args).toEqual(['/F', '/T', '/PID', String(child.pid)]);
  });

  it('survives a taskkill spawn ENOENT (taskkill missing on PATH)', async () => {
    setPlatformWin32();
    mockProcessKill();
    const child = makeFakeChild();
    const failingTaskkill = makeFakeChild();

    const spawnImpl = ((command: string) => {
      if (command === 'taskkill') {
        // Defer the error to next tick so spawnExternal can attach its
        // 'error' handler before the event fires.
        setImmediate(() => failingTaskkill.emit('error', new Error('ENOENT')));
        return failingTaskkill;
      }
      return child;
    }) as unknown as typeof import('child_process').spawn;

    const handle = spawnExternal({
      command: 'C:\\zap\\zap.bat',
      args: [],
      timeoutMs: 60_000,
      spawnImpl,
    });

    handle.abort('cancellation_requested');
    setImmediate(() => child.finishWith(null, 'SIGTERM'));
    const result = await handle.done;
    expect(result.aborted).toBe(true);
    // child.kill() best-effort still happens.
    expect(child.killCalls).toContain('SIGTERM');
  });
});

describe('spawnExternal — SIGTERM grace constant', () => {
  it('SIGTERM_GRACE_MS is 10 seconds (per plan §Task 7)', () => {
    expect(SIGTERM_GRACE_MS).toBe(10_000);
  });
});

describe('spawnExternal — error during spawn', () => {
  it('rejects when child emits error before close', async () => {
    mockProcessKill();
    const child = makeFakeChild();
    const handle = spawnExternal({
      command: '/does/not/exist',
      args: [],
      timeoutMs: 60_000,
      spawnImpl: makeFakeSpawnImpl(child),
    });

    setImmediate(() => {
      child.emit('error', new Error('ENOENT'));
    });

    await expect(handle.done).rejects.toThrow('ENOENT');
  });
});

// ---------------------------------------------------------------------------
// createAuthLostWatcher
// ---------------------------------------------------------------------------

describe('createAuthLostWatcher', () => {
  it('fires onThresholdReached after 4 hits in default window', () => {
    const onThresholdReached = jest.fn();
    const w = createAuthLostWatcher({ onThresholdReached });
    w.recordHit(200, '/page1');
    w.recordHit(200, '/page2');
    w.recordHit(302, '/page3');
    expect(onThresholdReached).not.toHaveBeenCalled();
    w.recordHit(401, '/page4');
    expect(onThresholdReached).toHaveBeenCalledTimes(1);
    expect(onThresholdReached.mock.calls[0][0].consecutiveLostCount).toBe(4);
    expect(onThresholdReached.mock.calls[0][0].lastLoggedOutUrl).toBe('/page4');
  });

  it('ignores 5xx and non-401 4xx', () => {
    const onThresholdReached = jest.fn();
    const w = createAuthLostWatcher({ onThresholdReached });
    for (let i = 0; i < 10; i++) {
      w.recordHit(500, '/page');
      w.recordHit(404, '/page');
      w.recordHit(403, '/page');
    }
    expect(onThresholdReached).not.toHaveBeenCalled();
    expect(w.state().consecutiveLostCount).toBe(0);
  });

  it('resets count on indicator clear', () => {
    const onThresholdReached = jest.fn();
    const w = createAuthLostWatcher({ onThresholdReached });
    w.recordHit(200, '/a');
    w.recordHit(200, '/b');
    w.recordHit(200, '/c');
    expect(w.state().consecutiveLostCount).toBe(3);
    w.recordIndicatorClear();
    expect(w.state().consecutiveLostCount).toBe(0);
    w.recordHit(401, '/d');
    expect(onThresholdReached).not.toHaveBeenCalled();
  });

  it('only fires onThresholdReached once even on subsequent hits', () => {
    const onThresholdReached = jest.fn();
    const w = createAuthLostWatcher({ onThresholdReached });
    for (let i = 0; i < 8; i++) w.recordHit(200, `/p${i}`);
    expect(onThresholdReached).toHaveBeenCalledTimes(1);
  });

  it('respects custom threshold', () => {
    const onThresholdReached = jest.fn();
    const w = createAuthLostWatcher({ onThresholdReached, threshold: 2 });
    w.recordHit(200, '/a');
    expect(onThresholdReached).not.toHaveBeenCalled();
    w.recordHit(200, '/b');
    expect(onThresholdReached).toHaveBeenCalledTimes(1);
  });

  it('default constants match plan acceptance', () => {
    expect(DEFAULT_AUTH_LOST_THRESHOLD).toBe(4);
    expect(DEFAULT_AUTH_LOST_WINDOW_MS).toBe(5 * 60_000);
  });
});
