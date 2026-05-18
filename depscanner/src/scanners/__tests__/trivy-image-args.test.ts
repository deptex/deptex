/**
 * runTrivyImage invocation guard.
 *
 * Phase 2's container reachability classifier depends on Trivy emitting the
 * full installed-package list under Results[].Packages[]. That only happens
 * when `--list-all-pkgs` is passed. This test pins the flag into the
 * invocation so a future refactor of runTrivyImage's args can't silently
 * drop it and starve the classifier of loaded-vs-installed signal.
 *
 * A real-Trivy integration run against alpine:3.20 would be the fuller check,
 * but it needs the Trivy binary + its CVE DB + network — not jest territory.
 */

const runScannerSubprocess = jest.fn();

jest.mock('../../with-timeout', () => ({
  runScannerSubprocess: (...args: unknown[]) => runScannerSubprocess(...args),
}));

import { runTrivyImage, _resetTrivyVersionCacheForTests } from '../trivy';

describe('runTrivyImage invocation', () => {
  beforeEach(() => {
    runScannerSubprocess.mockReset();
    _resetTrivyVersionCacheForTests();
  });

  it('passes --list-all-pkgs so Results[].Packages[] is populated', async () => {
    // First call resolves the Trivy version; second is the image scan.
    runScannerSubprocess
      .mockResolvedValueOnce({ stdout: 'Version: 0.69.3\n', exitCode: 0 })
      .mockResolvedValueOnce({ stdout: '{"Results":[]}', exitCode: 0 });

    await runTrivyImage({ imageRef: 'alpine:3.20' });

    const imageCall = runScannerSubprocess.mock.calls[1][0] as { exe: string; args: string[] };
    expect(imageCall.exe).toBe('trivy');
    expect(imageCall.args).toContain('--list-all-pkgs');
    // The flag must precede the image ref — Trivy treats trailing tokens as the target.
    expect(imageCall.args.indexOf('--list-all-pkgs')).toBeLessThan(
      imageCall.args.indexOf('alpine:3.20')
    );
  });

  it('keeps the existing --scanners=vuln and --platform flags alongside it', async () => {
    runScannerSubprocess
      .mockResolvedValueOnce({ stdout: 'Version: 0.69.3\n', exitCode: 0 })
      .mockResolvedValueOnce({ stdout: '{"Results":[]}', exitCode: 0 });

    await runTrivyImage({ imageRef: 'node:20-slim' });

    const imageCall = runScannerSubprocess.mock.calls[1][0] as { args: string[] };
    expect(imageCall.args).toEqual(
      expect.arrayContaining(['--scanners=vuln', '--list-all-pkgs', '--platform', 'linux/amd64'])
    );
  });
});
