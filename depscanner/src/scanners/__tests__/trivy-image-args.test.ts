/**
 * runTrivyImage invocation guard.
 *
 * Pins the exact image-scan args so a future refactor can't accidentally
 * regress the platform pin (multi-arch cache-key divergence) or re-add the
 * inert `--list-all-pkgs` flag (the close-out dropped it — the reachability
 * classifier reads the image's own dpkg/apk DB, not Trivy's Packages[]).
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

  it('emits the expected image-scan args', async () => {
    // First call resolves the Trivy version; second is the image scan.
    runScannerSubprocess
      .mockResolvedValueOnce({ stdout: 'Version: 0.69.3\n', exitCode: 0 })
      .mockResolvedValueOnce({ stdout: '{"Results":[]}', exitCode: 0 });

    await runTrivyImage({ imageRef: 'alpine:3.20' });

    const imageCall = runScannerSubprocess.mock.calls[1][0] as { exe: string; args: string[] };
    expect(imageCall.exe).toBe('trivy');
    expect(imageCall.args).toEqual([
      'image',
      '--format', 'json',
      '--scanners=vuln',
      '--platform', 'linux/amd64',
      'alpine:3.20',
    ]);
  });

  it('does NOT pass --list-all-pkgs — nothing reads Results[].Packages[]', async () => {
    runScannerSubprocess
      .mockResolvedValueOnce({ stdout: 'Version: 0.69.3\n', exitCode: 0 })
      .mockResolvedValueOnce({ stdout: '{"Results":[]}', exitCode: 0 });

    await runTrivyImage({ imageRef: 'node:20-slim' });

    const imageCall = runScannerSubprocess.mock.calls[1][0] as { args: string[] };
    expect(imageCall.args).not.toContain('--list-all-pkgs');
  });

  it('keeps the image ref as the trailing positional arg', async () => {
    runScannerSubprocess
      .mockResolvedValueOnce({ stdout: 'Version: 0.69.3\n', exitCode: 0 })
      .mockResolvedValueOnce({ stdout: '{"Results":[]}', exitCode: 0 });

    await runTrivyImage({ imageRef: 'node:20-slim' });

    const imageCall = runScannerSubprocess.mock.calls[1][0] as { args: string[] };
    expect(imageCall.args[imageCall.args.length - 1]).toBe('node:20-slim');
  });
});
