import { isLowPrecisionGuardDogRule } from '../malicious/guarddog';

describe('isLowPrecisionGuardDogRule — drop noisy GuardDog source heuristics', () => {
  it('suppresses low-precision structural heuristics across ecosystem prefixes', () => {
    expect(isLowPrecisionGuardDogRule('npm-api-obfuscation')).toBe(true);
    expect(isLowPrecisionGuardDogRule('pypi-api-obfuscation')).toBe(true);
    expect(isLowPrecisionGuardDogRule('NPM-API-OBFUSCATION')).toBe(true);
    // Presence-of-install-hook (flagged esbuild / @types/node) and the
    // suspicious-domain-shape heuristic (flagged is-number / micromatch /
    // proxy-from-env) are structural, not behavioral — suppressed.
    expect(isLowPrecisionGuardDogRule('npm-install-script')).toBe(true);
    expect(isLowPrecisionGuardDogRule('npm-shady-links')).toBe(true);
  });

  it('keeps high-signal behavioral malware rules', () => {
    expect(isLowPrecisionGuardDogRule('npm-exfiltrate-sensitive-data')).toBe(false);
    expect(isLowPrecisionGuardDogRule('npm-silent-process-execution')).toBe(false);
    expect(isLowPrecisionGuardDogRule('npm-obfuscated-code')).toBe(false);
  });

  it('is safe on empty / unknown rule ids', () => {
    expect(isLowPrecisionGuardDogRule('')).toBe(false);
    expect(isLowPrecisionGuardDogRule('obfuscation-something-else')).toBe(false);
  });
});
