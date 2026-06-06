import { isLowPrecisionGuardDogRule } from '../malicious/guarddog';

describe('isLowPrecisionGuardDogRule — drop noisy GuardDog source heuristics', () => {
  it('suppresses api-obfuscation across ecosystem prefixes', () => {
    expect(isLowPrecisionGuardDogRule('npm-api-obfuscation')).toBe(true);
    expect(isLowPrecisionGuardDogRule('pypi-api-obfuscation')).toBe(true);
    expect(isLowPrecisionGuardDogRule('NPM-API-OBFUSCATION')).toBe(true);
  });

  it('keeps high-signal malware rules', () => {
    expect(isLowPrecisionGuardDogRule('npm-exfiltrate-sensitive-data')).toBe(false);
    expect(isLowPrecisionGuardDogRule('npm-install-script')).toBe(false);
    expect(isLowPrecisionGuardDogRule('npm-silent-process-execution')).toBe(false);
  });

  it('is safe on empty / unknown rule ids', () => {
    expect(isLowPrecisionGuardDogRule('')).toBe(false);
    expect(isLowPrecisionGuardDogRule('obfuscation-something-else')).toBe(false);
  });
});
