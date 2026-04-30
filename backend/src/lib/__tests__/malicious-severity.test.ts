import {
  severityForFeedFinding,
  severityForGuardDogFinding,
  severityRank,
  maxSeverity,
} from '../malicious/severity';

describe('severityForFeedFinding', () => {
  it('always returns critical (feed match is a confirmed malicious advisory)', () => {
    expect(severityForFeedFinding()).toBe('critical');
  });
});

describe('severityForGuardDogFinding', () => {
  it.each([
    ['ERROR', 'high'],
    ['error', 'high'],
    ['WARNING', 'medium'],
    ['warning', 'medium'],
    ['INFO', 'info'],
  ])('GuardDog %s -> %s', (raw, expected) => {
    expect(severityForGuardDogFinding(raw)).toBe(expected);
  });

  it('falls back to info for unknown / missing severity instead of throwing', () => {
    expect(severityForGuardDogFinding(null)).toBe('info');
    expect(severityForGuardDogFinding(undefined)).toBe('info');
    expect(severityForGuardDogFinding('')).toBe('info');
    expect(severityForGuardDogFinding('UNRECOGNISED')).toBe('info');
  });
});

describe('severity rank + maxSeverity', () => {
  it('ranks critical highest, info lowest', () => {
    expect(severityRank('critical')).toBeGreaterThan(severityRank('high'));
    expect(severityRank('high')).toBeGreaterThan(severityRank('medium'));
    expect(severityRank('medium')).toBeGreaterThan(severityRank('low'));
    expect(severityRank('low')).toBeGreaterThan(severityRank('info'));
  });

  it('maxSeverity picks the higher-ranked input regardless of order', () => {
    expect(maxSeverity('critical', 'low')).toBe('critical');
    expect(maxSeverity('low', 'critical')).toBe('critical');
    expect(maxSeverity('high', 'medium')).toBe('high');
    expect(maxSeverity('info', 'info')).toBe('info');
  });
});
