import { ENTRY_WEIGHT_BY_CLASS } from '../epd';
import type { EntryPointClassification } from '../epd';

describe('ENTRY_WEIGHT_BY_CLASS', () => {
  it('matches the EPD spec (framework-rule-pack-guide)', () => {
    expect(ENTRY_WEIGHT_BY_CLASS.PUBLIC_UNAUTH).toBe(1.0);
    expect(ENTRY_WEIGHT_BY_CLASS.AUTH_INTERNAL).toBe(0.5);
    expect(ENTRY_WEIGHT_BY_CLASS.OFFLINE_WORKER).toBe(0.2);
    expect(ENTRY_WEIGHT_BY_CLASS.UNKNOWN).toBe(1.0);
  });

  it('covers every EntryPointClassification value', () => {
    const classifications: EntryPointClassification[] = [
      'PUBLIC_UNAUTH',
      'AUTH_INTERNAL',
      'OFFLINE_WORKER',
      'UNKNOWN',
    ];
    for (const c of classifications) {
      expect(typeof ENTRY_WEIGHT_BY_CLASS[c]).toBe('number');
      expect(ENTRY_WEIGHT_BY_CLASS[c]).toBeGreaterThan(0);
      expect(ENTRY_WEIGHT_BY_CLASS[c]).toBeLessThanOrEqual(1);
    }
  });

  it('conservative-default: UNKNOWN assumed worst-case (weight 1.0) when AI cannot classify', () => {
    expect(ENTRY_WEIGHT_BY_CLASS.UNKNOWN).toBe(ENTRY_WEIGHT_BY_CLASS.PUBLIC_UNAUTH);
  });

  it('OFFLINE_WORKER under-weighted vs PUBLIC_UNAUTH (offline path deprioritized)', () => {
    expect(ENTRY_WEIGHT_BY_CLASS.OFFLINE_WORKER).toBeLessThan(ENTRY_WEIGHT_BY_CLASS.PUBLIC_UNAUTH);
    expect(ENTRY_WEIGHT_BY_CLASS.OFFLINE_WORKER).toBeLessThan(ENTRY_WEIGHT_BY_CLASS.AUTH_INTERNAL);
  });
});
