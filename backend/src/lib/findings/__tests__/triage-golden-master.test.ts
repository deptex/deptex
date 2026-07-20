import {
  GOLDEN_CASES,
  referenceStoredAutoIgnored,
  referenceEffectiveAutoIgnored,
} from '../triage-golden-master';
import { vulnAutoIgnoreReason } from '../../aegis/finding-triage';

/**
 * Golden-master freeze. Locks the per-row auto-triage verdict as of the
 * findings-status foundation so the SQL `compute_auto_ignored()` (phase55) can
 * be proven byte-equal to it, and so the backend Aegis mirror
 * (`vulnAutoIgnoreReason`) is shown to agree before it is cut over to the
 * stored column. The matching frontend lock against the REAL `autoTriageRow`
 * lives in frontend/src/components/security/__tests__/autoTriage.test.ts — keep
 * the two case sets in sync until autoTriageRow is deleted.
 */
describe('triage golden master — reference port', () => {
  it.each(GOLDEN_CASES.map((c) => [c.name, c] as const))(
    'stored verdict: %s',
    (_name, c) => {
      expect(referenceStoredAutoIgnored(c.type, c.input)).toEqual(c.stored);
    },
  );

  it.each(GOLDEN_CASES.map((c) => [c.name, c] as const))(
    'effective verdict: %s',
    (_name, c) => {
      expect(referenceEffectiveAutoIgnored(c.type, c.input)).toEqual(c.effective);
    },
  );

  it('composition law: effective = stored, with the PDV runtime override applied', () => {
    for (const c of GOLDEN_CASES) {
      const overridden =
        c.type === 'vulnerability' && c.input.runtime_confirmed_at
          ? { auto_ignored: false, auto_ignore_reason: null }
          : c.stored;
      expect(c.effective).toEqual(overridden);
    }
  });

  it('only the four row-level types ever produce auto_ignored=true', () => {
    const ignorable = new Set(['vulnerability', 'container', 'iac', 'dast']);
    for (const c of GOLDEN_CASES) {
      if (c.stored.auto_ignored) expect(ignorable.has(c.type)).toBe(true);
    }
  });
});

describe('triage golden master — backend Aegis mirror agrees on SCA', () => {
  // `vulnAutoIgnoreReason` is the SCA-only effective verdict Aegis reasons with.
  // It must equal the effective reason for every vulnerability case, or the
  // agent contradicts what the user sees in the table.
  it.each(
    GOLDEN_CASES.filter((c) => c.type === 'vulnerability').map((c) => [c.name, c] as const),
  )('vulnAutoIgnoreReason matches effective: %s', (_name, c) => {
    const expected = c.effective.auto_ignored ? c.effective.auto_ignore_reason : null;
    expect(vulnAutoIgnoreReason(c.input)).toBe(expected);
  });
});
