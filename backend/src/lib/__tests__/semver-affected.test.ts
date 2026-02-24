/**
 * Tests for semver-affected (isVersionAffected, isVersionFixed).
 * Ensures version comparison uses semver correctly (e.g. 1.13 > 1.9, not string sort).
 */

import { isVersionAffected, isVersionFixed } from '../semver-affected';

describe('semver-affected', () => {
  describe('isVersionAffected', () => {
    it('uses semver comparison: 1.13 is not less than 1.9', () => {
      // Vuln affects < 1.10 (fixed in 1.10). Version 1.13 should NOT be affected (1.13 >= 1.10).
      const affected = [{ ranges: [{ events: [{ introduced: '0.0.0', fixed: '1.10.0' }] }] }];
      expect(isVersionAffected('1.9.0', affected)).toBe(true);
      expect(isVersionAffected('1.10.0', affected)).toBe(false);
      expect(isVersionAffected('1.13.0', affected)).toBe(false);
      expect(isVersionAffected('1.13', affected)).toBe(false);
    });

    it('uses semver comparison: 1.9 is affected when fixed is 1.10', () => {
      const affected = [{ ranges: [{ events: [{ introduced: '0.0.0', fixed: '1.10.0' }] }] }];
      expect(isVersionAffected('1.9', affected)).toBe(true);
      expect(isVersionAffected('1.9.5', affected)).toBe(true);
    });

    it('handles versions list (exact match)', () => {
      const affected = [{ versions: ['1.13.0', '1.9.0'] }];
      expect(isVersionAffected('1.9.0', affected)).toBe(true);
      expect(isVersionAffected('1.13.0', affected)).toBe(true);
      expect(isVersionAffected('1.12.0', affected)).toBe(false);
    });

    it('returns false for invalid version', () => {
      const affected = [{ ranges: [{ events: [{ introduced: '0.0.0' }] }] }];
      expect(isVersionAffected('not-a-version', affected)).toBe(false);
    });

    it('returns true when affectedVersions is null (conservative)', () => {
      expect(isVersionAffected('1.0.0', null)).toBe(true);
    });
  });

  describe('isVersionFixed', () => {
    it('uses semver comparison: 1.13 >= 1.10 is fixed', () => {
      expect(isVersionFixed('1.13.0', ['1.10.0'])).toBe(true);
      expect(isVersionFixed('1.13', ['1.10.0'])).toBe(true);
      expect(isVersionFixed('1.9.0', ['1.10.0'])).toBe(false);
    });

    it('uses semver comparison: 1.9 is not >= 1.10', () => {
      expect(isVersionFixed('1.9', ['1.10.0'])).toBe(false);
      expect(isVersionFixed('1.10.0', ['1.10.0'])).toBe(true);
    });

    it('returns false for empty fixed list', () => {
      expect(isVersionFixed('1.13.0', [])).toBe(false);
      expect(isVersionFixed('1.13.0', null)).toBe(false);
    });
  });
});
