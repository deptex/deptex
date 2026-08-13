import { describe, it, expect, beforeEach } from 'vitest';
import { resolvePreviewAccess } from '../preview-access';

const STORAGE_KEY = 'deptex_preview_access';
const VALID = '?access=deptex-preview';

describe('resolvePreviewAccess', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('denies a first-time visitor with no query param', () => {
    expect(resolvePreviewAccess('')).toBe(false);
  });

  it('grants access for the correct key and remembers it', () => {
    expect(resolvePreviewAccess(VALID)).toBe(true);
    expect(localStorage.getItem(STORAGE_KEY)).toBe('1');
  });

  it('keeps access on a later visit to a bare /login', () => {
    resolvePreviewAccess(VALID);
    expect(resolvePreviewAccess('')).toBe(true);
  });

  it('survives extra query params alongside the key', () => {
    expect(resolvePreviewAccess('?redirect=%2Fjoin%2Fabc&access=deptex-preview')).toBe(true);
  });

  it('denies a wrong key', () => {
    expect(resolvePreviewAccess('?access=guess')).toBe(false);
  });

  it('revokes a previous grant when an explicit wrong key is passed', () => {
    resolvePreviewAccess(VALID);
    expect(resolvePreviewAccess('?access=off')).toBe(false);
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('does not revoke on an unrelated query param', () => {
    resolvePreviewAccess(VALID);
    expect(resolvePreviewAccess('?redirect=%2Forganizations')).toBe(true);
  });

  it('is case-sensitive about the key', () => {
    expect(resolvePreviewAccess('?access=DEPTEX-PREVIEW')).toBe(false);
  });

  it('treats a non-"1" stored value as no grant', () => {
    localStorage.setItem(STORAGE_KEY, 'true');
    expect(resolvePreviewAccess('')).toBe(false);
  });
});
