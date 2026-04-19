export type Edition = 'ce' | 'ee';

/**
 * Returns the current Deptex edition.
 * - DEPTEX_EDITION=ce: Community Edition (no EE routes)
 * - DEPTEX_EDITION=ee or unset: Enterprise Edition (full SaaS)
 */
export function getEdition(): Edition {
  const edition = process.env.DEPTEX_EDITION;
  if (edition === 'ce') return 'ce';
  if (edition === 'ee') return 'ee';
  // Default to ee when unset to preserve current behavior
  return 'ee';
}

export function isEeEdition(): boolean {
  return getEdition() === 'ee';
}
