export type Edition = 'ce' | 'ee';

/**
 * Returns the current Deptex edition.
 * - DEPTEX_EDITION=ce: Community Edition (no EE routes)
 * - DEPTEX_EDITION=ee: Enterprise Edition (full SaaS)
 * - Unset: defaults to CE so deployment works without ee/ when ee is removed temporarily
 */
export function getEdition(): Edition {
  const edition = process.env.DEPTEX_EDITION;
  if (edition === 'ce') return 'ce';
  if (edition === 'ee') return 'ee';
  return 'ce';
}

export function isEeEdition(): boolean {
  return getEdition() === 'ee';
}
