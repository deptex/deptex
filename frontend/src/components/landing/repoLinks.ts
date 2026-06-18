/**
 * Single source of truth for every GitHub link on the landing page.
 * Pre-flight blocker #1 (landing-page-redesign.plan.md §1): when the repo is
 * private, REPO_PUBLIC flips false and every RepoLink renders as a plain mono
 * file path instead of an anchor — no 404s, no dead CTAs.
 *
 * Verified PUBLIC 2026-06-11 via `gh repo view deptex/deptex`.
 */
export const REPO_PUBLIC = true;

export const REPO_URL = "https://github.com/deptex/deptex";

/** Deep link to a file (or directory) on the default branch. */
export function repoFile(path: string): string {
  return `${REPO_URL}/blob/main/${path}`;
}

/** Deep link to a directory tree on the default branch. */
export function repoDir(path: string): string {
  return `${REPO_URL}/tree/main/${path}`;
}
