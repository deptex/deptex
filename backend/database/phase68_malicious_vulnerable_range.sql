-- phase68: malicious feed semver-RANGE matching (N4)
--
-- Malicious-package feed matching is exact-version only: a
-- `known_malicious_packages` row matches solely when the installed version
-- string equals the row's concrete `version`. Range-scoped malware advisories
-- (a GHSA `vulnerableVersionRange` like `>= 1.0, < 2.0`, or a `>= 0`
-- "all versions" assertion) are written as enumerated versions or — when they
-- can't be enumerated — collapsed to a single `version=null` "flag-all" row.
-- The scan side (depscanner `lookupFeed`) correctly SKIPS those null-version
-- rows to avoid the name-only false positive (flagging clean chalk@5.6.2 just
-- because chalk@5.6.1 was once compromised), but that turns range-scoped
-- advisories into false NEGATIVES.
--
-- This adds a `vulnerable_range` column so the feed-sync write side can store
-- a worker-evaluable range string ALONGSIDE (not instead of) the exact
-- `version` rows. The depscanner side flags a package only when the installed
-- version SATISFIES the range — precise, not flag-all.
--
-- Scope: only **npm** rows carry a populated `vulnerable_range` (a `semver`
-- range string). semver is the one range grammar the worker evaluates
-- correctly; every other ecosystem keeps exact-version matching unchanged, and
-- we never guess foreign range semantics.
--
-- Flag-all FP guard is preserved end-to-end: a row with NEITHER an exact
-- `version` NOR a `vulnerable_range` is still skipped at scan time. Existing
-- rows back-fill to `vulnerable_range = NULL` (column is nullable) and so keep
-- their current behavior until the next feed-sync re-writes them.

ALTER TABLE public.known_malicious_packages
  ADD COLUMN IF NOT EXISTS vulnerable_range text;
