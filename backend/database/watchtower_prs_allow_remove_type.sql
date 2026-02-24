-- DEPRECATED: Table renamed to dependency_prs; type check is in dependency_prs_schema.sql.
-- Allow type 'remove' in watchtower_prs for zombie dependency removal PRs.
-- Existing CHECK (type IN ('bump', 'decrease')) is replaced to include 'remove'.

ALTER TABLE watchtower_prs DROP CONSTRAINT IF EXISTS watchtower_prs_type_check;
ALTER TABLE watchtower_prs ADD CONSTRAINT watchtower_prs_type_check
  CHECK (type IN ('bump', 'decrease', 'remove'));
