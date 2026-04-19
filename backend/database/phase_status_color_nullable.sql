-- Allow organization_statuses.color to be NULL so "no color" (transparent badge) matches Create Role behavior.
-- Safe: no data removed; existing rows keep their color.
ALTER TABLE organization_statuses
  ALTER COLUMN color DROP NOT NULL,
  ALTER COLUMN color DROP DEFAULT;
