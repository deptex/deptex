-- Org overview canvas positions
-- Adds persisted (x, y) coordinates for teams and projects on the multiplayer
-- org overview graph. NULL = never placed (layout hook will seed with a
-- Fibonacci fallback on first admin load). Non-NULL = authoritative; never
-- recomputed. Existing row-level security on teams/projects already gates
-- read/write by org membership, so no new policies are needed for these
-- additive columns.

ALTER TABLE teams
  ADD COLUMN IF NOT EXISTS canvas_position_x NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_y NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_updated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS canvas_position_updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS canvas_position_x NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_y NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_updated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS canvas_position_updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL;
