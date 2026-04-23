-- Add canvas_cursors_enabled flag to organizations.
-- When false, live cursor presence is disabled org-wide. Only the org owner can toggle it.
ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS canvas_cursors_enabled BOOLEAN DEFAULT TRUE;
