-- Add get_started_dismissed column to organizations table
-- When true, the "Get Started" onboarding card is hidden for the entire organization
ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS get_started_dismissed BOOLEAN DEFAULT FALSE;
