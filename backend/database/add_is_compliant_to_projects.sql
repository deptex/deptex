-- Add is_compliant column to projects table
-- This column tracks the overall license compliance status of a project
-- It defaults to TRUE and is updated when:
-- 1. Dependencies are analyzed
-- 2. Policy exceptions are approved/rejected
-- 3. Organization policies change

ALTER TABLE projects ADD COLUMN IF NOT EXISTS is_compliant BOOLEAN DEFAULT TRUE;

-- Create an index for efficient filtering by compliance status
CREATE INDEX IF NOT EXISTS idx_projects_is_compliant ON projects(is_compliant);
