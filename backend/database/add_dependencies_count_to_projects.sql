-- Add dependencies_count to projects for quick summaries
ALTER TABLE projects
ADD COLUMN IF NOT EXISTS dependencies_count INTEGER DEFAULT 0;

