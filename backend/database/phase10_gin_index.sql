-- Phase 10: GIN index on activities.metadata for project-scoped activity queries
-- (activities has no project_id column; filtering uses metadata->>'project_id')
CREATE INDEX IF NOT EXISTS idx_activities_metadata ON activities USING GIN (metadata);
