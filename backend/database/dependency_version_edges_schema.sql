-- Dependency version edges table - stores parent-child relationships between dependency versions
-- This is a global table (not project-scoped). "axios@1.6.0 depends on follow-redirects@1.15.0"
-- is a universal fact, stored once and shared across all projects.

CREATE TABLE IF NOT EXISTS dependency_version_edges (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  parent_version_id UUID NOT NULL REFERENCES dependency_versions(id) ON DELETE CASCADE,
  child_version_id UUID NOT NULL REFERENCES dependency_versions(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(parent_version_id, child_version_id)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_dve_parent ON dependency_version_edges(parent_version_id);
CREATE INDEX IF NOT EXISTS idx_dve_child ON dependency_version_edges(child_version_id);

-- Enable RLS
ALTER TABLE dependency_version_edges ENABLE ROW LEVEL SECURITY;

-- Allow service role full access (global data, not project-scoped)
CREATE POLICY "Service role can manage dependency_version_edges" ON dependency_version_edges
  FOR ALL
  USING (true)
  WITH CHECK (true);
