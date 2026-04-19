-- Phase 6B: Code-Level Reachability Engine
-- Tables for storing atom/dep-scan deep reachability analysis results

-- Reachable data-flow paths traced by atom engine
CREATE TABLE IF NOT EXISTS project_reachable_flows (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  purl TEXT NOT NULL,
  dependency_id UUID REFERENCES dependencies(id),
  flow_nodes JSONB NOT NULL,
  entry_point_file TEXT,
  entry_point_method TEXT,
  entry_point_line INTEGER,
  entry_point_tag TEXT,
  sink_file TEXT,
  sink_method TEXT,
  sink_line INTEGER,
  sink_is_external BOOLEAN DEFAULT true,
  flow_length INTEGER,
  llm_prompt TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, extraction_run_id, purl, entry_point_file, entry_point_line, sink_method)
);

CREATE INDEX IF NOT EXISTS idx_prf_project_purl ON project_reachable_flows(project_id, purl);
CREATE INDEX IF NOT EXISTS idx_prf_project_dep ON project_reachable_flows(project_id, dependency_id);
CREATE INDEX IF NOT EXISTS idx_prf_project_entry ON project_reachable_flows(project_id, entry_point_file);
CREATE INDEX IF NOT EXISTS idx_prf_run ON project_reachable_flows(extraction_run_id);

-- Usage slices: how each library is used (resolved methods, types)
CREATE TABLE IF NOT EXISTS project_usage_slices (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_number INTEGER NOT NULL,
  containing_method TEXT,
  target_name TEXT NOT NULL,
  target_type TEXT,
  resolved_method TEXT,
  usage_label TEXT,
  ecosystem TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, file_path, line_number, target_name)
);

CREATE INDEX IF NOT EXISTS idx_pus_project_type ON project_usage_slices(project_id, target_type);
CREATE INDEX IF NOT EXISTS idx_pus_project_file ON project_usage_slices(project_id, file_path);
CREATE INDEX IF NOT EXISTS idx_pus_run ON project_usage_slices(extraction_run_id);

-- Add reachability level columns to project_dependency_vulnerabilities
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS reachability_level TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS reachability_details JSONB;
