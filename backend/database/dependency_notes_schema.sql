CREATE TABLE IF NOT EXISTS dependency_notes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_dependency_id UUID REFERENCES project_dependencies(id) ON DELETE CASCADE,
  author_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  content TEXT NOT NULL,
  is_warning BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_dependency_notes_pd ON dependency_notes(project_dependency_id);
ALTER TABLE dependency_notes ENABLE ROW LEVEL SECURITY;
-- RLS: org members can view notes for dependencies in projects belonging to their org
CREATE POLICY "Org members can view dependency notes" ON dependency_notes FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM project_dependencies pd
    JOIN projects p ON p.id = pd.project_id
    JOIN organization_members om ON om.organization_id = p.organization_id
    WHERE pd.id = dependency_notes.project_dependency_id AND om.user_id = auth.uid()
  )
);
