CREATE TABLE IF NOT EXISTS dependency_note_reactions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  note_id UUID REFERENCES dependency_notes(id) ON DELETE CASCADE,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  emoji TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(note_id, user_id, emoji)
);

CREATE INDEX idx_dependency_note_reactions_note ON dependency_note_reactions(note_id);
CREATE INDEX idx_dependency_note_reactions_user ON dependency_note_reactions(user_id);

ALTER TABLE dependency_note_reactions ENABLE ROW LEVEL SECURITY;

-- Org members can view reactions on notes for dependencies in projects belonging to their org
CREATE POLICY "Org members can view note reactions" ON dependency_note_reactions FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM dependency_notes dn
    JOIN project_dependencies pd ON pd.id = dn.project_dependency_id
    JOIN projects p ON p.id = pd.project_id
    JOIN organization_members om ON om.organization_id = p.organization_id
    WHERE dn.id = dependency_note_reactions.note_id AND om.user_id = auth.uid()
  )
);

-- Org members can add reactions (their own user_id)
CREATE POLICY "Org members can add note reactions" ON dependency_note_reactions FOR INSERT WITH CHECK (
  user_id = auth.uid()
  AND EXISTS (
    SELECT 1 FROM dependency_notes dn
    JOIN project_dependencies pd ON pd.id = dn.project_dependency_id
    JOIN projects p ON p.id = pd.project_id
    JOIN organization_members om ON om.organization_id = p.organization_id
    WHERE dn.id = dependency_note_reactions.note_id AND om.user_id = auth.uid()
  )
);

-- Users can delete only their own reactions
CREATE POLICY "Users can delete own note reactions" ON dependency_note_reactions FOR DELETE USING (
  user_id = auth.uid()
);
