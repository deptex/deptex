-- Aegis chat threads table
CREATE TABLE IF NOT EXISTS aegis_chat_threads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE aegis_chat_threads ENABLE ROW LEVEL SECURITY;

-- RLS Policies for aegis_chat_threads
-- Users can view threads for organizations they are members of
CREATE POLICY "Users can view aegis threads for their orgs"
  ON aegis_chat_threads FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Users can create threads for organizations they are members of
CREATE POLICY "Users can create aegis threads"
  ON aegis_chat_threads FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
    AND user_id = auth.uid()
  );

-- Users can update their own threads
CREATE POLICY "Users can update their own aegis threads"
  ON aegis_chat_threads FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
    AND user_id = auth.uid()
  );

-- Users can delete their own threads
CREATE POLICY "Users can delete their own aegis threads"
  ON aegis_chat_threads FOR DELETE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
    AND user_id = auth.uid()
  );

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_aegis_chat_threads_organization_id ON aegis_chat_threads(organization_id);
CREATE INDEX IF NOT EXISTS idx_aegis_chat_threads_user_id ON aegis_chat_threads(user_id);
CREATE INDEX IF NOT EXISTS idx_aegis_chat_threads_updated_at ON aegis_chat_threads(updated_at DESC);

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_aegis_chat_threads_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_aegis_chat_threads_updated_at
  BEFORE UPDATE ON aegis_chat_threads
  FOR EACH ROW
  EXECUTE FUNCTION update_aegis_chat_threads_updated_at();

