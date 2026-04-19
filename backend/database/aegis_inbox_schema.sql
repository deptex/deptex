-- Aegis inbox messages table
CREATE TABLE IF NOT EXISTS aegis_inbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('alert', 'message', 'task', 'approval', 'report')),
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  metadata JSONB DEFAULT '{}',
  read BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE aegis_inbox ENABLE ROW LEVEL SECURITY;

-- RLS Policies for aegis_inbox
-- Users can view inbox messages for organizations they are members of
-- If user_id is null, it's org-wide and all members can see it
-- If user_id is set, only that user can see it
CREATE POLICY "Users can view aegis inbox messages for their orgs"
  ON aegis_inbox FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
    AND (aegis_inbox.user_id IS NULL OR aegis_inbox.user_id = auth.uid())
  );

-- Only authenticated users can create inbox messages (typically done by backend/Aegis)
CREATE POLICY "Authenticated users can create aegis inbox messages"
  ON aegis_inbox FOR INSERT
  WITH CHECK (auth.uid() IS NOT NULL);

-- Users can update their own inbox messages (mark as read)
CREATE POLICY "Users can update their own aegis inbox messages"
  ON aegis_inbox FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
    AND (aegis_inbox.user_id IS NULL OR aegis_inbox.user_id = auth.uid())
  );

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_aegis_inbox_organization_id ON aegis_inbox(organization_id);
CREATE INDEX IF NOT EXISTS idx_aegis_inbox_user_id ON aegis_inbox(user_id);
CREATE INDEX IF NOT EXISTS idx_aegis_inbox_read ON aegis_inbox(read);
CREATE INDEX IF NOT EXISTS idx_aegis_inbox_created_at ON aegis_inbox(created_at DESC);

