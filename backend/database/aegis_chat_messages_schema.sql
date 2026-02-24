-- Aegis chat messages table
CREATE TABLE IF NOT EXISTS aegis_chat_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  thread_id UUID NOT NULL REFERENCES aegis_chat_threads(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
  content TEXT NOT NULL,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE aegis_chat_messages ENABLE ROW LEVEL SECURITY;

-- RLS Policies for aegis_chat_messages
-- Users can view messages for threads in organizations they are members of
CREATE POLICY "Users can view aegis messages for their orgs"
  ON aegis_chat_messages FOR SELECT
  USING (
    thread_id IN (
      SELECT id FROM aegis_chat_threads
      WHERE organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
      )
    )
  );

-- Users can create messages for threads in organizations they are members of
CREATE POLICY "Users can create aegis messages"
  ON aegis_chat_messages FOR INSERT
  WITH CHECK (
    thread_id IN (
      SELECT id FROM aegis_chat_threads
      WHERE organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
      )
    )
  );

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_aegis_chat_messages_thread_id ON aegis_chat_messages(thread_id);
CREATE INDEX IF NOT EXISTS idx_aegis_chat_messages_created_at ON aegis_chat_messages(created_at DESC);

