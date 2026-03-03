-- Feedback table for user-submitted issues and ideas (CE).
-- Used by the header Feedback popover; optional user_id when logged in.

CREATE TABLE IF NOT EXISTS feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  type text NOT NULL CHECK (type IN ('issue', 'idea')),
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_feedback_type ON feedback (type);

COMMENT ON TABLE feedback IS 'User feedback (issues/ideas) from the app header; CE.';
 