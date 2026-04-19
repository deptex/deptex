-- Allow users to delete their own invitations when accepting
-- This is needed when a user accepts an invitation

CREATE POLICY "Users can delete their own invitations"
  ON organization_invitations FOR DELETE
  USING (
    email = (SELECT email FROM auth.users WHERE id = auth.uid())
  );

