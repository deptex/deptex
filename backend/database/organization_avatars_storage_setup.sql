-- Supabase Storage Setup for Organization Avatars
-- Run this in your Supabase SQL Editor

-- Create the organization-avatars storage bucket
INSERT INTO storage.buckets (id, name, public)
VALUES ('organization-avatars', 'organization-avatars', true)
ON CONFLICT (id) DO NOTHING;

-- Create policy to allow authenticated users to upload avatars for organizations they own/admin
CREATE POLICY "Admins can upload org avatars"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'organization-avatars' AND
  (storage.foldername(name))[1] IN (
    SELECT id::text FROM organizations
    WHERE id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  )
);

-- Create policy to allow users to update org avatars
CREATE POLICY "Admins can update org avatars"
ON storage.objects FOR UPDATE
TO authenticated
USING (
  bucket_id = 'organization-avatars' AND
  (storage.foldername(name))[1] IN (
    SELECT id::text FROM organizations
    WHERE id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  )
)
WITH CHECK (
  bucket_id = 'organization-avatars' AND
  (storage.foldername(name))[1] IN (
    SELECT id::text FROM organizations
    WHERE id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  )
);

-- Create policy to allow users to delete org avatars
CREATE POLICY "Admins can delete org avatars"
ON storage.objects FOR DELETE
TO authenticated
USING (
  bucket_id = 'organization-avatars' AND
  (storage.foldername(name))[1] IN (
    SELECT id::text FROM organizations
    WHERE id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  )
);

-- Create policy to allow public read access to org avatars
CREATE POLICY "Public can view org avatars"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'organization-avatars');

