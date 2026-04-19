-- Supabase Storage Setup for Custom Integration Icons
-- Run this in your Supabase SQL Editor

-- Create the integration-icons storage bucket
INSERT INTO storage.buckets (id, name, public)
VALUES ('integration-icons', 'integration-icons', true)
ON CONFLICT (id) DO NOTHING;

-- Allow authenticated org members to upload icons
CREATE POLICY "Org members can upload integration icons"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'integration-icons' AND
  (storage.foldername(name))[1] IN (
    SELECT id::text FROM organizations
    WHERE id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  )
);

-- Allow org members to update icons
CREATE POLICY "Org members can update integration icons"
ON storage.objects FOR UPDATE
TO authenticated
USING (
  bucket_id = 'integration-icons' AND
  (storage.foldername(name))[1] IN (
    SELECT id::text FROM organizations
    WHERE id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  )
)
WITH CHECK (
  bucket_id = 'integration-icons' AND
  (storage.foldername(name))[1] IN (
    SELECT id::text FROM organizations
    WHERE id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  )
);

-- Allow org members to delete icons
CREATE POLICY "Org members can delete integration icons"
ON storage.objects FOR DELETE
TO authenticated
USING (
  bucket_id = 'integration-icons' AND
  (storage.foldername(name))[1] IN (
    SELECT id::text FROM organizations
    WHERE id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  )
);

-- Public read access for icons (they're displayed in the UI)
CREATE POLICY "Public can view integration icons"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'integration-icons');
