-- Supabase Storage Setup for Avatars
-- Run this in your Supabase SQL Editor

-- Create the avatars storage bucket
INSERT INTO storage.buckets (id, name, public)
VALUES ('avatars', 'avatars', true)
ON CONFLICT (id) DO NOTHING;

-- Create policy to allow authenticated users to upload their own avatars
-- Files are stored in avatars/{user_id}/{filename}
CREATE POLICY "Users can upload their own avatar"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'avatars' AND
  (storage.foldername(name))[1] = auth.uid()::text
);

-- Create policy to allow users to update their own avatars
CREATE POLICY "Users can update their own avatar"
ON storage.objects FOR UPDATE
TO authenticated
USING (
  bucket_id = 'avatars' AND
  (storage.foldername(name))[1] = auth.uid()::text
)
WITH CHECK (
  bucket_id = 'avatars' AND
  (storage.foldername(name))[1] = auth.uid()::text
);

-- Create policy to allow users to delete their own avatars
CREATE POLICY "Users can delete their own avatar"
ON storage.objects FOR DELETE
TO authenticated
USING (
  bucket_id = 'avatars' AND
  (storage.foldername(name))[1] = auth.uid()::text
);

-- Create policy to allow public read access to avatars
CREATE POLICY "Public can view avatars"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'avatars');

-- Alternative: Allow users to upload any file in avatars folder (simpler)
-- If the above policies don't work, use this instead:
/*
CREATE POLICY "Authenticated users can upload avatars"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'avatars');

CREATE POLICY "Authenticated users can update avatars"
ON storage.objects FOR UPDATE
TO authenticated
USING (bucket_id = 'avatars')
WITH CHECK (bucket_id = 'avatars');

CREATE POLICY "Authenticated users can delete avatars"
ON storage.objects FOR DELETE
TO authenticated
USING (bucket_id = 'avatars');

CREATE POLICY "Public can view avatars"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'avatars');
*/

