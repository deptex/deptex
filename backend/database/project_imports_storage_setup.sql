-- Supabase Storage Setup for Project Import Artifacts
-- Bucket: project-imports
-- Path pattern: {project_id}/{run_id}/sbom.json, dep-scan.json, semgrep.json, trufflehog.json
-- Used by extraction worker to store SBOM and scan outputs.

-- Create the project-imports storage bucket (private)
-- Worker uses SUPABASE_SERVICE_ROLE_KEY which bypasses RLS
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('project-imports', 'project-imports', false, 52428800, ARRAY['application/json'])
ON CONFLICT (id) DO NOTHING;
