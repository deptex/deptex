-- Phase 27e: defense-in-depth RLS on container_image_scan_cache.
--
-- The table is intentionally tenant-global (content-addressed by image digest)
-- and the worker reads/writes via service role which bypasses RLS. The
-- migration-safety-auditor flagged that without RLS, any future GRANT to
-- anon/authenticated — even one added by accident — would leak first-scanned
-- forensics columns and full vulnerability lists across orgs.
--
-- This migration enables RLS and installs a deny-all policy for the
-- non-service roles. Service role access is unchanged (RLS bypass).

ALTER TABLE container_image_scan_cache ENABLE ROW LEVEL SECURITY;

-- USING (false) for the SELECT policy; WITH CHECK (false) on the write
-- policies. Without these, ENABLE ROW LEVEL SECURITY alone defaults to
-- deny-all for non-service roles which is what we want, but explicit
-- policies make the intent visible to anyone reading the schema.
DROP POLICY IF EXISTS cisc_deny_anon_select ON container_image_scan_cache;
CREATE POLICY cisc_deny_anon_select ON container_image_scan_cache
  FOR SELECT TO anon, authenticated USING (false);

DROP POLICY IF EXISTS cisc_deny_anon_write ON container_image_scan_cache;
CREATE POLICY cisc_deny_anon_write ON container_image_scan_cache
  FOR ALL TO anon, authenticated USING (false) WITH CHECK (false);
