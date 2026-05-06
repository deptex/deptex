-- Rollback for phase27e_cache_rls.sql.

DROP POLICY IF EXISTS cisc_deny_anon_write ON container_image_scan_cache;
DROP POLICY IF EXISTS cisc_deny_anon_select ON container_image_scan_cache;
ALTER TABLE container_image_scan_cache DISABLE ROW LEVEL SECURITY;
