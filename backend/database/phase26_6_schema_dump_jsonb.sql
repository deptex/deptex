-- Wrap pg_catalog_dump_v1() in a JSONB-returning sibling so the dump
-- script bypasses PostgREST's db-max-rows cap (1000 on managed Supabase).
--
-- The schema crossed 1000 rows during Phase 6 — the trigger section sorts
-- last and was being silently truncated, leaking out of schema.sql one PR
-- at a time. JSONB returns are a single response value, not subject to
-- the row cap.
--
-- Original SETOF function is left in place so any out-of-tree caller that
-- relies on it keeps working.

CREATE OR REPLACE FUNCTION public.pg_catalog_dump_v1_all()
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
  SELECT COALESCE(
    jsonb_agg(
      jsonb_build_object('kind', kind, 'ord', ord, 'ddl', ddl)
      ORDER BY ord, ddl
    ),
    '[]'::jsonb
  )
  FROM public.pg_catalog_dump_v1();
$$;

REVOKE EXECUTE ON FUNCTION public.pg_catalog_dump_v1_all() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.pg_catalog_dump_v1_all() TO service_role;
