-- phase34a — scan_jobs.type='dast_zap_dry_run' for Test-login probes.
--
-- /criticalreview SVED-1 (P0): the v2.1d Test-login flow queued
-- type='dast_zap' with payload.dry_run=true, distinguished only by a payload
-- key the worker dispatcher inspected. claim_scan_job() filters ONLY by
-- (status='queued', type IN supportedTypes) — no payload/version/capability
-- gate. A stale pre-v2.1d worker (warm Fly machine, partial-deploy window,
-- scale-to-zero machine pinned to an older revision) would claim the row,
-- ignore the unknown dry_run key, and run a full spider + active-scan
-- against the user's app using their recorded credentials. User clicked
-- "Test login" expecting a 60-second probe; got a 30-minute production
-- scan that pollutes their findings dataset and PDV graph.
--
-- The structural fix: introduce a NEW scan_jobs.type value. Old workers
-- don't advertise it; the row sits queued until a v2.1d+ worker arrives.
-- New workers dispatch on type directly — the payload.dry_run flag is no
-- longer load-bearing (kept as transitional, will be removed in v2.1e).
--
-- Changes:
--   1. CHECK constraint scan_jobs_type_check extended to include
--      'dast_zap_dry_run'.
--   2. queue_scan_job() routes the new type through the same DAST
--      validation as 'dast_zap' (target_id required, SSRF check,
--      credentials lookup, concurrency cap).
--   3. The existing per-project DAST concurrency cap (1) intentionally
--      applies to dry_run too — Test-login while a real scan is running
--      surfaces the 409 'project_concurrent_dast_blocked' which the FE's
--      Cancel-running-scan affordance handles.
--
-- Migration shape: pure additive. CREATE OR REPLACE on the function, ALTER
-- on the CHECK constraint. No data backfill. Safe to re-apply.

BEGIN;

-- Step 1: widen the scan_jobs.type CHECK constraint.
ALTER TABLE public.scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_type_check;
ALTER TABLE public.scan_jobs ADD CONSTRAINT scan_jobs_type_check
  CHECK ((type = ANY (ARRAY[
    'extraction'::text,
    'dast'::text,
    'dast_zap'::text,
    'dast_nuclei'::text,
    'dast_zap_dry_run'::text
  ])));

-- Step 2: queue_scan_job() must route 'dast_zap_dry_run' through DAST
-- validation. The function body is identical to the pre-existing version
-- except every `type IN ('dast', 'dast_zap', 'dast_nuclei')` predicate is
-- widened to include 'dast_zap_dry_run'.
CREATE OR REPLACE FUNCTION public.queue_scan_job(
  p_project_id uuid,
  p_organization_id uuid,
  p_type text,
  p_payload jsonb,
  p_target_id uuid DEFAULT NULL::uuid,
  p_target_url text DEFAULT NULL::text,
  p_scan_profile text DEFAULT NULL::text,
  p_timeout_minutes integer DEFAULT NULL::integer,
  p_trigger_source text DEFAULT NULL::text,
  p_triggered_by uuid DEFAULT NULL::uuid
)
 RETURNS scan_jobs
 LANGUAGE plpgsql
AS $function$
DECLARE
  v_target_org_id UUID;
  v_target_project_id UUID;
  v_org_concurrent INT;
  v_proj_concurrent INT;
  v_inserted scan_jobs%ROWTYPE;
  v_credential_id UUID;
  v_credential_hash TEXT;
  v_host TEXT;
BEGIN
  IF p_type IN ('dast', 'dast_zap', 'dast_nuclei', 'dast_zap_dry_run') THEN
    IF p_target_id IS NULL THEN
      RAISE EXCEPTION 'queue_scan_job: p_target_id is required for dast* types'
        USING ERRCODE = 'P0001';
    END IF;

    SELECT project_id, organization_id INTO v_target_project_id, v_target_org_id
    FROM project_dast_targets
    WHERE id = p_target_id;

    IF v_target_project_id IS NULL THEN
      RAISE EXCEPTION 'queue_scan_job: target % not found', p_target_id
        USING ERRCODE = 'P0001';
    END IF;

    IF v_target_project_id <> p_project_id OR v_target_org_id <> p_organization_id THEN
      RAISE EXCEPTION
        'queue_scan_job: tenant drift — target % belongs to (project=%, org=%); caller passed (project=%, org=%)',
        p_target_id, v_target_project_id, v_target_org_id, p_project_id, p_organization_id
        USING ERRCODE = 'P0001';
    END IF;

    IF p_target_url IS NULL THEN
      SELECT target_url INTO p_target_url
      FROM project_dast_targets
      WHERE id = p_target_id;
    END IF;

    v_host := lower(substring(p_target_url FROM '^[a-z]+://([^:/?#]+)'));

    IF v_host IS NULL OR v_host = '' THEN
      RAISE EXCEPTION 'queue_scan_job: target_url must be http(s) URL with host'
        USING ERRCODE = 'P0001';
    END IF;

    IF v_host = 'localhost'
       OR v_host = '0.0.0.0'
       OR v_host = '::1'
       OR v_host LIKE '127.%'
       OR v_host LIKE '10.%'
       OR v_host LIKE '192.168.%'
       OR v_host ~ '^172\.(1[6-9]|2[0-9]|3[0-1])\.'
       OR v_host LIKE '169.254.%'
       OR v_host LIKE 'fe80:%'
       OR v_host LIKE 'fdaa:%'
       OR v_host LIKE '%.internal'
       OR v_host LIKE '%.fly.dev.internal' THEN
      RAISE EXCEPTION 'queue_scan_job: target_url host % rejected (private/loopback/internal)', v_host
        USING ERRCODE = 'P0001';
    END IF;

    SELECT id, encode(digest(encrypted_payload, 'sha256'), 'hex')
    INTO v_credential_id, v_credential_hash
    FROM project_dast_credentials
    WHERE target_id = p_target_id;

    SELECT COUNT(*) INTO v_proj_concurrent
    FROM scan_jobs
    WHERE project_id = p_project_id
      AND type IN ('dast', 'dast_zap', 'dast_nuclei', 'dast_zap_dry_run')
      AND status IN ('queued', 'processing');

    IF v_proj_concurrent >= 1 THEN
      RAISE EXCEPTION 'queue_scan_job: project_concurrent_dast_blocked'
        USING ERRCODE = 'P0001',
              DETAIL = 'A DAST scan is already queued or running for this project.';
    END IF;

    SELECT COUNT(*) INTO v_org_concurrent
    FROM scan_jobs
    WHERE organization_id = p_organization_id
      AND type IN ('dast', 'dast_zap', 'dast_nuclei', 'dast_zap_dry_run')
      AND status IN ('queued', 'processing');

    IF v_org_concurrent >= 5 THEN
      RAISE EXCEPTION 'queue_scan_job: org_concurrent_dast_cap'
        USING ERRCODE = 'P0001',
              DETAIL = 'Organization is at the 5-concurrent DAST scan cap.';
    END IF;
  END IF;

  INSERT INTO scan_jobs (
    project_id, organization_id, type, status, payload,
    target_id, target_url,
    scan_profile, timeout_minutes,
    trigger_source, triggered_by,
    credential_id, credential_payload_hash
  )
  VALUES (
    p_project_id, p_organization_id, p_type, 'queued', COALESCE(p_payload, '{}'::jsonb),
    p_target_id, p_target_url,
    p_scan_profile, p_timeout_minutes,
    p_trigger_source, p_triggered_by,
    v_credential_id, v_credential_hash
  )
  RETURNING * INTO v_inserted;

  RETURN v_inserted;
END;
$function$;

COMMIT;

-- Sanity: assert the new type is in the CHECK constraint.
DO $$
DECLARE v_ok BOOLEAN;
BEGIN
  SELECT 'dast_zap_dry_run' = ANY (
    string_to_array(
      regexp_replace(pg_get_constraintdef(oid), '.*ARRAY\[(.*?)\].*', '\1'),
      ', '
    )::text[]
  )
  OR pg_get_constraintdef(oid) LIKE '%dast_zap_dry_run%'
  INTO v_ok
  FROM pg_constraint
  WHERE conname = 'scan_jobs_type_check';

  IF NOT COALESCE(v_ok, FALSE) THEN
    RAISE EXCEPTION 'phase34a: scan_jobs_type_check is missing dast_zap_dry_run after migration';
  END IF;
END $$;
