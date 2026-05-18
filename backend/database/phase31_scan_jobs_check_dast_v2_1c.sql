-- Extend scan_jobs_dast_columns_match_type to cover dast_zap + dast_nuclei.
--
-- phase24a forward-reserved 'dast_zap' and 'dast_nuclei' on the
-- scan_jobs.type CHECK so the v2.1c (Nuclei) and the split ZAP path could
-- land without a destructive enum migration. The sister CHECK that gates
-- which rows may carry the DAST-only payload columns (target_url,
-- scan_profile, timeout_minutes, trigger_source, triggered_by,
-- error_category, findings_count, duration_seconds) was not updated at the
-- same time and still gates on `type = 'dast'` exactly. As soon as a
-- worker enqueues a real `dast_zap` or `dast_nuclei` row with a
-- target_url, the row is rejected by this CHECK.
--
-- Widen the gate to allow any DAST-family type to carry the sparse columns;
-- non-DAST rows (extraction) must continue to leave them NULL.

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_dast_columns_match_type;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_dast_columns_match_type
  CHECK (
    (type IN ('dast', 'dast_zap', 'dast_nuclei')) OR (
      target_url IS NULL
      AND scan_profile IS NULL
      AND timeout_minutes IS NULL
      AND trigger_source IS NULL
      AND triggered_by IS NULL
      AND error_category IS NULL
      AND findings_count IS NULL
      AND duration_seconds IS NULL
    )
  );
