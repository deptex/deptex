-- Aegis task-agent durability hardening.
--
-- 1. agent_run_stats: per-run telemetry the worker writes each step so the task
--    chat can render a live context meter (input tokens vs the model's window)
--    and the /status slash command can report step/elapsed/context. jsonb so
--    the shape can grow without another migration:
--      { "inputTokens": int, "window": int, "step": int, "updatedAt": iso }
--
-- 2. A partial UNIQUE index backstopping the double-accept guard: one AGENT fix
--    row per (task, fix_type, finding). The application also does a
--    compare-and-swap on the task's status flip; this index is the last line of
--    defense against two concurrent Accepts fanning out duplicate PRs.
--    Scoped to strategy='agent' + task_id NOT NULL so the legacy standalone
--    request_fix pipeline (many rows per finding over time) is unaffected.

BEGIN;

ALTER TABLE public.project_security_fixes
  ADD COLUMN IF NOT EXISTS agent_run_stats jsonb;

-- The finding is identified by whichever type-specific column is set; coalesce
-- them into one expression so a single partial index covers all fix types.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_fix_per_task_finding
  ON public.project_security_fixes (
    task_id,
    fix_type,
    COALESCE(
      osv_id, semgrep_finding_id::text, secret_finding_id::text, iac_finding_id::text,
      container_finding_id::text, base_image_rec_id::text, dast_finding_id::text,
      reachable_flow_id::text, malicious_finding_id::text, ''
    )
  )
  WHERE strategy = 'agent' AND task_id IS NOT NULL;

COMMIT;
