-- Wake the Task Agent: resume a terminal agent fix row via a follow-up message.
--
-- A "wake" reuses the SAME project_security_fixes row (keeps the deterministic
-- branch name, the ChangeCard subscription keyed on fixId, and the rollup's
-- one-row-per-target invariant so a retried FAILED row's success actually drops
-- v_failed and re-flips the tracker chips). It resets the terminal row back to
-- 'approved', stamps plan.resume + plan.prior_status so the worker replays the
-- thread (and can restore 'completed' if the user Stops a resume of an already
-- -completed task), and bumps run_seq so the per-run billing meter key changes
-- (each user-initiated wake bills once; run_seq=0 keeps the historical ':final'
-- key so fixes that straddle the deploy never double-bill).
--
-- DDL safety: ADD COLUMN ... NOT NULL DEFAULT 0 is a metadata-only change on
-- PG 11+ (Supabase runs PG 15) — no table rewrite, brief ACCESS EXCLUSIVE lock;
-- IF NOT EXISTS makes it idempotent. Backward-compatible (the old worker reads
-- row.run_seq ?? 0), so forward-only with no DOWN. Rollout order still matters
-- for CODE: deploy the fix-worker resume image BEFORE the backend/frontend that
-- expose the wake endpoint — an old worker claiming a woken row would re-run it
-- as a first run (same deterministic branch -> non-fast-forward push + dup PR).
--
-- Apply to prod via Supabase MCP FIRST, then `cd depscanner && npm run
-- schema:dump`, then diff schema.sql.

BEGIN;

-- run_seq: the billing-meter dedup boundary. 0 = first run; +1 per user wake.
-- Recovery re-claims never touch run_seq, so a crashed-then-recovered run still
-- bills exactly once (and for agent rows max_attempts=1 means recovery never
-- re-runs them anyway — it fails them; a new user message is the retry).
ALTER TABLE public.project_security_fixes
  ADD COLUMN IF NOT EXISTS run_seq integer NOT NULL DEFAULT 0;

-- wake_agent_fix: idempotently resurrect a terminal agent fix row for a resume.
-- Returns the row id when it actually woke one (caller boots a machine), NULL
-- when the row is non-terminal (a run is active or already queued — the
-- worker's end-of-run drain handles any queued follow-up) or not an agent row.
--
-- Also does the re-open housekeeping the rollup trigger cannot: the trigger
-- only ever SETS chips to 'done' and preserves completed_at, so waking a
-- completed task must reset the aegis tracker links to 'open' and null the
-- task's completed_at here. Lives in the RPC (not the endpoint) so BOTH wake
-- paths — the /message endpoint and the worker's end-of-run drain — get it.
CREATE OR REPLACE FUNCTION public.wake_agent_fix(p_fix_id uuid)
RETURNS uuid
LANGUAGE plpgsql AS $$
DECLARE
  v_id uuid;
  v_task uuid;
BEGIN
  UPDATE public.project_security_fixes psf
    SET status = 'approved',
        attempts = 0,
        machine_id = NULL,
        heartbeat_at = NULL,
        started_at = NULL,
        completed_at = NULL,
        error_message = NULL,
        error_category = NULL,
        failure_details = NULL,
        rejected_at = NULL,
        rejected_by_user_id = NULL,
        rejection_reason = NULL,
        approved_at = NOW(),
        run_seq = psf.run_seq + 1,
        -- plan.resume flags the worker's replay path; plan.prior_status lets a
        -- Stop of a resume-of-completed restore the original success instead of
        -- downgrading it to failed. (SET expressions read OLD column values.)
        plan = COALESCE(psf.plan, '{}'::jsonb)
                 || jsonb_build_object('resume', true, 'prior_status', psf.status)
    WHERE psf.id = p_fix_id
      AND psf.strategy = 'agent'
      AND psf.status IN ('completed', 'failed', 'rejected')
    RETURNING psf.id, psf.task_id INTO v_id, v_task;

  IF v_id IS NULL THEN
    RETURN NULL;  -- active run / already queued / non-agent: no-op
  END IF;

  IF v_task IS NOT NULL THEN
    -- Re-open the task. The status flip above already fired the rollup trigger
    -- (v_open>0 -> 'working'), but the trigger keeps the stale completed_at and
    -- early-returns entirely for user-terminal ('cancelled'/'declined') tasks —
    -- both handled here.
    UPDATE public.aegis_agent_tasks
      SET status = CASE WHEN status IN ('cancelled', 'declined') THEN 'working' ELSE status END,
          completed_at = NULL,
          updated_at = NOW()
      WHERE id = v_task;
    -- Un-green the chips while the resume runs; the trigger re-flips them to
    -- 'done' only when the resume lands cleanly.
    UPDATE public.finding_tracker_links
      SET external_state = 'open', external_state_synced_at = NOW()
      WHERE provider = 'aegis' AND external_id = v_task::text;
  END IF;

  RETURN v_id;
END;
$$;

COMMIT;
