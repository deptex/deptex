-- phase9z: Aegis Task primitive — "a task is a chat with one goal".
--
-- A task is an aegis_chat_threads row (context_type='task') plus one
-- aegis_agent_tasks record. Execution reuses the untouched
-- project_security_fixes -> fix-worker pipeline, linked by a new task_id.
-- Status surfacing reuses finding_tracker_links with a new 'aegis' provider.
--
-- Named to sort LAST in backend/database filename order (lexical: phase20 <
-- phase7 < phase9z) so a fresh filename-replay applies it after the tables it
-- references (phase7 project_security_fixes, phase57 finding_tracker_links,
-- aegis_chat_threads_schema). Apply to prod via Supabase MCP FIRST, then
-- `cd depscanner && npm run schema:dump`, then diff schema.sql.

BEGIN;

-- 1. The task record. STABLE identity only in `targets`; live finding rows are
--    re-resolved at accept time (PDV uuids churn on every rescan).
CREATE TABLE IF NOT EXISTS public.aegis_agent_tasks (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  project_id      uuid REFERENCES public.projects(id) ON DELETE SET NULL,
  created_by      uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  thread_id       uuid REFERENCES public.aegis_chat_threads(id) ON DELETE CASCADE,  -- task IS a chat; tear down together
  kind            text NOT NULL DEFAULT 'fix',          -- forward-compat for investigate/report; CHECK widened later
  title           text NOT NULL,
  description     text,
  status          text NOT NULL DEFAULT 'proposed',
  source          text NOT NULL DEFAULT 'chat',
  targets         jsonb NOT NULL DEFAULT '[]'::jsonb,   -- [{findingType, findingKey, osvId?, projectId, label}]
  total_fixes     integer NOT NULL DEFAULT 0,           -- planned count, stamped up front in acceptTask
  completed_fixes integer NOT NULL DEFAULT 0,
  failed_fixes    integer NOT NULL DEFAULT 0,
  summary         text,
  accepted_at     timestamptz,
  started_at      timestamptz,
  completed_at    timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT aegis_agent_tasks_status_chk CHECK (status = ANY (ARRAY[
    'proposed','working','completed','completed_with_failures','failed','declined','cancelled','needs_input'])),
  CONSTRAINT aegis_agent_tasks_source_chk CHECK (source = ANY (ARRAY['chat','finding'])),
  CONSTRAINT aegis_agent_tasks_kind_chk   CHECK (kind = 'fix')          -- widen when non-fix task types ship
);
-- 1:1 task <-> chat. Partial so multiple proposed (thread-less) tasks coexist.
CREATE UNIQUE INDEX IF NOT EXISTS uq_aegis_agent_tasks_thread
  ON public.aegis_agent_tasks (thread_id) WHERE thread_id IS NOT NULL;
-- Serves the sidebar pile list (WHERE org ORDER BY created_at DESC).
CREATE INDEX IF NOT EXISTS idx_aegis_agent_tasks_org_created
  ON public.aegis_agent_tasks (organization_id, created_at DESC);

CREATE OR REPLACE FUNCTION public.update_aegis_agent_tasks_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_aegis_agent_tasks_updated_at ON public.aegis_agent_tasks;
CREATE TRIGGER trg_aegis_agent_tasks_updated_at BEFORE UPDATE ON public.aegis_agent_tasks
  FOR EACH ROW EXECUTE FUNCTION public.update_aegis_agent_tasks_updated_at();

-- 2. Link each fix to its parent task. SET NULL (not CASCADE) intentionally —
--    preserve fix/PR history if a task is deleted.
ALTER TABLE public.project_security_fixes
  ADD COLUMN IF NOT EXISTS task_id uuid REFERENCES public.aegis_agent_tasks(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_psf_task_id
  ON public.project_security_fixes (task_id) WHERE task_id IS NOT NULL;

-- 3. Aegis-as-a-tracker: relax the provider CHECK to admit 'aegis'. Must reach
--    prod BEFORE any code inserts provider='aegis'. CI's schema-check only greps
--    identifier presence (the chk name is unchanged) — diff the dump manually.
ALTER TABLE public.finding_tracker_links DROP CONSTRAINT IF EXISTS finding_tracker_links_provider_chk;
ALTER TABLE public.finding_tracker_links ADD CONSTRAINT finding_tracker_links_provider_chk
  CHECK (provider = ANY (ARRAY['jira'::text,'linear'::text,'github'::text,'aegis'::text]));
CREATE INDEX IF NOT EXISTS idx_ftl_provider_external
  ON public.finding_tracker_links (provider, external_id);

-- 4. Rollup: recompute a task's status from its fixes, and ✓ the Aegis chips
--    ONLY when the task resolved cleanly (no failures) and fully (all planned
--    fixes terminal). Never touches a user-terminal (declined/cancelled) task.
CREATE OR REPLACE FUNCTION public.recompute_aegis_task_status() RETURNS trigger AS $$
DECLARE v_task uuid := NEW.task_id; v_planned int; v_status text;
        v_total int; v_done int; v_failed int; v_open int;
BEGIN
  SELECT total_fixes, status INTO v_planned, v_status FROM public.aegis_agent_tasks WHERE id = v_task;
  IF v_task IS NULL OR v_status IN ('declined','cancelled') THEN RETURN NEW; END IF;   -- user-terminal: never touch status/chips
  SELECT count(*),
         count(*) FILTER (WHERE status='completed'),
         count(*) FILTER (WHERE status IN ('failed','rejected')),
         count(*) FILTER (WHERE status IN ('planning','awaiting_approval','approved','executing'))
    INTO v_total, v_done, v_failed, v_open
    FROM public.project_security_fixes WHERE task_id = v_task;
  UPDATE public.aegis_agent_tasks SET
    completed_fixes = v_done, failed_fixes = v_failed,
    status = CASE
      WHEN v_open > 0 OR v_total < v_planned THEN 'working'      -- not all planned fixes exist yet -> no premature completion
      WHEN v_failed = 0 THEN 'completed'
      WHEN v_done   = 0 THEN 'failed'
      ELSE 'completed_with_failures' END,
    completed_at = CASE WHEN v_open = 0 AND v_total >= v_planned THEN now() ELSE completed_at END,
    updated_at = now()
   WHERE id = v_task;
  -- ✓ the Aegis chips ONLY when the task resolved cleanly (no failures) and fully.
  IF v_open = 0 AND v_total >= v_planned AND v_failed = 0 THEN
    UPDATE public.finding_tracker_links SET external_state='done', external_state_synced_at=now()
     WHERE provider='aegis' AND external_id = v_task::text;
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_recompute_aegis_task_status ON public.project_security_fixes;
CREATE TRIGGER trg_recompute_aegis_task_status
  AFTER INSERT OR UPDATE OF status ON public.project_security_fixes
  FOR EACH ROW WHEN (NEW.task_id IS NOT NULL)        -- never fires for ordinary single-fix flows
  EXECUTE FUNCTION public.recompute_aegis_task_status();

COMMIT;
