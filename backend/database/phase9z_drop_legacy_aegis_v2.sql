-- phase9z: remove the dead legacy aegis-v2 task primitive.
--
-- phase20 already DROPs these, but phase20 sorts BEFORE phase7b in filename
-- order ('phase20' < 'phase7b'), so a fresh filename-replay runs phase20's DROP
-- (no-op) and THEN phase7b's CREATE — leaving aegis_tasks recreated. This file
-- sorts AFTER phase7b ('phase9z' > 'phase7b') so a fresh replay ends WITHOUT
-- the legacy tables. On prod (already past phase20) this is a harmless no-op.
--
-- Only the legacy *task* primitive is removed. aegis-v3 still uses aegis_memory,
-- aegis_org_settings, aegis_tool_executions, aegis_event_triggers — DO NOT drop
-- those here. Incident tables were dropped in phase20 and are never recreated.

BEGIN;

DROP TABLE IF EXISTS public.aegis_task_steps CASCADE;
DROP TABLE IF EXISTS public.aegis_tasks CASCADE;
DROP TABLE IF EXISTS public.aegis_approval_requests CASCADE;

COMMIT;
