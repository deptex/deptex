-- phase58: external ticket state on finding_tracker_links
--
-- Lets a finding's tracker chip show a resolved (✓) state once the linked ticket
-- is closed/done. `external_state` is normalized across providers to 'open' or
-- 'done' (NULL = not yet synced). New tickets are stamped 'open' at creation;
-- GitHub keeps it fresh via the `issues` webhook. Linear/Jira sync is a
-- follow-on (they stay 'open' until then).

ALTER TABLE public.finding_tracker_links
  ADD COLUMN IF NOT EXISTS external_state text,
  ADD COLUMN IF NOT EXISTS external_state_synced_at timestamp with time zone;
