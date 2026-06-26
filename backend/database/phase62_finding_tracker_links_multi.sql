-- phase62: allow multiple tracker issues per (finding, provider)
--
-- A finding can legitimately be tracked by several issues in the same provider
-- (e.g. two Linear issues, or a GitHub issue per affected service). The old
-- unique (project, type, key, provider) blocked the second one. Relax it to
-- include external_id so distinct tickets are allowed while still preventing the
-- exact same ticket being linked twice.

ALTER TABLE public.finding_tracker_links
  DROP CONSTRAINT IF EXISTS finding_tracker_links_unique;

ALTER TABLE public.finding_tracker_links
  ADD CONSTRAINT finding_tracker_links_unique
  UNIQUE (project_id, finding_type, finding_key, provider, external_id);
