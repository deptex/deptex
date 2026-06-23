-- phase62: stop finalize_extraction timing out on container-heavy projects.
--
-- finalize_extraction does NOT set its own statement_timeout, so it inherited the
-- API role's lightweight default (~8s). Inside it, the container status carry-forward
-- (UPDATE project_container_findings new_cf ... FROM project_container_findings old_cf
-- ON container_fingerprint) self-joins this run against the previous run. For projects
-- whose Dockerfile base image is ancient (e.g. rust:1.60.0 / golang:1.17.0 / ruby:2.7.0
-- carry ~7-11k OS CVEs each), that touches ~11k+ rows and blew the ~8s budget — the whole
-- extraction failed at "finalize_extraction: canceling statement due to statement timeout"
-- (observed on dogfood axum/gin/rails/fastapi; the lighter nextjs/laravel squeaked under).
--
-- The atomic commit is a heavy step and legitimately needs more than the API default
-- (the depscanner worker already tolerates finalize taking up to ~10 min). Give the
-- function its own budget, and add a composite index so the carry-forward join (and the
-- reap that follows) stay index-driven on (project, run, fingerprint).

ALTER FUNCTION public.finalize_extraction(uuid, uuid, text) SET statement_timeout TO '120s';

CREATE INDEX IF NOT EXISTS idx_pcf_carryforward
  ON public.project_container_findings (project_id, extraction_run_id, container_fingerprint)
  WHERE container_fingerprint IS NOT NULL;
