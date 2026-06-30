-- phase66_silence_events.sql
--
-- Workstream M (M1) — Silence-event log for the reachability classifier.
--
-- WHY: depscanner's reachability classifier decides, per PDV
-- (project_dependency_vulnerabilities row), a `reachability_level`
-- (unreachable/module/function/data_flow/confirmed) + `is_reachable`. When it
-- marks a vuln `unreachable` or `module` the finding is auto-ignored
-- (depscore ~0). Today that verdict is OVERWRITTEN IN PLACE every run
-- (reachability.ts batch upsert onConflict 'id'), with NO history, so we cannot
-- diff two runs to detect when a previously-silenced vuln gets promoted — the
-- cheapest ground-truth signal that the earlier silence was a false-negative.
--
-- This table is a durable, append-one-row-per-(run, pdv) record of the silence/
-- reachability verdict plus the classifier inputs that produced it. It is PURE
-- OBSERVABILITY: nothing reads it on the prod silence path, so it cannot change
-- any finding's visibility. M2 (cross-run silence-FN differ) reads it.
--
-- CONVENTIONS (match per-run worker tables like project_reachable_flows):
--   * No inline FK constraints. `pdv_id` / `project_dependency_id` point at rows
--     that reap_old_extractions() prunes (it keeps only the active + previous
--     runs). A FK + ON DELETE CASCADE would erode the history we exist to keep;
--     a soft uuid pointer keeps full history regardless of PDV pruning.
--   * `extraction_run_id` is the scan_jobs.id stored as TEXT (same as every other
--     per-run table) — no extraction_runs table exists to reference.
--   * uuid_generate_v4() default (uuid-ossp), same as PDV + project_reachable_flows;
--     available in PGLite local mode via the uuid_ossp contrib bundle.
--
-- LOCAL MODE: the depscanner CLI / CI run against PGLite seeded from
-- backend/database/schema.sql. After this migration lands, HAND-PATCH schema.sql
-- to add this CREATE TABLE + indexes (do NOT `npm run schema:dump` — that pulls
-- prod drift). The silence-event write goes through the same Storage.upsert()
-- surface as the PDV write, so it works in both Supabase (prod) and PGLite modes.

CREATE TABLE IF NOT EXISTS public.silence_events (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),

  -- Tenancy + run axes -------------------------------------------------------
  project_id uuid NOT NULL,                 -- soft pointer (no FK; tenancy boundary)
  extraction_run_id text NOT NULL,          -- scan_jobs.id as text; the "run" axis of history

  -- Subject pointers ---------------------------------------------------------
  pdv_id uuid NOT NULL,                      -- the run-specific PDV row id (NOT stable across runs)
  project_dependency_id uuid NOT NULL,       -- STABLE across runs (PD upserts on name+version+...);
                                             --   primary cross-run join key (with osv_id) for M2
  dependency_id uuid NOT NULL,               -- global package id (stable); package-level bucketing
  osv_id text NOT NULL,                      -- CVE/GHSA id (stable); other half of the M2 join key

  -- The verdict --------------------------------------------------------------
  reachability_level text NOT NULL,          -- confirmed|data_flow|function|module|unreachable (`level`)
  is_reachable boolean NOT NULL,             -- `isReachable` (level <> 'unreachable')
  verdict text,                              -- fine-grained silence reason from details.verdict:
                                             --   dev_scope_unreachable | orphan_transitive_unreachable |
                                             --   transitive_of_reachable | callgraph_reached_transitive;
                                             --   NULL for confirmed/data_flow/function/plain-module rows

  -- Classifier inputs (the M-plan's classifier_inputs bundle) ----------------
  graph_trusted boolean NOT NULL,            -- options.graphTrusted (direct/transitive split trusted)
  ast_parsed boolean NOT NULL,               -- options.astParsedSuccessfully (usage extraction ran)
  ecosystem text,                            -- options.ecosystem (npm/pypi/composer/maven/...)
  files_importing_count integer,             -- pd meta.filesImporting (NULL when PD meta missing)
  is_direct boolean,                         -- pd meta.isDirect
  dev_scoped boolean,                        -- isDevScoped(meta.scope)
  callgraph_reached boolean,                 -- depMatchesUsedTransitives(...) for this dep — a cheap
                                             --   silence-FN label: a prior `unreachable` later showing
                                             --   callgraph_reached=true proves the silence was wrong
  classifier_inputs jsonb,                   -- forward-compat catch-all (used_transitives_count,
                                             --   callgraph_ran, is_client_spa, sink_patterns_present, ...)

  created_at timestamp with time zone NOT NULL DEFAULT now(),

  -- One row per PDV per run. The classifier normally runs once per run, but EPD
  -- rescore / retries may re-enter it; the upsert conflict target makes the
  -- write idempotent within a run (last-write-wins) instead of duplicating —
  -- so the table is effectively append-one-row-per-RUN, which is exactly what
  -- M2's cross-run diff needs.
  CONSTRAINT silence_events_run_pdv_uniq UNIQUE (extraction_run_id, pdv_id)
);

-- M2 cross-run self-join: given a prior-run silenced row, find the SAME finding
-- in another run by the stable (project, project_dependency, osv) key, plus the
-- run discriminator. Also serves "recency within a finding".
CREATE INDEX IF NOT EXISTS idx_silence_events_finding
  ON public.silence_events (project_id, project_dependency_id, osv_id, extraction_run_id);

-- Fetch one run's full / silenced event set for a project (M2 reads the prev
-- run's silenced subset and the cur run's rows); also supports cleanup-by-run.
CREATE INDEX IF NOT EXISTS idx_silence_events_project_run
  ON public.silence_events (project_id, extraction_run_id);

-- Hot path for M2: the prior-run "silenced set" scan only cares about
-- unreachable|module rows. Partial index keeps it tiny.
CREATE INDEX IF NOT EXISTS idx_silence_events_silenced
  ON public.silence_events (project_id, extraction_run_id, verdict)
  WHERE reachability_level IN ('unreachable', 'module');

COMMENT ON TABLE public.silence_events IS
  'M1 silence-event log: append-one-row-per-(run,pdv) durable record of the reachability classifier verdict + its inputs. Pure observability (nothing reads it on the prod silence path). M2 diffs the two most-recent runs to catch silence false-negatives. Written by depscanner reachability.updateReachabilityLevels via Storage.upsert(onConflict extraction_run_id,pdv_id).';
COMMENT ON COLUMN public.silence_events.project_dependency_id IS
  'Stable across runs (project_dependencies upserts on project_id+name+version+is_direct+source); the primary cross-run join key with osv_id. pdv_id is NOT stable across runs.';
COMMENT ON COLUMN public.silence_events.verdict IS
  'Fine-grained silence reason from reachability_details.verdict (dev_scope_unreachable / orphan_transitive_unreachable / transitive_of_reachable / callgraph_reached_transitive). NULL for non-silence / plain-module verdicts. M2 buckets transitions by this.';
COMMENT ON COLUMN public.silence_events.callgraph_reached IS
  'Whether the taint-engine callgraph confirmed a CallEdge into this dep (depMatchesUsedTransitives). A prior unreachable row later showing TRUE here is a silence false-negative signal.';
