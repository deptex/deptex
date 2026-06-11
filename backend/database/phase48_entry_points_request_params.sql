-- Phase 48: project_entry_points query-parameter enrichment (deterministic v1).
--
-- Populated during usage-extraction by the framework detectors' deterministic
-- param harvest (express + flask in v1): for each HTTP route, the request
-- query/header/cookie parameter names the handler reads. Consumed by the DAST
-- OpenAPI synthesizer (depscanner/src/dast/openapi-synth.ts) to emit `query`
-- parameters so ZAP's active scanner injects into real injection points (the
-- express `/api/users?id=` SQLi was previously missed because the synthesized
-- spec declared no query params).
--
-- Shape (JSONB array of OpenAPI-shaped parameter objects):
--   [{ "name": "id", "in": "query", "required": false,
--      "schema": { "type": "string" }, "provenance": "ast" }, ...]
--
-- Rides along the existing whole-row reap of project_entry_points (the Phase 19
-- active-run-pointer model) — no reaper / commit_extraction change required.
-- request_body_schema (POST/PUT body fields) + the LLM enrichment pass are a
-- separate fast-follow (phase49).

ALTER TABLE project_entry_points
  ADD COLUMN IF NOT EXISTS request_params JSONB;
