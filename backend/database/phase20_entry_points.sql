-- Phase 20: project_entry_points table.
--
-- Populated by the framework rule-pack layer in the tree-sitter extractor
-- (Phase 2 of the reachability roadmap). Consumed by EPD contextual scoring
-- (Phase 4) and UI entry-point visualizations ("where does the attacker get
-- in?").
--
-- Lifecycle mirrors the Phase 19 atomic soft-switch: rows are written under
-- the pending extraction_run_id and made visible when commit_extraction flips
-- the project's active_extraction_run_id. Carry-forward is handled by the
-- commit_extraction RPC (updated in a later milestone when the extractor
-- actually populates this table).

CREATE TABLE IF NOT EXISTS project_entry_points (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_number INTEGER NOT NULL,
  framework TEXT NOT NULL,
    -- 'express' | 'fastify' | 'koa' | 'nextjs' | 'nestjs' | 'aws-lambda'
    -- | 'flask' | 'django' | 'fastapi' | 'starlette' | 'tornado' | 'aiohttp'
    -- | 'spring' | 'quarkus' | 'micronaut' | 'jaxrs'
    -- | 'nethttp' | 'gin' | 'echo' | 'fiber' | 'chi' | 'gorilla-mux'
    -- | 'rails' | 'sinatra' | 'grape'
    -- | 'laravel' | 'symfony' | 'slim'
    -- | 'actix' | 'axum' | 'rocket' | 'warp'
    -- | 'aspnet-core' | 'minimal-apis'
  handler_name TEXT,
  http_method TEXT,
    -- 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS' | NULL
  route_pattern TEXT,
  entry_point_type TEXT NOT NULL,
    -- 'http_route' | 'graphql_resolver' | 'websocket' | 'message_handler'
    -- | 'cli_command' | 'cron_job' | 'background_job' | 'event_listener'
    -- | 'rpc_method' | 'serverless_handler'
  classification TEXT NOT NULL DEFAULT 'UNKNOWN',
    -- 'PUBLIC_UNAUTH' | 'AUTH_INTERNAL' | 'OFFLINE_WORKER' | 'UNKNOWN'
  authenticated BOOLEAN,
  auth_mechanism TEXT,
    -- Free-form signal from rule: 'bearer_jwt' | 'session_cookie' | 'api_key' | 'mtls' | NULL
  middleware_chain TEXT[],
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (project_id, extraction_run_id, file_path, line_number, framework, handler_name)
);

CREATE INDEX IF NOT EXISTS idx_pep_project ON project_entry_points(project_id);
CREATE INDEX IF NOT EXISTS idx_pep_run ON project_entry_points(extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_pep_framework ON project_entry_points(framework);
CREATE INDEX IF NOT EXISTS idx_pep_classification ON project_entry_points(classification);
CREATE INDEX IF NOT EXISTS idx_pep_project_run ON project_entry_points(project_id, extraction_run_id);

-- No RLS: matches sibling extractor-populated tables (project_reachable_flows,
-- project_usage_slices, project_dependency_functions). Access is mediated by
-- the backend API using the service role; the user-facing routes gate on
-- project membership before returning rows.
