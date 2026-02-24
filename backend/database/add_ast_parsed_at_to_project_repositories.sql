-- Track when AST import analysis completed for a project (used for "finalizing" status)
ALTER TABLE project_repositories
  ADD COLUMN IF NOT EXISTS ast_parsed_at TIMESTAMP WITH TIME ZONE DEFAULT NULL;

COMMENT ON COLUMN project_repositories.ast_parsed_at IS 'Set when parser-worker finishes import analysis; null while AST parsing is queued or in progress.';
