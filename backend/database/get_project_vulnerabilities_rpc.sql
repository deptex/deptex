-- Single-query path for project vulnerabilities: RPC + composite index for join performance.
-- Use from GET /api/organizations/:id/projects/:projectId/vulnerabilities.

-- Composite index to speed up join: project_dependencies(project_id, dependency_id)
CREATE INDEX IF NOT EXISTS idx_project_dependencies_project_id_dependency_id
  ON project_dependencies(project_id, dependency_id);

-- RPC: return all vulnerabilities for a project's dependencies in one query (join with project_dependencies for name/version).
CREATE OR REPLACE FUNCTION get_project_vulnerabilities(p_project_id UUID)
RETURNS TABLE (
  id UUID,
  dependency_id UUID,
  osv_id TEXT,
  severity TEXT,
  summary TEXT,
  details TEXT,
  aliases TEXT[],
  fixed_versions TEXT[],
  published_at TIMESTAMPTZ,
  modified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ,
  dependency_name TEXT,
  dependency_version TEXT
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    dv.id,
    dv.dependency_id,
    dv.osv_id,
    dv.severity,
    dv.summary,
    dv.details,
    dv.aliases,
    dv.fixed_versions,
    dv.published_at,
    dv.modified_at,
    dv.created_at,
    pd.name AS dependency_name,
    pd.version AS dependency_version
  FROM dependency_vulnerabilities dv
  INNER JOIN project_dependencies pd
    ON pd.dependency_id = dv.dependency_id
   AND pd.project_id = p_project_id;
$$;
