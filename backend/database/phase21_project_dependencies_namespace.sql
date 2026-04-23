-- Adds a namespace column to project_dependencies.
--
-- For ecosystems whose package identity is split between a namespace/group
-- and an artifact name (Maven groupId/artifactId, NuGet's nested namespaces,
-- etc.), the namespace is needed at reachability-analysis time to resolve
-- an import path back to an artifact. A Java import of
-- `org.apache.logging.log4j.Logger` belongs to artifact `log4j-core` in
-- groupId `org.apache.logging.log4j` — without the groupId, the import can't
-- be tied to the artifact.
--
-- NULL for ecosystems that don't split (npm, pypi, go, cargo, rubygems).
-- Populated by sbom.ts at extraction time from the Maven purl.

ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS namespace TEXT;

-- CONCURRENTLY so this migration doesn't lock writes on a hot table.
-- Note: CONCURRENTLY cannot run inside a transaction — if your runner wraps
-- each file in BEGIN/COMMIT, strip the transaction for this statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pd_namespace
  ON project_dependencies(namespace)
  WHERE namespace IS NOT NULL;
