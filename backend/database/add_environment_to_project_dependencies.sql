-- Add environment column to project_dependencies (prod | dev for direct deps; NULL for transitive)
ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS environment TEXT;

COMMENT ON COLUMN project_dependencies.environment IS 'prod for dependencies, dev for devDependencies, NULL for transitive';
