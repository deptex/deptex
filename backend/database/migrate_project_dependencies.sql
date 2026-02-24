-- Migration script to convert project_dependencies to a junction table
-- This adds a dependency_id column that references the new dependencies table

-- Step 1: Add dependency_id column
ALTER TABLE project_dependencies 
ADD COLUMN IF NOT EXISTS dependency_id UUID REFERENCES dependencies(id);

-- Step 2: Create index on the new column
CREATE INDEX IF NOT EXISTS idx_project_dependencies_dependency_id 
  ON project_dependencies(dependency_id);

-- Note: After running the new import flow, the dependency_id column will be populated.
-- The old columns (name, version, license) are kept for backward compatibility during migration.
-- Once all projects have been re-imported, you can optionally drop the redundant columns:
-- ALTER TABLE project_dependencies DROP COLUMN name;
-- ALTER TABLE project_dependencies DROP COLUMN version;
-- ALTER TABLE project_dependencies DROP COLUMN license;
