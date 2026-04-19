-- Drop the old project-scoped dependency_relationships table
-- This table linked project_dependencies rows and was rebuilt on every extraction.
-- Replaced by dependency_version_edges which links dependency_versions globally.

DROP TABLE IF EXISTS dependency_relationships CASCADE;
