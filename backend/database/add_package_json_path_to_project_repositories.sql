-- Add package_json_path: directory containing package.json; '' = repo root.
-- Enables monorepo: one project can link to repo root, another to e.g. apps/web.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'project_repositories' AND column_name = 'package_json_path'
  ) THEN
    ALTER TABLE project_repositories ADD COLUMN package_json_path TEXT NOT NULL DEFAULT '';
  END IF;
END $$;

-- Unique: a given (repo + path) can be linked by only one project
CREATE UNIQUE INDEX IF NOT EXISTS idx_project_repositories_repo_full_name_package_json_path
  ON project_repositories(repo_full_name, package_json_path);
