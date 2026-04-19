-- Migrate watchtower_prs (name) to dependency_prs (dependency_id).
-- Run after dependency_prs_schema.sql. Safe to run if watchtower_prs is already gone.

-- 1. Create dependency_prs if not exists (schema may have been applied for new installs)
CREATE TABLE IF NOT EXISTS dependency_prs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('bump', 'decrease', 'remove')),
  target_version TEXT NOT NULL,
  pr_url TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  branch_name TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_id, dependency_id, type, target_version)
);

CREATE INDEX IF NOT EXISTS idx_dependency_prs_project_dependency_type
  ON dependency_prs(project_id, dependency_id, type);

COMMENT ON TABLE dependency_prs IS 'PRs created by Watchtower bump/decrease/remove; one row per (project, dependency_id, type, target_version). Name comes from dependencies.name.';

-- 2. Migrate data from watchtower_prs (only if watchtower_prs exists and has rows)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'watchtower_prs') THEN
    -- Backfill: insert into dependency_prs where we can resolve name -> dependencies.id
    INSERT INTO dependency_prs (project_id, dependency_id, type, target_version, pr_url, pr_number, branch_name, created_at)
    SELECT wp.project_id, d.id, wp.type, wp.target_version, wp.pr_url, wp.pr_number, wp.branch_name, wp.created_at
    FROM watchtower_prs wp
    INNER JOIN dependencies d ON d.name = wp.name
    ON CONFLICT (project_id, dependency_id, type, target_version) DO NOTHING;

    -- De-duplicate: keep one row per (project_id, dependency_id, type, target_version), delete duplicates by keeping min(id)
    DELETE FROM dependency_prs a
    USING dependency_prs b
    WHERE a.id > b.id
      AND a.project_id = b.project_id
      AND a.dependency_id = b.dependency_id
      AND a.type = b.type
      AND a.target_version = b.target_version;

    DROP TABLE watchtower_prs;
  END IF;
END $$;
