DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'project_repositories'
      AND column_name = 'ecosystem'
  ) THEN
    ALTER TABLE project_repositories
      ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'npm';
  END IF;
END $$;
