-- Package Commit Touched Functions
-- Stores which exported function names each commit touched (from diff + AST analysis)
-- Used to show "Touches my imports" in Watchtower and "Functions worked on" in commit sidebar

CREATE TABLE IF NOT EXISTS package_commit_touched_functions (
  watched_package_id UUID NOT NULL REFERENCES watched_packages(id) ON DELETE CASCADE,
  commit_sha TEXT NOT NULL,
  function_name TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(watched_package_id, commit_sha, function_name)
);

CREATE INDEX IF NOT EXISTS idx_package_commit_touched_functions_lookup
  ON package_commit_touched_functions(watched_package_id, commit_sha);

ALTER TABLE package_commit_touched_functions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role can manage package_commit_touched_functions" ON package_commit_touched_functions
  FOR ALL
  USING (true)
  WITH CHECK (true);
