-- Add polling fields to watched_packages table
-- Used by the watchtower-poller to track the last known commit and polling schedule

-- Add last_known_commit_sha to track the most recent commit we've analyzed
ALTER TABLE watched_packages 
ADD COLUMN IF NOT EXISTS last_known_commit_sha TEXT;

-- Add last_polled_at to track when we last checked for new commits
ALTER TABLE watched_packages 
ADD COLUMN IF NOT EXISTS last_polled_at TIMESTAMP WITH TIME ZONE;

-- Add github_url to cache the parsed GitHub URL (avoids re-parsing repository field)
ALTER TABLE watched_packages 
ADD COLUMN IF NOT EXISTS github_url TEXT;

-- Index for efficient polling queries
CREATE INDEX IF NOT EXISTS idx_watched_packages_last_polled_at 
  ON watched_packages(last_polled_at)
  WHERE status = 'ready';

-- Comment explaining the fields
COMMENT ON COLUMN watched_packages.last_known_commit_sha IS 'The SHA of the most recent commit we have analyzed. Used by poller to detect new commits.';
COMMENT ON COLUMN watched_packages.last_polled_at IS 'When we last checked this package for new commits.';
COMMENT ON COLUMN watched_packages.github_url IS 'Cached GitHub clone URL parsed from the repository field.';
