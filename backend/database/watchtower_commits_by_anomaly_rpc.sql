-- RPC: return a page of package_commits ordered by anomaly score (desc), then timestamp (desc).
-- Used for "Sort by Anomaly Score" with pagination (e.g. top 100, then next 100 on scroll).
-- Same filters as the main commits list: since watchtower_cleared_at, exclude cleared shas.

CREATE OR REPLACE FUNCTION get_watchtower_commits_by_anomaly(
  p_watched_package_id UUID,
  p_since_created_at TIMESTAMPTZ,
  p_cleared_shas TEXT[],
  p_limit INT,
  p_offset INT
)
RETURNS SETOF package_commits
LANGUAGE sql
STABLE
AS $$
  SELECT c.*
  FROM package_commits c
  LEFT JOIN package_anomalies a ON a.commit_sha = c.sha AND a.watched_package_id = c.watched_package_id
  WHERE c.watched_package_id = p_watched_package_id
  AND (p_since_created_at IS NULL OR c.created_at >= p_since_created_at)
  AND (p_cleared_shas IS NULL OR cardinality(p_cleared_shas) = 0 OR c.sha != ALL(p_cleared_shas))
  ORDER BY a.anomaly_score DESC NULLS LAST, c.timestamp DESC
  LIMIT p_limit OFFSET p_offset;
$$;
