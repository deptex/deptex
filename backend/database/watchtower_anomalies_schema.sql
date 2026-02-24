-- Package Anomalies Table
-- Stores anomaly detection results for commits
-- Used by the Watchtower worker to flag suspicious commit patterns

CREATE TABLE IF NOT EXISTS package_anomalies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  watched_package_id UUID NOT NULL REFERENCES watched_packages(id) ON DELETE CASCADE,
  commit_sha TEXT NOT NULL,
  contributor_id UUID REFERENCES package_contributors(id) ON DELETE CASCADE,
  
  -- Anomaly scoring
  anomaly_score FLOAT NOT NULL DEFAULT 0, -- Total anomaly score (0+, higher = more suspicious)
  
  -- Detailed breakdown of why it was flagged
  -- Array of {factor: string, points: number, reason: string}
  score_breakdown JSONB DEFAULT '[]',
  
  -- When the anomaly was detected
  detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Ensure no duplicate anomalies per commit per package
  UNIQUE(watched_package_id, commit_sha)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_package_anomalies_watched_package_id 
  ON package_anomalies(watched_package_id);

CREATE INDEX IF NOT EXISTS idx_package_anomalies_anomaly_score 
  ON package_anomalies(anomaly_score DESC);

CREATE INDEX IF NOT EXISTS idx_package_anomalies_detected_at 
  ON package_anomalies(detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_package_anomalies_contributor_id 
  ON package_anomalies(contributor_id);

-- Enable RLS
ALTER TABLE package_anomalies ENABLE ROW LEVEL SECURITY;

-- Allow service role full access
CREATE POLICY "Service role can manage package_anomalies" ON package_anomalies
  FOR ALL
  USING (true)
  WITH CHECK (true);
