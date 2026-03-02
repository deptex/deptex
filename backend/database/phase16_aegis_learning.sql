-- Phase 16: Aegis Outcome-Based Learning
-- Run after all Phase 7B migrations. Independent of Phase 15.
-- Prerequisites: phase7_ai_fix.sql (project_security_fixes), phase7b_aegis_platform.sql (aegis_memory)

-- 16-Pre-B: CWE column for GHSA vulnerability data
ALTER TABLE dependency_vulnerabilities ADD COLUMN IF NOT EXISTS cwe_ids TEXT[] DEFAULT '{}';

-- 16-Pre-D: match_aegis_memories RPC (missing from Phase 7B migrations)
CREATE OR REPLACE FUNCTION match_aegis_memories(
  query_embedding vector(768),
  match_threshold float,
  match_count int,
  filter_org_id uuid,
  filter_category text DEFAULT NULL
) RETURNS TABLE (id uuid, category text, key text, content text, similarity float)
LANGUAGE sql STABLE AS $$
  SELECT id, category, key, content,
         1 - (embedding <=> query_embedding) AS similarity
  FROM aegis_memory
  WHERE organization_id = filter_org_id
    AND (filter_category IS NULL OR category = filter_category)
    AND (expires_at IS NULL OR expires_at > NOW())
    AND 1 - (embedding <=> query_embedding) > match_threshold
  ORDER BY embedding <=> query_embedding
  LIMIT match_count;
$$;

-- 16A: fix_outcomes table
CREATE TABLE IF NOT EXISTS fix_outcomes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  fix_job_id UUID NOT NULL REFERENCES project_security_fixes(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,

  fix_type TEXT NOT NULL,
  strategy TEXT NOT NULL,

  ecosystem TEXT NOT NULL,
  framework TEXT,
  vulnerability_type TEXT,
  cwe_id TEXT,
  severity TEXT,
  package_name TEXT,
  is_direct_dep BOOLEAN,
  has_reachability_data BOOLEAN,
  reachability_level TEXT,
  provider TEXT DEFAULT 'github',

  success BOOLEAN NOT NULL,
  failure_reason TEXT,
  failure_detail TEXT,

  duration_seconds INTEGER,
  tokens_used INTEGER,
  estimated_cost NUMERIC(10, 4),
  files_changed INTEGER,
  lines_added INTEGER,
  lines_removed INTEGER,

  pr_merged BOOLEAN,
  pr_merged_at TIMESTAMPTZ,
  human_quality_rating INTEGER CHECK (human_quality_rating BETWEEN 1 AND 5),
  introduced_new_vulns BOOLEAN DEFAULT false,
  fix_reverted BOOLEAN DEFAULT false,
  feedback_prompted_at TIMESTAMPTZ,

  previous_attempt_id UUID REFERENCES fix_outcomes(id),
  led_to_strategy TEXT,

  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fo_org_ecosystem ON fix_outcomes(organization_id, ecosystem);
CREATE INDEX IF NOT EXISTS idx_fo_org_strategy ON fix_outcomes(organization_id, strategy);
CREATE INDEX IF NOT EXISTS idx_fo_org_vuln_type ON fix_outcomes(organization_id, vulnerability_type);
CREATE INDEX IF NOT EXISTS idx_fo_org_success ON fix_outcomes(organization_id, success);
CREATE INDEX IF NOT EXISTS idx_fo_created ON fix_outcomes(created_at);
CREATE INDEX IF NOT EXISTS idx_fo_fix_job ON fix_outcomes(fix_job_id);
CREATE INDEX IF NOT EXISTS idx_fo_feedback ON fix_outcomes(organization_id, pr_merged, human_quality_rating, feedback_prompted_at)
  WHERE pr_merged = true AND human_quality_rating IS NULL AND feedback_prompted_at IS NULL;

-- 16A: strategy_patterns table
CREATE TABLE IF NOT EXISTS strategy_patterns (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  ecosystem TEXT,
  vulnerability_type TEXT,
  strategy TEXT NOT NULL,
  is_direct_dep BOOLEAN,
  framework TEXT,

  total_attempts INTEGER NOT NULL DEFAULT 0,
  successes INTEGER NOT NULL DEFAULT 0,
  success_rate NUMERIC(5, 4) NOT NULL DEFAULT 0,
  avg_duration_seconds INTEGER,
  avg_cost NUMERIC(10, 4),
  avg_quality_rating NUMERIC(3, 2),
  pr_merge_rate NUMERIC(5, 4),
  revert_rate NUMERIC(5, 4),

  confidence TEXT NOT NULL DEFAULT 'low',
  sample_count INTEGER NOT NULL DEFAULT 0,

  common_failure_reasons JSONB,
  best_followup_strategy TEXT,
  followup_success_rate NUMERIC(5, 4),

  last_computed_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, ecosystem, vulnerability_type, strategy, is_direct_dep, framework)
);

CREATE INDEX IF NOT EXISTS idx_sp_org_lookup ON strategy_patterns(organization_id, ecosystem, vulnerability_type);
CREATE INDEX IF NOT EXISTS idx_sp_org_strategy ON strategy_patterns(organization_id, strategy);

-- RLS
ALTER TABLE fix_outcomes ENABLE ROW LEVEL SECURITY;
ALTER TABLE strategy_patterns ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Service role full access on fix_outcomes') THEN
    CREATE POLICY "Service role full access on fix_outcomes" ON fix_outcomes FOR ALL
      USING (auth.role() = 'service_role');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Service role full access on strategy_patterns') THEN
    CREATE POLICY "Service role full access on strategy_patterns" ON strategy_patterns FOR ALL
      USING (auth.role() = 'service_role');
  END IF;
END $$;

-- compute_strategy_patterns RPC
CREATE OR REPLACE FUNCTION compute_strategy_patterns(p_org_id UUID)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM strategy_patterns WHERE organization_id = p_org_id;

  -- Level 1: Most specific (ecosystem + vulnerability_type + strategy + is_direct_dep)
  INSERT INTO strategy_patterns (
    organization_id, ecosystem, vulnerability_type, strategy, is_direct_dep,
    total_attempts, successes, success_rate, avg_duration_seconds, avg_cost,
    avg_quality_rating, pr_merge_rate, revert_rate, confidence, sample_count,
    common_failure_reasons, last_computed_at
  )
  SELECT
    p_org_id, ecosystem, vulnerability_type, strategy, is_direct_dep,
    COUNT(*),
    COUNT(*) FILTER (WHERE success),
    ROUND(COUNT(*) FILTER (WHERE success)::numeric / NULLIF(COUNT(*), 0), 4),
    AVG(duration_seconds)::integer,
    AVG(estimated_cost),
    AVG(human_quality_rating),
    ROUND(COUNT(*) FILTER (WHERE pr_merged)::numeric / NULLIF(COUNT(*) FILTER (WHERE success), 0), 4),
    ROUND(COUNT(*) FILTER (WHERE fix_reverted)::numeric / NULLIF(COUNT(*) FILTER (WHERE pr_merged), 0), 4),
    CASE
      WHEN COUNT(*) >= 20 THEN 'high'
      WHEN COUNT(*) >= 5 THEN 'medium'
      ELSE 'low'
    END,
    COUNT(*),
    (SELECT jsonb_object_agg(fr, cnt) FROM (
      SELECT failure_reason AS fr, COUNT(*) AS cnt
      FROM fix_outcomes fo2
      WHERE fo2.organization_id = p_org_id
        AND fo2.ecosystem = fix_outcomes.ecosystem
        AND fo2.vulnerability_type IS NOT DISTINCT FROM fix_outcomes.vulnerability_type
        AND fo2.strategy = fix_outcomes.strategy
        AND fo2.is_direct_dep IS NOT DISTINCT FROM fix_outcomes.is_direct_dep
        AND fo2.failure_reason IS NOT NULL
      GROUP BY failure_reason
    ) sub),
    NOW()
  FROM fix_outcomes
  WHERE organization_id = p_org_id
    AND ecosystem IS NOT NULL
  GROUP BY ecosystem, vulnerability_type, strategy, is_direct_dep;

  -- Level 2: Medium (ecosystem + strategy only)
  INSERT INTO strategy_patterns (
    organization_id, ecosystem, vulnerability_type, strategy, is_direct_dep,
    total_attempts, successes, success_rate, avg_duration_seconds, avg_cost,
    avg_quality_rating, pr_merge_rate, revert_rate, confidence, sample_count,
    last_computed_at
  )
  SELECT
    p_org_id, ecosystem, NULL, strategy, NULL,
    COUNT(*),
    COUNT(*) FILTER (WHERE success),
    ROUND(COUNT(*) FILTER (WHERE success)::numeric / NULLIF(COUNT(*), 0), 4),
    AVG(duration_seconds)::integer,
    AVG(estimated_cost),
    AVG(human_quality_rating),
    ROUND(COUNT(*) FILTER (WHERE pr_merged)::numeric / NULLIF(COUNT(*) FILTER (WHERE success), 0), 4),
    ROUND(COUNT(*) FILTER (WHERE fix_reverted)::numeric / NULLIF(COUNT(*) FILTER (WHERE pr_merged), 0), 4),
    CASE WHEN COUNT(*) >= 20 THEN 'high' WHEN COUNT(*) >= 5 THEN 'medium' ELSE 'low' END,
    COUNT(*),
    NOW()
  FROM fix_outcomes
  WHERE organization_id = p_org_id AND ecosystem IS NOT NULL
  GROUP BY ecosystem, strategy
  ON CONFLICT (organization_id, ecosystem, vulnerability_type, strategy, is_direct_dep, framework)
  DO NOTHING;

  -- Level 3: Broad (strategy only, org-wide)
  INSERT INTO strategy_patterns (
    organization_id, ecosystem, vulnerability_type, strategy, is_direct_dep,
    total_attempts, successes, success_rate, avg_duration_seconds, avg_cost,
    avg_quality_rating, pr_merge_rate, revert_rate, confidence, sample_count,
    last_computed_at
  )
  SELECT
    p_org_id, NULL, NULL, strategy, NULL,
    COUNT(*),
    COUNT(*) FILTER (WHERE success),
    ROUND(COUNT(*) FILTER (WHERE success)::numeric / NULLIF(COUNT(*), 0), 4),
    AVG(duration_seconds)::integer,
    AVG(estimated_cost),
    AVG(human_quality_rating),
    ROUND(COUNT(*) FILTER (WHERE pr_merged)::numeric / NULLIF(COUNT(*) FILTER (WHERE success), 0), 4),
    ROUND(COUNT(*) FILTER (WHERE fix_reverted)::numeric / NULLIF(COUNT(*) FILTER (WHERE pr_merged), 0), 4),
    CASE WHEN COUNT(*) >= 20 THEN 'high' WHEN COUNT(*) >= 5 THEN 'medium' ELSE 'low' END,
    COUNT(*),
    NOW()
  FROM fix_outcomes
  WHERE organization_id = p_org_id
  GROUP BY strategy
  ON CONFLICT (organization_id, ecosystem, vulnerability_type, strategy, is_direct_dep, framework)
  DO NOTHING;

  -- Compute follow-up strategies from retry chains
  UPDATE strategy_patterns sp SET
    best_followup_strategy = sub.next_strategy,
    followup_success_rate = sub.followup_rate
  FROM (
    SELECT
      fo_failed.organization_id,
      fo_failed.ecosystem,
      fo_failed.vulnerability_type,
      fo_failed.strategy,
      fo_failed.is_direct_dep,
      fo_retry.strategy AS next_strategy,
      ROUND(COUNT(*) FILTER (WHERE fo_retry.success)::numeric / NULLIF(COUNT(*), 0), 4) AS followup_rate
    FROM fix_outcomes fo_failed
    JOIN fix_outcomes fo_retry ON fo_retry.previous_attempt_id = fo_failed.id
    WHERE fo_failed.organization_id = p_org_id AND NOT fo_failed.success
    GROUP BY fo_failed.organization_id, fo_failed.ecosystem, fo_failed.vulnerability_type,
             fo_failed.strategy, fo_failed.is_direct_dep, fo_retry.strategy
    ORDER BY followup_rate DESC
  ) sub
  WHERE sp.organization_id = sub.organization_id
    AND sp.ecosystem IS NOT DISTINCT FROM sub.ecosystem
    AND sp.vulnerability_type IS NOT DISTINCT FROM sub.vulnerability_type
    AND sp.strategy = sub.strategy
    AND sp.is_direct_dep IS NOT DISTINCT FROM sub.is_direct_dep;
END;
$$;
