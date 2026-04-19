-- Phase 17: Incident Response Orchestration
-- Run after: Phase 7B (Aegis tables), Phase 14 (security_audit_logs), Phase 15 (SLA tables)
-- Creates: incident_playbooks, security_incidents, incident_timeline, incident_notes
-- Alters: organizations (allow_autonomous_containment)

-- ─── incident_playbooks ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS incident_playbooks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN (
    'zero_day', 'supply_chain', 'secret_exposure', 'compliance_breach', 'custom'
  )),
  trigger_criteria JSONB,
  phases JSONB NOT NULL,
  auto_execute BOOLEAN DEFAULT false,
  notification_channels JSONB,
  is_template BOOLEAN DEFAULT false,
  enabled BOOLEAN DEFAULT true,
  version INTEGER DEFAULT 1,
  usage_count INTEGER DEFAULT 0,
  last_used_at TIMESTAMPTZ,
  created_by UUID,
  updated_by UUID,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_org ON incident_playbooks(organization_id);
CREATE INDEX IF NOT EXISTS idx_ip_org_trigger ON incident_playbooks(organization_id, trigger_type)
  WHERE enabled = true;

-- ─── security_incidents ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS security_incidents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  playbook_id UUID REFERENCES incident_playbooks(id) ON DELETE SET NULL,
  task_id UUID REFERENCES aegis_tasks(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN (
    'active', 'contained', 'assessing', 'communicating',
    'remediating', 'verifying', 'resolved', 'closed', 'aborted'
  )),
  current_phase TEXT NOT NULL DEFAULT 'contain' CHECK (current_phase IN (
    'contain', 'assess', 'communicate', 'remediate', 'verify', 'report'
  )),
  trigger_source TEXT,
  trigger_data JSONB,
  dedup_key TEXT,

  declared_by UUID,
  assigned_to UUID,
  escalation_level INTEGER DEFAULT 0,

  affected_projects UUID[],
  affected_packages TEXT[],
  affected_cves TEXT[],

  time_to_contain_ms BIGINT,
  time_to_remediate_ms BIGINT,
  total_duration_ms BIGINT,
  fixes_created INTEGER DEFAULT 0,
  prs_merged INTEGER DEFAULT 0,

  autonomous_actions_taken JSONB DEFAULT '[]',
  is_false_positive BOOLEAN DEFAULT false,

  post_mortem TEXT,

  declared_at TIMESTAMPTZ DEFAULT NOW(),
  contained_at TIMESTAMPTZ,
  remediated_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_si_dedup ON security_incidents(organization_id, dedup_key)
  WHERE dedup_key IS NOT NULL AND status NOT IN ('resolved', 'closed', 'aborted');
CREATE INDEX IF NOT EXISTS idx_si_org_status ON security_incidents(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_si_org_created ON security_incidents(organization_id, created_at DESC);

-- ─── incident_timeline ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS incident_timeline (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id UUID NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
  phase TEXT NOT NULL,
  event_type TEXT NOT NULL,
  description TEXT NOT NULL,
  actor TEXT,
  metadata JSONB,
  duration_ms INTEGER,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_it_incident ON incident_timeline(incident_id, created_at);

-- ─── incident_notes ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS incident_notes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id UUID NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
  author_id UUID NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_in_incident ON incident_notes(incident_id, created_at);

-- ─── Organization column ─────────────────────────────────────────────────────

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS allow_autonomous_containment BOOLEAN DEFAULT false;

-- ─── RLS Policies ────────────────────────────────────────────────────────────

ALTER TABLE incident_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_notes ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Service role full access on incident_playbooks') THEN
    CREATE POLICY "Service role full access on incident_playbooks" ON incident_playbooks FOR ALL
      USING (auth.role() = 'service_role');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Service role full access on security_incidents') THEN
    CREATE POLICY "Service role full access on security_incidents" ON security_incidents FOR ALL
      USING (auth.role() = 'service_role');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Service role full access on incident_timeline') THEN
    CREATE POLICY "Service role full access on incident_timeline" ON incident_timeline FOR ALL
      USING (auth.role() = 'service_role');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Service role full access on incident_notes') THEN
    CREATE POLICY "Service role full access on incident_notes" ON incident_notes FOR ALL
      USING (auth.role() = 'service_role');
  END IF;
END $$;
