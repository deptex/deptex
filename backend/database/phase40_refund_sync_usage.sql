-- Refund a sync slot to a plan after a terminal failure (cancel, fly
-- never started, recovery reap). Mirror of increment_sync_usage so a
-- counter that was debited speculatively at queue time can be
-- credited back when we're certain no extraction actually ran.
--
-- Clamps at 0 so a duplicate refund (e.g. cancel followed by reaper)
-- never goes negative.

CREATE OR REPLACE FUNCTION refund_sync_usage(p_org_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_new_count INTEGER;
BEGIN
  UPDATE organization_plans
    SET syncs_used = GREATEST(0, syncs_used - 1)
    WHERE organization_id = p_org_id
    RETURNING syncs_used INTO v_new_count;
  RETURN COALESCE(v_new_count, 0);
END;
$$ LANGUAGE plpgsql;
