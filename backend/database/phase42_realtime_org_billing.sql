-- phase42: stream organization_billing UPDATEs through Supabase Realtime
--
-- The Plan/Billing UI subscribes to balance/auto-recharge state changes for
-- the current org so the balance card updates without a page refresh
-- (auto-recharge fires server-side, low-balance state flips, etc).
-- Without this, postgres_changes events never reach the client.

ALTER PUBLICATION supabase_realtime ADD TABLE organization_billing;
