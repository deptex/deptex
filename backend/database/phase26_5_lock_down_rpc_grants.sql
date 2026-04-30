-- Lock down the two taint-engine RPCs from cross-tenant exposure.
--
-- get_taint_engine_monthly_spend(uuid) and get_taint_engine_recent_runs(int)
-- shipped in phase26_3 and phase26_4 with EXECUTE granted to the
-- authenticated role. The ai_usage_logs and taint_engine_runs tables they
-- read have no RLS (service-role-mediated), so the GRANT let any signed-in
-- tenant call the RPCs via PostgREST and read every other org's AI spend
-- totals + fleet-wide run telemetry. Both RPCs are only ever called from
-- the worker (cost-cap.ts and taint-engine-retirement-gates.ts) and never
-- needed authenticated GRANT in the first place.

REVOKE EXECUTE ON FUNCTION public.get_taint_engine_monthly_spend(uuid) FROM authenticated;
REVOKE EXECUTE ON FUNCTION public.get_taint_engine_recent_runs(integer) FROM authenticated;

-- Re-affirm the service_role grant in case a fresh-install only saw the
-- corrected phase26_3 / phase26_4 (idempotent — no-op if already present).
GRANT EXECUTE ON FUNCTION public.get_taint_engine_monthly_spend(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.get_taint_engine_recent_runs(integer) TO service_role;
