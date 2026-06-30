-- phase66_usage_breakdown_rpc.sql
-- Server-side aggregation for the Usage-tab breakdown.
--
-- The previous path fetched EVERY usage_deduction row in the range and summed in JS:
-- O(transactions) over the wire + a silent-truncation risk at PostgREST's row cap
-- (one org already has 1k+ rows; an active org generates thousands/month). This RPC
-- groups in SQL and returns one row per (bucket, feature, event_type) —
-- O(buckets × features), bounded and correct at any volume.
--
-- Buckets are UTC-aligned to match the client's bucketing: date_trunc('week') returns
-- the ISO Monday, which matches the frontend's Monday-start weeks; 'day'/'month' are
-- the UTC day / first-of-month. Returned as a `date`, which PostgREST serializes as
-- 'YYYY-MM-DD' — identical to the client's bucket keys.

create or replace function get_usage_breakdown(
  p_organization_id uuid,
  p_start timestamptz,
  p_end timestamptz,
  p_granularity text default 'day',
  p_features text[] default null,
  p_project_ids uuid[] default null
)
returns table (
  bucket date,
  feature text,
  event_type text,
  cents bigint,
  quantity numeric
)
language sql
stable
as $$
  select
    (case lower(p_granularity)
       when 'month' then date_trunc('month', bt.created_at at time zone 'UTC')
       when 'week'  then date_trunc('week',  bt.created_at at time zone 'UTC')
       else              date_trunc('day',   bt.created_at at time zone 'UTC')
     end)::date as bucket,
    bt.feature,
    bt.event_type,
    sum(abs(bt.amount_cents))::bigint as cents,
    sum(coalesce(bt.quantity, 0))::numeric as quantity
  from billing_transactions bt
  where bt.organization_id = p_organization_id
    and bt.kind = 'usage_deduction'
    and bt.created_at >= p_start
    and bt.created_at <= p_end
    and (p_features is null or bt.feature = any (p_features))
    and (p_project_ids is null or bt.project_id = any (p_project_ids))
  group by 1, bt.feature, bt.event_type;
$$;

-- Backend-only: the function takes an arbitrary org_id and bypasses RLS, so it must NOT
-- be reachable from the public PostgREST API (anon/authenticated) — that would let any
-- signed-in user read another org's billing aggregates. Only the service role calls it.
revoke all on function get_usage_breakdown(uuid, timestamptz, timestamptz, text, text[], uuid[]) from public;
revoke all on function get_usage_breakdown(uuid, timestamptz, timestamptz, text, text[], uuid[]) from anon;
revoke all on function get_usage_breakdown(uuid, timestamptz, timestamptz, text, text[], uuid[]) from authenticated;
grant execute on function get_usage_breakdown(uuid, timestamptz, timestamptz, text, text[], uuid[]) to service_role;
