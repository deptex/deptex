-- Hardening of the org canvas multiplayer authorization function.
-- Layered on top of org_canvas_realtime_auth.sql; apply AFTER that migration.
--
-- Fixes three issues surfaced by the critical review:
--   1. Cross-org team-channel hijack: a user in orgA (team T) who is also a
--      member of orgB could subscribe/broadcast to
--      'org-canvas:{orgB_id}:team:{orgA_team_T_id}' because the team-scope
--      branch only checked team_members without verifying the team belonged
--      to the parsed org_id. Now joined against public.teams with the
--      cross-check.
--   2. canvas_cursors_enabled kill switch was frontend-only: the RLS function
--      never consulted the flag, so any org member could open a raw
--      supabase.channel subscription and continue broadcasting/reading after
--      the owner disabled cursors. Now enforced at the DB layer.
--   3. FK covering indexes for canvas_position_updated_by were missing, so
--      auth.users deletion did seq scans on teams/projects.

create or replace function public.can_access_org_canvas_topic(
  _topic text,
  _user_id uuid,
  _mode text
)
returns boolean
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  _parts text[];
  _org_id uuid;
  _scope text;
  _scope_id text;
  _is_org_member boolean;
  _is_admin boolean;
  _cursors_enabled boolean;
begin
  if _topic is null or _user_id is null then
    return false;
  end if;

  _parts := string_to_array(_topic, ':');
  if array_length(_parts, 1) < 3 or _parts[1] <> 'org-canvas' then
    return false;
  end if;

  begin
    _org_id := _parts[2]::uuid;
  exception when others then
    return false;
  end;
  _scope := _parts[3];

  -- Must be a member of the org, full stop.
  select exists (
    select 1 from public.organization_members
    where organization_id = _org_id and user_id = _user_id
  ) into _is_org_member;
  if not _is_org_member then
    return false;
  end if;

  -- Org-wide kill switch. When disabled, deny every realtime path for this
  -- org. Default TRUE so rows missing the column still work.
  select coalesce(canvas_cursors_enabled, true)
    into _cursors_enabled
    from public.organizations
    where id = _org_id;
  if not coalesce(_cursors_enabled, true) then
    return false;
  end if;

  -- Admin check: owner role OR manage_teams_and_projects permission.
  select
    (om.role = 'owner')
    or coalesce((roles.permissions->>'manage_teams_and_projects')::boolean, false)
  into _is_admin
  from public.organization_members om
  left join public.organization_roles roles
    on roles.organization_id = om.organization_id and roles.name = om.role
  where om.organization_id = _org_id and om.user_id = _user_id
  limit 1;
  _is_admin := coalesce(_is_admin, false);

  -- Org-wide channel: all org members read; admins write.
  -- Carries org-center drag events only.
  if _scope = 'org' then
    if _mode = 'read'  then return true; end if;
    if _mode = 'write' then return _is_admin; end if;
    return false;
  end if;

  -- Admin-only channel: admin read + admin write. Admin cursor presence.
  if _scope = 'admins' then
    return _is_admin;
  end if;

  -- Team channel: team members (of a team that actually belongs to this org)
  -- or admins. The teams.organization_id join is the cross-org guard.
  if _scope = 'team' and array_length(_parts, 1) >= 4 then
    _scope_id := _parts[4];
    if _is_admin then
      return exists (
        select 1 from public.teams t
        where t.id::text = _scope_id and t.organization_id = _org_id
      );
    end if;
    begin
      return exists (
        select 1
        from public.team_members tm
        join public.teams t on t.id = tm.team_id
        where tm.team_id = _scope_id::uuid
          and tm.user_id = _user_id
          and t.organization_id = _org_id
      );
    exception when others then
      return false;
    end;
  end if;

  return false;
end;
$$;

grant execute on function public.can_access_org_canvas_topic(text, uuid, text) to authenticated;

-- Replace the INSERT policy to add sender-identity attestation. The channel
-- access check was not enough on its own: broadcast payloads carry a
-- client-declared `userId`, which could impersonate any other member. Now any
-- org-canvas message that claims a userId must have that userId match the
-- authenticated caller's auth.uid(). Messages without a userId (e.g. the org
-- canvas-settings broadcast) pass through unchanged.
drop policy if exists "org_canvas_insert" on realtime.messages;

create policy "org_canvas_insert"
on realtime.messages
for insert
to authenticated
with check (
  realtime.topic() like 'org-canvas:%'
  and public.can_access_org_canvas_topic(realtime.topic(), (select auth.uid()), 'write')
  and (
    -- Look for userId in the two shapes Supabase Realtime can produce
    -- (bare broadcast payload vs. nested {type, event, payload} envelope).
    -- If neither carries a userId, the message is identity-neutral (e.g.
    -- canvas-settings) and passes.
    coalesce(
      payload->>'userId',
      payload->'payload'->>'userId',
      (select auth.uid())::text
    ) = (select auth.uid())::text
  )
);

-- Covering indexes on the FK from canvas_position_updated_by so that
-- auth.users deletion (ON DELETE SET NULL) doesn't seq-scan teams/projects.
create index if not exists idx_teams_canvas_position_updated_by
  on public.teams(canvas_position_updated_by)
  where canvas_position_updated_by is not null;

create index if not exists idx_projects_canvas_position_updated_by
  on public.projects(canvas_position_updated_by)
  where canvas_position_updated_by is not null;

-- Bulk canvas position update in a single transaction.
-- Replaces the N+1 serial for-loop in the backend batch PATCH route.
-- Teams and projects are each updated with a single UPDATE FROM jsonb_array.
-- The caller has already verified org-level manage permission. Any id that
-- does not belong to _org_id raises an exception so the whole transaction
-- rolls back (no partial writes). Returns the updated rows.
create or replace function public.update_canvas_positions_batch(
  _org_id uuid,
  _user_id uuid,
  _teams jsonb,
  _projects jsonb
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  _now timestamptz := now();
  _expected_teams int := coalesce(jsonb_array_length(_teams), 0);
  _expected_projects int := coalesce(jsonb_array_length(_projects), 0);
  _updated_teams jsonb := '[]'::jsonb;
  _updated_projects jsonb := '[]'::jsonb;
  _team_count int := 0;
  _project_count int := 0;
begin
  if _expected_teams > 0 then
    with
      team_input as (
        select
          (elem->>'id')::uuid as id,
          (elem->>'x')::numeric as x,
          (elem->>'y')::numeric as y
        from jsonb_array_elements(_teams) elem
      ),
      team_updates as (
        update public.teams t
        set
          canvas_position_x = ti.x,
          canvas_position_y = ti.y,
          canvas_position_updated_at = _now,
          canvas_position_updated_by = _user_id
        from team_input ti
        where t.id = ti.id and t.organization_id = _org_id
        returning
          t.id,
          t.canvas_position_x,
          t.canvas_position_y,
          t.canvas_position_updated_at
      )
    select
      coalesce(jsonb_agg(to_jsonb(tu.*)), '[]'::jsonb),
      count(*)
    into _updated_teams, _team_count
    from team_updates tu;

    if _team_count <> _expected_teams then
      raise exception using
        errcode = 'P0001',
        message = 'one or more teams not found in this organization';
    end if;
  end if;

  if _expected_projects > 0 then
    with
      project_input as (
        select
          (elem->>'id')::uuid as id,
          (elem->>'x')::numeric as x,
          (elem->>'y')::numeric as y
        from jsonb_array_elements(_projects) elem
      ),
      project_updates as (
        update public.projects p
        set
          canvas_position_x = pi.x,
          canvas_position_y = pi.y,
          canvas_position_updated_at = _now,
          canvas_position_updated_by = _user_id
        from project_input pi
        where p.id = pi.id and p.organization_id = _org_id
        returning
          p.id,
          p.canvas_position_x,
          p.canvas_position_y,
          p.canvas_position_updated_at
      )
    select
      coalesce(jsonb_agg(to_jsonb(pu.*)), '[]'::jsonb),
      count(*)
    into _updated_projects, _project_count
    from project_updates pu;

    if _project_count <> _expected_projects then
      raise exception using
        errcode = 'P0001',
        message = 'one or more projects not found in this organization';
    end if;
  end if;

  return jsonb_build_object('teams', _updated_teams, 'projects', _updated_projects);
end;
$$;

grant execute on function public.update_canvas_positions_batch(uuid, uuid, jsonb, jsonb) to authenticated;
