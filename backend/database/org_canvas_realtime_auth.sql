-- Realtime Authorization for the org canvas multiplayer channels.
--
-- Channel topology:
--   org-canvas:{orgId}:org           — SELECT: any org member.
--                                       INSERT: admins only.
--                                       Carries org-center drag events.
--   org-canvas:{orgId}:admins        — SELECT/INSERT: admins only.
--                                       Carries admin cursor presence so
--                                       admins see each other.
--   org-canvas:{orgId}:team:{teamId} — SELECT/INSERT: team members OR admins.
--                                       Carries team/project drag events and
--                                       team-scoped cursors.
--
-- Writes pass through Supabase Realtime Broadcast; both subscription
-- acknowledgement and each published message are validated by the RLS
-- policies on realtime.messages below via `realtime.topic()`.
--
-- Supabase Realtime "subscribe" always checks SELECT, so every channel a
-- client writes to must also be one it can read. That's why there is no
-- dedicated "admins" channel: admins broadcast their cursor to :org (read
-- by everyone) and drags to the target team channel.

create or replace function public.can_access_org_canvas_topic(
  _topic text,
  _user_id uuid,
  _mode text
)
returns boolean
language plpgsql
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

  if _scope = 'team' and array_length(_parts, 1) >= 4 then
    _scope_id := _parts[4];
    if _is_admin then
      return true;
    end if;
    begin
      return exists (
        select 1 from public.team_members
        where team_id = _scope_id::uuid and user_id = _user_id
      );
    exception when others then
      return false;
    end;
  end if;

  return false;
end;
$$;

grant execute on function public.can_access_org_canvas_topic(text, uuid, text) to authenticated;

-- RLS on realtime.messages for the org-canvas topic namespace.
-- Uses `realtime.topic()` — returns the topic of the current realtime request.
alter table realtime.messages enable row level security;

drop policy if exists "org_canvas_select" on realtime.messages;
drop policy if exists "org_canvas_insert" on realtime.messages;

create policy "org_canvas_select"
on realtime.messages
for select
to authenticated
using (
  realtime.topic() like 'org-canvas:%'
  and public.can_access_org_canvas_topic(realtime.topic(), (select auth.uid()), 'read')
);

create policy "org_canvas_insert"
on realtime.messages
for insert
to authenticated
with check (
  realtime.topic() like 'org-canvas:%'
  and public.can_access_org_canvas_topic(realtime.topic(), (select auth.uid()), 'write')
);
