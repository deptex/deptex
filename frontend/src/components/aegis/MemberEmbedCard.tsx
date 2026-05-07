import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, type OrganizationMember } from '../../lib/api';
import { cn } from '../../lib/utils';
import { RoleBadge } from '../RoleBadge';

interface MemberEmbedCardProps {
  organizationId: string;
  userId: string;
}

export function MemberEmbedCard({ organizationId, userId }: MemberEmbedCardProps) {
  const settingsTo = useMemo(
    () => `/organizations/${organizationId}/settings/members`,
    [organizationId],
  );

  const [member, setMember] = useState<OrganizationMember | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setMember(null);
    setError(null);
    api
      .getOrganizationMembersCached(organizationId)
      .then((rows) => {
        if (cancelled) return;
        const found = rows.find((r) => r.user_id === userId) ?? null;
        if (found) setMember(found);
        else setError('This member could not be found.');
      })
      .catch(() => {
        if (!cancelled) setError('Could not load this member.');
      });
    return () => {
      cancelled = true;
    };
  }, [organizationId, userId]);

  const linkClassName = cn(
    'my-2 block rounded-lg border border-border bg-background-card text-left transition-colors',
    'hover:bg-table-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
  );

  if (error) {
    return (
      <Link to={settingsTo} className={cn(linkClassName, 'px-3 py-2 text-xs text-foreground-muted')}>
        {error}
      </Link>
    );
  }

  if (!member) {
    return (
      <Link to={settingsTo} className={cn(linkClassName, 'px-4 py-3')}>
        <div className="animate-pulse flex items-center gap-3">
          <div className="h-10 w-10 shrink-0 rounded-full bg-muted" />
          <div className="flex-1 min-w-0 space-y-1.5">
            <div className="h-3.5 w-32 rounded bg-muted" />
            <div className="h-3 w-48 rounded bg-muted" />
          </div>
          <div className="h-5 w-16 shrink-0 rounded bg-muted" />
        </div>
      </Link>
    );
  }

  return (
    <Link to={settingsTo} className={cn(linkClassName, 'px-4 py-3')}>
      <div className="flex items-center gap-3 min-w-0">
        <img
          src={member.avatar_url || '/images/blank_profile_image.png'}
          alt={member.full_name || member.email}
          referrerPolicy="no-referrer"
          onError={(e) => {
            e.currentTarget.src = '/images/blank_profile_image.png';
          }}
          className="h-10 w-10 shrink-0 rounded-full border border-border object-cover"
        />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium text-foreground">
            {member.full_name || member.email.split('@')[0]}
          </div>
          <div className="truncate text-xs text-foreground-secondary">
            {member.email}
          </div>
        </div>
        <RoleBadge
          role={member.role}
          roleDisplayName={member.role_display_name ?? null}
          roleColor={member.role_color ?? null}
        />
      </div>
    </Link>
  );
}
