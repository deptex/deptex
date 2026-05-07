import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, type OrganizationMember } from '../../lib/api';
import { RoleBadge } from '../RoleBadge';

interface MembersTableProps {
  organizationId: string;
  userIds: string[];
}

interface MissingRow {
  user_id: string;
  missing: true;
}

type Row = OrganizationMember | MissingRow;

function isMissing(r: Row): r is MissingRow {
  return (r as MissingRow).missing === true;
}

export function MembersTable({ organizationId, userIds }: MembersTableProps) {
  const settingsTo = useMemo(
    () => `/organizations/${organizationId}/settings/members`,
    [organizationId],
  );

  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setRows(null);
    setError(null);
    api
      .getOrganizationMembersCached(organizationId)
      .then((all) => {
        if (cancelled) return;
        const byId = new Map(all.map((m) => [m.user_id, m]));
        const ordered: Row[] = userIds.map((uid) =>
          byId.get(uid) ?? { user_id: uid, missing: true },
        );
        setRows(ordered);
      })
      .catch(() => {
        if (!cancelled) setError('Could not load these members.');
      });
    return () => {
      cancelled = true;
    };
  }, [organizationId, userIds]);

  if (error) {
    return (
      <div className="my-2 rounded-lg border border-border bg-background-card px-3 py-2 text-xs text-foreground-muted">
        {error}{' '}
        <Link to={settingsTo} className="underline underline-offset-2 hover:text-foreground">
          Open members
        </Link>
      </div>
    );
  }

  return (
    <div className="my-2 overflow-hidden rounded-lg border border-border bg-background-card">
      <table className="w-full table-fixed">
        <colgroup>
          <col style={{ width: 'auto' }} />
          <col style={{ width: '160px' }} />
        </colgroup>
        <thead className="bg-background-card-header border-b border-border">
          <tr>
            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
              Member
            </th>
            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
              Role
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rows === null
            ? userIds.map((uid) => (
                <tr key={`skeleton-${uid}`} className="animate-pulse">
                  <td className="px-4 py-3 min-w-0 overflow-hidden">
                    <div className="flex items-center gap-3">
                      <div className="h-10 w-10 shrink-0 rounded-full bg-muted" />
                      <div className="flex-1 min-w-0 space-y-1.5">
                        <div className="h-3.5 w-32 rounded bg-muted" />
                        <div className="h-3 w-48 rounded bg-muted" />
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="h-5 w-16 rounded bg-muted" />
                  </td>
                </tr>
              ))
            : rows.map((row) =>
                isMissing(row) ? (
                  <tr key={row.user_id}>
                    <td colSpan={2} className="px-4 py-3 text-xs text-foreground-muted">
                      Member could not be found.
                    </td>
                  </tr>
                ) : (
                  <tr key={row.user_id} className="hover:bg-table-hover transition-colors">
                    <td className="px-4 py-3 min-w-0 overflow-hidden">
                      <div className="flex items-center gap-3 min-w-0">
                        <img
                          src={row.avatar_url || '/images/blank_profile_image.png'}
                          alt={row.full_name || row.email}
                          className="h-10 w-10 shrink-0 rounded-full border border-border object-cover"
                          referrerPolicy="no-referrer"
                          onError={(e) => {
                            e.currentTarget.src = '/images/blank_profile_image.png';
                          }}
                        />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-medium text-foreground">
                            {row.full_name || row.email.split('@')[0]}
                          </div>
                          <div className="truncate text-xs text-foreground-secondary">
                            {row.email}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <RoleBadge
                        role={row.role}
                        roleDisplayName={row.role_display_name ?? null}
                        roleColor={row.role_color ?? null}
                      />
                    </td>
                  </tr>
                ),
              )}
        </tbody>
      </table>
    </div>
  );
}
