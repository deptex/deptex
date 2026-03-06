import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { RoleBadge } from '../RoleBadge';

export interface OrgMemberNodeData {
  memberId: string;
  fullName?: string | null;
  email: string;
  avatarUrl?: string | null;
  role: string;
  roleDisplayName?: string | null;
  roleColor?: string | null;
}

const MEMBER_NODE_WIDTH = 200;
const MEMBER_NODE_HEIGHT = 56;

function OrgMemberNodeComponent({ data }: NodeProps) {
  const {
    fullName,
    email,
    avatarUrl,
    role,
    roleDisplayName,
    roleColor,
  } = (data as unknown as OrgMemberNodeData) ?? {};

  const displayName = fullName?.trim() || email?.split('@')[0] || 'Member';

  return (
    <div className="relative">
      <Handle id="left" type="target" position={Position.Left} className="!opacity-0 !w-0 !h-0" />
      <div className="rounded-lg border border-border bg-background-card shadow-md overflow-hidden min-w-[200px] h-14 flex items-center gap-3 px-3 py-2">
        <div className="flex-shrink-0 w-9 h-9 rounded-full overflow-hidden bg-muted flex items-center justify-center">
          {avatarUrl ? (
            <img
              src={avatarUrl}
              alt=""
              className="w-full h-full object-cover"
            />
          ) : (
            <span className="text-xs font-medium text-muted-foreground">
              {displayName.charAt(0).toUpperCase()}
            </span>
          )}
        </div>
        <div className="min-w-0 flex-1 flex flex-col gap-0.5">
          <p className="text-sm font-medium text-foreground truncate" title={displayName}>
            {displayName}
          </p>
          <RoleBadge
            role={role}
            roleDisplayName={roleDisplayName}
            roleColor={roleColor}
            className="w-fit"
          />
        </div>
      </div>
    </div>
  );
}

export const OrgMemberNode = memo(OrgMemberNodeComponent);
export { MEMBER_NODE_WIDTH, MEMBER_NODE_HEIGHT };
