import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';

/** Skeleton center node for org overview loading; matches compact GroupCenterNode org production layout. */
function SkeletonGroupCenterNodeComponent(_props: NodeProps) {
  return (
    <div className="relative h-full w-full min-h-0 rounded-xl">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <div className="relative flex h-full w-full items-center gap-2.5 overflow-hidden rounded-xl border border-border bg-background-card-header shadow-lg pl-3.5 pr-3.5">
        {/* Avatar tile placeholder */}
        <div className="h-9 w-9 shrink-0 rounded-lg bg-muted/50 animate-pulse" />
        <div className="min-w-0 flex-1">
          {/* Name placeholder */}
          <div className="h-4 max-w-[8rem] rounded bg-muted/60 animate-pulse" />
          {/* Plan pill placeholder */}
          <div className="mt-1.5 h-4 w-10 rounded-md border border-border/70 bg-muted/40 animate-pulse" />
        </div>
      </div>
    </div>
  );
}

export const SkeletonGroupCenterNode = memo(SkeletonGroupCenterNodeComponent);
