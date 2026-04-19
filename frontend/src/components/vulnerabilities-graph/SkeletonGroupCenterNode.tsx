import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';

/** Skeleton center node for org overview loading; matches GroupCenterNode org production layout. */
function SkeletonGroupCenterNodeComponent(_props: NodeProps) {
  return (
    <div className="relative h-full w-full min-h-0">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <div className="relative flex h-full w-full flex-col justify-between overflow-hidden rounded-xl border border-border bg-background-card-header shadow-lg px-5 py-5">
        {/* GraphScopePill placeholder */}
        <div
          className="pointer-events-none absolute top-1.5 right-1.5 z-[2] h-6 w-[1.85rem] rounded-md border border-border/90 bg-muted/30 animate-pulse"
          aria-hidden
        />
        {/* Avatar + title + plan */}
        <div className="flex items-center gap-4 min-w-0">
          <div className="flex-shrink-0 w-10 h-10 rounded-xl bg-muted/50 animate-pulse" />
          <div className="min-w-0 flex-1">
            <div className="h-5 max-w-[10rem] rounded bg-muted/60 animate-pulse" />
            <div className="h-3 max-w-[5rem] rounded bg-muted/40 animate-pulse mt-1.5" />
          </div>
        </div>
        {/* Active status indicator */}
        <div className="flex items-center gap-1.5 pl-[4px]">
          <div className="w-2 h-2 rounded-full bg-muted/50 animate-pulse" />
          <div className="h-3 w-10 rounded bg-muted/40 animate-pulse" />
        </div>
      </div>
    </div>
  );
}

export const SkeletonGroupCenterNode = memo(SkeletonGroupCenterNodeComponent);
