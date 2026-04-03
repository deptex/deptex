import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';

/** Skeleton center node for org overview loading; matches GroupCenterNode org layout. */
function SkeletonGroupCenterNodeComponent(_props: NodeProps) {
  return (
    <div className="relative h-full w-full min-h-0">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <div className="relative flex h-full min-h-0 w-full max-w-[min(100vw-2rem,360px)] flex-col overflow-hidden rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5">
        <div
          className="absolute top-1.5 right-1.5 z-[1] h-6 w-[1.85rem] rounded-md border border-border/90 bg-muted/30 animate-pulse"
          aria-hidden
        />
        <div className="flex min-h-0 flex-1 flex-col justify-center px-5 py-5">
          <div className="flex items-center gap-4 min-w-0 pr-10">
            <div className="flex-shrink-0 w-14 h-14 rounded-xl bg-muted/50 animate-pulse" />
            <div className="min-w-0 flex-1">
              <div className="h-7 max-w-[14rem] rounded bg-muted/60 animate-pulse" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export const SkeletonGroupCenterNode = memo(SkeletonGroupCenterNodeComponent);
