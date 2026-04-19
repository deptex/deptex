import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';

/** Skeleton center node for org overview loading; matches GroupCenterNode org two-section layout. */
function SkeletonGroupCenterNodeComponent(_props: NodeProps) {
  return (
    <div className="relative">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <div className="relative rounded-xl border border-border shadow-lg shadow-slate-500/5 overflow-hidden min-w-[280px] max-w-[320px] bg-background-card">
        <div className="px-4 pt-4 pb-3">
          <div className="flex items-center gap-3">
            <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-muted/50 animate-pulse" />
            <div className="h-5 w-36 rounded bg-muted/60 animate-pulse" />
          </div>
          <div className="mt-4">
            <div className="h-6 w-16 rounded-md bg-muted/50 animate-pulse" />
          </div>
        </div>
        <div className="border-t border-border w-full" />
        <div className="px-4 py-3">
          <div className="h-4 w-36 rounded bg-muted/50 animate-pulse" />
        </div>
      </div>
    </div>
  );
}

export const SkeletonGroupCenterNode = memo(SkeletonGroupCenterNodeComponent);
