import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';

/** Skeleton center node for vulnerabilities graph loading state. Matches ProjectCenterNode dimensions (260×80) so viewport is preserved when swapping to real nodes. */
function SkeletonProjectCenterNodeComponent(_props: NodeProps) {
  return (
    <div className="relative">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <div
        className="relative rounded-xl border-2 shadow-lg overflow-hidden min-w-[260px] border-primary/50 shadow-primary/10 bg-background-card px-5 pt-4 pb-4"
      >
        <div className="absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 bg-primary" />
        <div className="flex items-center gap-2.5">
          <div className="flex-shrink-0 w-9 h-9 rounded-lg bg-primary/15 animate-pulse" />
          <div className="min-w-0 flex-1">
            <div className="h-4 w-40 rounded bg-muted/60 animate-pulse" />
          </div>
        </div>
      </div>
    </div>
  );
}

export const SkeletonProjectCenterNode = memo(SkeletonProjectCenterNodeComponent);
