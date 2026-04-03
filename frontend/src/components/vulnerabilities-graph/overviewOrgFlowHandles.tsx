import { Handle, Position } from '@xyflow/react';
import { ORG_OVERVIEW_EDGE_SLOTS, type OrgSatelliteTargetEdge } from './overviewOrgLayout';

const RF_HIDE = '!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0';

/** Distributed source handles on the org card (one side → many slots). */
export function OrgOverviewSourceHandles() {
  return (
    <>
      {Array.from({ length: ORG_OVERVIEW_EDGE_SLOTS }, (_, i) => {
        const pct = `${((i + 1) / (ORG_OVERVIEW_EDGE_SLOTS + 1)) * 100}%`;
        return (
          <Handle
            key={`ov-src-top-${i}`}
            id={`ov-src-top-${i}`}
            type="source"
            position={Position.Top}
            className={RF_HIDE}
            style={{ left: pct, top: 0, transform: 'translate(-50%, -50%)' }}
          />
        );
      })}
      {Array.from({ length: ORG_OVERVIEW_EDGE_SLOTS }, (_, i) => {
        const pct = `${((i + 1) / (ORG_OVERVIEW_EDGE_SLOTS + 1)) * 100}%`;
        return (
          <Handle
            key={`ov-src-right-${i}`}
            id={`ov-src-right-${i}`}
            type="source"
            position={Position.Right}
            className={RF_HIDE}
            style={{ top: pct, right: 0, transform: 'translate(50%, -50%)' }}
          />
        );
      })}
      {Array.from({ length: ORG_OVERVIEW_EDGE_SLOTS }, (_, i) => {
        const pct = `${((i + 1) / (ORG_OVERVIEW_EDGE_SLOTS + 1)) * 100}%`;
        return (
          <Handle
            key={`ov-src-bottom-${i}`}
            id={`ov-src-bottom-${i}`}
            type="source"
            position={Position.Bottom}
            className={RF_HIDE}
            style={{ left: pct, bottom: 0, transform: 'translate(-50%, 50%)' }}
          />
        );
      })}
      {Array.from({ length: ORG_OVERVIEW_EDGE_SLOTS }, (_, i) => {
        const pct = `${((i + 1) / (ORG_OVERVIEW_EDGE_SLOTS + 1)) * 100}%`;
        return (
          <Handle
            key={`ov-src-left-${i}`}
            id={`ov-src-left-${i}`}
            type="source"
            position={Position.Left}
            className={RF_HIDE}
            style={{ top: pct, left: 0, transform: 'translate(-50%, -50%)' }}
          />
        );
      })}
    </>
  );
}

/** Distributed target handles on team / ungrouped project cards for org overview links. */
export function OverviewOrgTargetHandleFan({ side }: { side: OrgSatelliteTargetEdge }) {
  return (
    <>
      {Array.from({ length: ORG_OVERVIEW_EDGE_SLOTS }, (_, i) => {
        const pct = `${((i + 1) / (ORG_OVERVIEW_EDGE_SLOTS + 1)) * 100}%`;
        const id = `ov-tgt-${side}-${i}`;
        if (side === 'top') {
          return (
            <Handle
              key={id}
              id={id}
              type="target"
              position={Position.Top}
              className={RF_HIDE}
              style={{ left: pct, top: 0, transform: 'translate(-50%, -50%)' }}
            />
          );
        }
        if (side === 'bottom') {
          return (
            <Handle
              key={id}
              id={id}
              type="target"
              position={Position.Bottom}
              className={RF_HIDE}
              style={{ left: pct, bottom: 0, transform: 'translate(-50%, 50%)' }}
            />
          );
        }
        if (side === 'left') {
          return (
            <Handle
              key={id}
              id={id}
              type="target"
              position={Position.Left}
              className={RF_HIDE}
              style={{ top: pct, left: 0, transform: 'translate(-50%, -50%)' }}
            />
          );
        }
        return (
          <Handle
            key={id}
            id={id}
            type="target"
            position={Position.Right}
            className={RF_HIDE}
            style={{ top: pct, right: 0, transform: 'translate(50%, -50%)' }}
          />
        );
      })}
    </>
  );
}
