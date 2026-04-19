import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Package, Scale, Check, X } from 'lucide-react';
import type { DependencyNodeData } from './useGraphLayout';

const ECOSYSTEM_ICON: Record<string, string> = {
  npm: '/images/npm_icon.png',
  pypi: '/images/frameworks/python.png',
  maven: '/images/frameworks/java.png',
  golang: '/images/frameworks/go.png',
  cargo: '/images/frameworks/rust.png',
  gem: '/images/frameworks/ruby.png',
  composer: '/images/frameworks/php.png',
};

function getEcosystemIcon(ecosystem: string | null | undefined): string | null {
  if (!ecosystem) return null;
  return ECOSYSTEM_ICON[ecosystem.toLowerCase()] ?? null;
}

function DependencyNodeComponent({ data }: NodeProps) {
  const nodeData = data as unknown as DependencyNodeData;

  // License badge (hidden when showLicense is false, e.g. on vulnerabilities graph)
  const showLicense = nodeData.showLicense !== false;
  const licenseLabel = showLicense && nodeData.license && nodeData.license !== 'Unknown' ? nodeData.license : null;
  const licenseBadgeClass = 'bg-foreground-secondary/10 text-foreground-secondary border-foreground-secondary/20';
  const showNotImported = nodeData.notImported === true;
  const ecosystemIcon = getEcosystemIcon(nodeData.ecosystem);
  const showPolicyBadge = nodeData.policyAllowed !== undefined && nodeData.policyAllowed !== null;

  return (
    <div className="relative group">
      {/* Target handles (incoming edges from center) */}
      <Handle id="top" type="target" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="target" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="target" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="target" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      {/* Source handles (outgoing edges to vulnerability nodes) */}
      <Handle id="source-top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      {/* Main card */}
      <div
        className="rounded-lg border border-border bg-background-card shadow-md"
        style={{ minWidth: 220 }}
      >
        {/* Header row */}
        <div className="px-3.5 py-3 flex items-center gap-2.5">
          {ecosystemIcon ? (
            <img src={ecosystemIcon} alt="" className="h-4 w-4 flex-shrink-0 object-contain" aria-hidden />
          ) : (
            <Package className="h-4 w-4 text-foreground-secondary flex-shrink-0" />
          )}
          <div className="min-w-0 flex-1">
            <p className="text-[13px] font-medium text-foreground truncate">{nodeData.name}</p>
            <div className="flex items-center gap-2 mt-0.5 flex-wrap">
              <span className="text-[11px] text-foreground-secondary font-mono">
                {nodeData.version}
              </span>
              {showPolicyBadge && (
                <span
                  className={nodeData.policyAllowed
                    ? 'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-medium border border-green-500/30 bg-green-500/10 text-green-600 dark:text-green-400'
                    : 'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-medium border border-destructive/30 bg-destructive/10 text-destructive'
                  }
                >
                  {nodeData.policyAllowed ? <Check className="h-2.5 w-2.5" /> : <X className="h-2.5 w-2.5" />}
                  {nodeData.policyAllowed ? 'Allowed' : 'Not allowed'}
                </span>
              )}
            </div>
          </div>
          {/* License badge (right side) */}
          {licenseLabel && (
            <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-medium border flex-shrink-0 ${licenseBadgeClass}`}>
              <Scale className="h-2.5 w-2.5" />
              {licenseLabel}
            </span>
          )}
          {/* Not imported badge (vulnerabilities graph, direct deps only) */}
          {showNotImported && (
            <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-medium border flex-shrink-0 bg-foreground-secondary/10 text-foreground-secondary border-foreground-secondary/20">
              Not imported
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

export const DependencyNode = memo(DependencyNodeComponent);
