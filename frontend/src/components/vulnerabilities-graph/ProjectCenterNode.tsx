import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { FrameworkIcon } from '../framework-icon';

export type WorstSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none';

export interface ProjectCenterNodeData {
  projectName: string;
  worstVulnerabilitySeverity?: WorstSeverity;
  worstDepscore?: number;
  frameworkName?: string;
  vulnCount?: number;
  semgrepCount?: number;
  secretCount?: number;
}

function getColorScheme(worstVulnerabilitySeverity: WorstSeverity) {
  switch (worstVulnerabilitySeverity) {
    case 'critical':
      return {
        border: 'border-red-500/40',
        shadow: 'shadow-red-500/5',
        glow: 'bg-red-500',
        iconBg: 'bg-red-500/10',
        iconText: 'text-red-500',
      };
    case 'high':
      return {
        border: 'border-orange-500/40',
        shadow: 'shadow-orange-500/5',
        glow: 'bg-orange-500',
        iconBg: 'bg-orange-500/10',
        iconText: 'text-orange-500',
      };
    case 'medium':
      return {
        border: 'border-yellow-500/40',
        shadow: 'shadow-yellow-500/5',
        glow: 'bg-yellow-500',
        iconBg: 'bg-yellow-500/10',
        iconText: 'text-yellow-500',
      };
    case 'low':
      return {
        border: 'border-slate-500/40',
        shadow: 'shadow-slate-500/5',
        glow: 'bg-slate-500',
        iconBg: 'bg-slate-500/10',
        iconText: 'text-slate-500',
      };
    case 'none':
    default:
      return {
        border: 'border-primary/50',
        shadow: 'shadow-primary/10',
        glow: 'bg-primary',
        iconBg: 'bg-primary/15',
        iconText: 'text-primary',
      };
  }
}

function ProjectCenterNodeComponent({ data }: NodeProps) {
  const {
    projectName = 'Project',
    worstVulnerabilitySeverity = 'none',
    worstDepscore,
    frameworkName,
    vulnCount,
    semgrepCount,
    secretCount,
  } = (data as unknown as ProjectCenterNodeData) ?? {};
  const colorScheme = getColorScheme(worstVulnerabilitySeverity);
  const hasKnownFramework = frameworkName && frameworkName.toLowerCase() !== 'unknown';
  const frameworkIdForIcon = hasKnownFramework ? frameworkName : undefined;

  const hasCounts = (vulnCount ?? 0) > 0 || (semgrepCount ?? 0) > 0 || (secretCount ?? 0) > 0;

  return (
    <div className="relative cursor-pointer">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      <div
        className={`relative rounded-xl border-2 shadow-lg overflow-hidden min-w-[260px] ${colorScheme.border} ${colorScheme.shadow}`}
      >
        <div className={`absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 ${colorScheme.glow}`} />
        <div className={`bg-background-card px-5 pt-4 pb-4 rounded-xl`}>
          <div className="flex items-center gap-2.5">
            <div
              className={`flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
            >
              <FrameworkIcon frameworkId={frameworkIdForIcon} size={20} className="text-current" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-foreground truncate">{projectName}</p>
              {hasCounts && (
                <p className="text-[10px] text-foreground-secondary mt-0.5">
                  {[
                    vulnCount ? `${vulnCount} vulns` : null,
                    semgrepCount ? `${semgrepCount} code issues` : null,
                    secretCount ? `${secretCount} secrets` : null,
                  ].filter(Boolean).join(' · ')}
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export const ProjectCenterNode = memo(ProjectCenterNodeComponent);
