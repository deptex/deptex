import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Folder, Users, Loader2 } from 'lucide-react';
import { FrameworkIcon } from '../framework-icon';
import type { WorstSeverity } from './useVulnerabilitiesGraphLayout';

export interface VulnProjectNodeData {
  projectName: string;
  projectId: string;
  /** When set, show framework icon (same as project vulnerabilities tab header); otherwise Folder. */
  framework?: string | null;
  /** Worst vulnerability severity for this project (used to color the card). */
  worstSeverity?: WorstSeverity;
  /** When true, render as a team node (Users icon) instead of a project (framework/folder icon). */
  isTeamNode?: boolean;
  /** Phase 15: Number of vulnerabilities with SLA breached. Shown as "SLA: X breached" when > 0. */
  slaBreachCount?: number;
  /** When true, show extracting spinner and no dependency/vulnerability data (like Project Security tab). */
  isExtracting?: boolean;
  /** When true (team node only), team has projects still extracting — show grey so color reflects known risk only. */
  hasExtractingProjects?: boolean;
}

const NODE_WIDTH = 220;
const NODE_HEIGHT = 64;

function getColorScheme(worstSeverity: WorstSeverity | undefined) {
  const s = worstSeverity ?? 'none';
  switch (s) {
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

const greyExtractingScheme = {
  border: 'border-slate-400/40',
  shadow: 'shadow-slate-400/5',
  glow: 'bg-slate-400',
  iconBg: 'bg-slate-400/15',
  iconText: 'text-slate-500',
};

function VulnProjectNodeComponent({ data }: NodeProps) {
  const { projectName = 'Project', projectId, framework, worstSeverity, isTeamNode, slaBreachCount, isExtracting, hasExtractingProjects } =
    (data as unknown as VulnProjectNodeData) ?? {};
  const hasKnownFramework = framework && framework.toLowerCase() !== 'unknown';
  const frameworkIdForIcon = hasKnownFramework ? framework : undefined;
  const useGrey = isExtracting || (isTeamNode && hasExtractingProjects);
  const colorScheme = useGrey ? greyExtractingScheme : getColorScheme(worstSeverity);
  const showSlaBreach = !isExtracting && typeof slaBreachCount === 'number' && slaBreachCount > 0;

  return (
    <div className="relative" style={{ minWidth: NODE_WIDTH, minHeight: NODE_HEIGHT }}>
      <Handle id="top" type="target" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="target" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="target" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="target" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      <div
        className={`relative rounded-xl border-2 bg-background-card px-3 py-2.5 shadow-sm h-full flex flex-col justify-center gap-0.5 min-w-0 overflow-hidden ${colorScheme.border} ${colorScheme.shadow}`}
      >
        {!isExtracting && <div className={`absolute inset-0 rounded-xl blur-xl opacity-15 -z-10 ${colorScheme.glow}`} />}
        <div className="flex items-center gap-2 min-w-0">
          {isTeamNode && !isExtracting ? (
            <div
              className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
            >
              <Users className="w-4 h-4" />
            </div>
          ) : frameworkIdForIcon ? (
            <div
              className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
            >
              <FrameworkIcon frameworkId={frameworkIdForIcon} size={18} className="text-current" />
            </div>
          ) : (
            <div
              className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
            >
              <Folder className="w-4 h-4" />
            </div>
          )}
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-foreground truncate" title={projectName}>
              {projectName}
            </p>
            {isExtracting && (
              <p className="text-[10px] text-foreground-secondary mt-0.5">Project still extracting</p>
            )}
          </div>
          {isExtracting && (
            <div className="flex-shrink-0" aria-hidden>
              <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
            </div>
          )}
        </div>
        {showSlaBreach && (
          <p className="text-[10px] text-red-400 font-medium truncate" title={`${slaBreachCount} SLA breach(es)`}>
            SLA: {slaBreachCount} breached
          </p>
        )}
      </div>
    </div>
  );
}

export const VulnProjectNode = memo(VulnProjectNodeComponent);
export const VULN_PROJECT_NODE_WIDTH = NODE_WIDTH;
export const VULN_PROJECT_NODE_HEIGHT = NODE_HEIGHT;
