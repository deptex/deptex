import { Package, FileText, Download, Loader2, LayoutDashboard } from 'lucide-react';
import { cn } from '../lib/utils';

export type ComplianceSection = 'project' | 'export-notice' | 'export-sbom' | 'overview';

interface ComplianceSidepanelBaseProps {
  canViewSettings: boolean;
  disabledExports?: boolean;
  exporting?: 'notice' | 'sbom' | null;
  /** Darker shell to match org Security project drawer (same as Dependencies embed). */
  embedSurface?: boolean;
}

interface ComplianceSidepanelProjectProps extends ComplianceSidepanelBaseProps {
  mode?: 'project';
  activeSection: 'project' | 'export-notice' | 'export-sbom';
  onSelect: (section: 'project' | 'export-notice' | 'export-sbom') => void;
  onExportNotice?: () => void;
  onExportSBOM?: () => void;
  onExportNoticeClick?: never;
  onExportSBOMClick?: never;
}

interface ComplianceSidepanelOrganizationProps extends ComplianceSidepanelBaseProps {
  mode: 'organization';
  activeSection: 'overview';
  onSelect: (section: 'overview') => void;
  onExportNotice?: never;
  onExportSBOM?: never;
  onExportNoticeClick?: () => void;
  onExportSBOMClick?: () => void;
}

export type ComplianceSidepanelProps = ComplianceSidepanelProjectProps | ComplianceSidepanelOrganizationProps;

export function ComplianceSidepanel(props: ComplianceSidepanelProps) {
  const { canViewSettings, disabledExports = false, exporting = null, embedSurface = false } = props;
  const mode = props.mode ?? 'project';
  const isOrg = mode === 'organization';

  return (
    <aside
      className={cn(
        'w-52 shrink-0 border-r border-border flex flex-col py-4',
        embedSurface
          ? 'bg-background-card-header'
          : isOrg
            ? 'bg-background'
            : 'bg-background-content'
      )}
    >
      <div className="px-3 mb-2">
        <h2 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
          Compliance
        </h2>
      </div>

      <nav className="flex-1" aria-label="Compliance navigation">
        {/* Overview (org) or Project (project) */}
        <div className="space-y-0.5">
          {isOrg ? (
            <button
              onClick={() => (props as ComplianceSidepanelOrganizationProps).onSelect('overview')}
              aria-current={props.activeSection === 'overview' ? 'page' : undefined}
              className={cn(
                'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
                props.activeSection === 'overview'
                  ? 'text-foreground bg-background-card'
                  : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
              )}
            >
              <LayoutDashboard className="h-4 w-4 shrink-0" />
              Overview
            </button>
          ) : (
            <button
              onClick={() => (props as ComplianceSidepanelProjectProps).onSelect('project')}
              aria-current={props.activeSection === 'project' ? 'page' : undefined}
              className={cn(
                'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
                props.activeSection === 'project'
                  ? 'text-foreground bg-background-card'
                  : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
              )}
            >
              <Package className="h-4 w-4 shrink-0" />
              Project
            </button>
          )}
        </div>

        {/* Export buttons: project = direct download, organization = open modal */}
        {canViewSettings && (
          <>
            <div className="my-3 border-t border-border" aria-hidden />

            {isOrg ? (
              <>
                {props.onExportNoticeClick != null && (
                  <div className="space-y-0.5">
                    <button
                      type="button"
                      onClick={props.onExportNoticeClick}
                      disabled={disabledExports}
                      className={cn(
                        'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
                        disabledExports && 'opacity-50 cursor-not-allowed',
                        !disabledExports && 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                      )}
                    >
                      <FileText className="h-4 w-4 shrink-0" />
                      Export Legal Notice
                    </button>
                  </div>
                )}
                {props.onExportSBOMClick != null && (
                  <div className="space-y-0.5">
                    <button
                      type="button"
                      onClick={props.onExportSBOMClick}
                      disabled={disabledExports}
                      className={cn(
                        'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
                        disabledExports && 'opacity-50 cursor-not-allowed',
                        !disabledExports && 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                      )}
                    >
                      <Download className="h-4 w-4 shrink-0" />
                      Export SBOM
                    </button>
                  </div>
                )}
              </>
            ) : (
              <>
                {props.onExportNotice != null && (
                  <div className="space-y-0.5">
                    <button
                      type="button"
                      onClick={props.onExportNotice}
                      disabled={disabledExports || exporting === 'notice'}
                      className={cn(
                        'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
                        (disabledExports || exporting === 'notice') && 'opacity-50 cursor-not-allowed',
                        !disabledExports && exporting !== 'notice' && 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                      )}
                    >
                      {exporting === 'notice' ? (
                        <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
                      ) : (
                        <FileText className="h-4 w-4 shrink-0" />
                      )}
                      Export Legal Notice
                    </button>
                  </div>
                )}
                {props.onExportSBOM != null && (
                  <div className="space-y-0.5">
                    <button
                      type="button"
                      onClick={props.onExportSBOM}
                      disabled={disabledExports || exporting === 'sbom'}
                      className={cn(
                        'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
                        (disabledExports || exporting === 'sbom') && 'opacity-50 cursor-not-allowed',
                        !disabledExports && exporting !== 'sbom' && 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                      )}
                    >
                      {exporting === 'sbom' ? (
                        <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
                      ) : (
                        <Download className="h-4 w-4 shrink-0" />
                      )}
                      Export SBOM
                    </button>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </nav>
    </aside>
  );
}
