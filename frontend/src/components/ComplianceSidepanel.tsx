import { Package, FileText, Download, Loader2 } from 'lucide-react';
import { cn } from '../lib/utils';

export type ComplianceSection = 'project' | 'export-notice' | 'export-sbom';

interface ComplianceSidepanelProps {
  activeSection: ComplianceSection;
  onSelect: (section: ComplianceSection) => void;
  canViewSettings: boolean;
  disabledExports?: boolean;
  /** When provided, Export Legal Notice is a download button instead of a tab. */
  onExportNotice?: () => void;
  /** When provided, Export SBOM is a download button instead of a tab. */
  onExportSBOM?: () => void;
  /** Which export is currently in progress (disables that button and shows spinner). */
  exporting?: 'notice' | 'sbom' | null;
}

export function ComplianceSidepanel({
  activeSection,
  onSelect,
  canViewSettings,
  disabledExports = false,
  onExportNotice,
  onExportSBOM,
  exporting = null,
}: ComplianceSidepanelProps) {
  return (
    <aside className="w-52 shrink-0 border-r border-border bg-background flex flex-col py-4">
      <div className="px-3 mb-2">
        <h2 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
          Compliance
        </h2>
      </div>

      <nav className="flex-1" aria-label="Compliance navigation">
        {/* Project */}
        <div className="space-y-0.5">
          <button
            onClick={() => onSelect('project')}
            aria-current={activeSection === 'project' ? 'page' : undefined}
            className={cn(
              'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
              activeSection === 'project'
                ? 'text-foreground bg-background-card'
                : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
            )}
          >
            <Package className="h-4 w-4 shrink-0" />
            Project
          </button>
        </div>

        {canViewSettings && (onExportNotice != null || onExportSBOM != null) && (
          <>
            <div className="my-3 border-t border-border" aria-hidden />

            {/* Export Legal Notice — same look as Project nav, triggers download */}
            {onExportNotice != null && (
              <div className="space-y-0.5">
                <button
                  type="button"
                  onClick={onExportNotice}
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

            {/* Export SBOM — same look as Project nav, triggers download */}
            {onExportSBOM != null && (
              <div className="space-y-0.5">
                <button
                  type="button"
                  onClick={onExportSBOM}
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
      </nav>
    </aside>
  );
}
