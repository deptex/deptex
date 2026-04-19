import { Package, FileText, Download, History } from 'lucide-react';
import { cn } from '../lib/utils';

export type ComplianceSection = 'project' | 'updates' | 'export-notice' | 'export-sbom';

interface ComplianceSidepanelProps {
  activeSection: ComplianceSection;
  onSelect: (section: ComplianceSection) => void;
  canViewSettings: boolean;
  disabledExports?: boolean;
}

export function ComplianceSidepanel({
  activeSection,
  onSelect,
  canViewSettings,
  disabledExports = false,
}: ComplianceSidepanelProps) {
  return (
    <aside className="w-52 shrink-0 border-r border-border bg-background flex flex-col py-4">
      <div className="px-3 mb-2">
        <h2 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
          Compliance
        </h2>
      </div>

      <nav className="flex-1" aria-label="Compliance navigation">
        {/* Licenses */}
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
            Licenses
          </button>
        </div>

        {/* Updates */}
        <div className="space-y-0.5 mt-1">
          <button
            onClick={() => onSelect('updates')}
            aria-current={activeSection === 'updates' ? 'page' : undefined}
            className={cn(
              'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
              activeSection === 'updates'
                ? 'text-foreground bg-background-card'
                : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
            )}
          >
            <History className="h-4 w-4 shrink-0" />
            Updates
          </button>
        </div>

        {canViewSettings && (
          <>
            <div className="my-3 border-t border-border" aria-hidden />

            {/* Export Notice */}
            <div className="space-y-0.5">
              <button
                onClick={() => onSelect('export-notice')}
                disabled={disabledExports}
                aria-current={activeSection === 'export-notice' ? 'page' : undefined}
                className={cn(
                  'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
                  disabledExports && 'opacity-50 cursor-not-allowed',
                  activeSection === 'export-notice' && !disabledExports
                    ? 'text-foreground bg-background-card'
                    : !disabledExports && 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                )}
              >
                <FileText className="h-4 w-4 shrink-0" />
                Export Notice
              </button>
            </div>

            {/* Export SBOM */}
            <div className="space-y-0.5">
              <button
                onClick={() => onSelect('export-sbom')}
                disabled={disabledExports}
                aria-current={activeSection === 'export-sbom' ? 'page' : undefined}
                className={cn(
                  'w-full flex items-center gap-2.5 h-9 px-3 text-sm font-medium transition-colors',
                  disabledExports && 'opacity-50 cursor-not-allowed',
                  activeSection === 'export-sbom' && !disabledExports
                    ? 'text-foreground bg-background-card'
                    : !disabledExports && 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                )}
              >
                <Download className="h-4 w-4 shrink-0" />
                Export SBOM
              </button>
            </div>
          </>
        )}
      </nav>
    </aside>
  );
}
