import { memo, useState } from 'react';
import { Search } from 'lucide-react';
import AppHeader from './AppHeader';
import CommandPalette from './CommandPalette';
import OrganizationSwitcher from './OrganizationSwitcher';
import { Organization } from '../lib/api';
import { Button } from './ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';

/** Aegis icon (shield + diamond) — matches Organization Settings sidebar. */
const AegisIcon = ({ className }: { className?: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
    <path d="M12 2L4 6v5c0 5 4 8 8 10 4-2 8-5 8-10V6l-8-4z" />
    <path d="M12 9l1 2 2 1-1 2-2 1-1-2-2-1 1-2 2-1z" fill="currentColor" stroke="none" />
  </svg>
);

interface OrganizationHeaderProps {
  organization: Organization | null;
  /** When provided, shows Aegis toggle button in header right; open state and toggle callback. */
  aegisSidebarOpen?: boolean;
  onToggleAegis?: () => void;
}

function OrganizationHeader({ organization, aegisSidebarOpen, onToggleAegis }: OrganizationHeaderProps) {
  const [commandOpen, setCommandOpen] = useState(false);

  if (!organization) {
    return null;
  }

  const searchButton = (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={() => setCommandOpen(true)}
            className="group hidden sm:flex items-center gap-1.5 px-2.5 py-1 h-8 rounded-md border border-border bg-background-card text-sm text-foreground-secondary hover:text-foreground hover:border-vercel-border-hover hover:bg-background-subtle transition-colors"
            aria-label="Search or run a command (Ctrl+K)"
          >
            <Search className="h-3.5 w-3.5 shrink-0" />
            <span>Search...</span>
            <span className="hidden md:inline-flex items-center gap-0.5 h-4 shrink-0 text-foreground-secondary transition-colors group-hover:text-foreground">
              <img src="/images/commandicon.png" alt="⌘" className="h-3 w-3 invert opacity-70 group-hover:opacity-90 transition-opacity" aria-hidden />
              <span className="font-mono text-[13px] leading-none font-medium">K</span>
            </span>
          </button>
        </TooltipTrigger>
        <TooltipContent side="bottom">Search or run a command (Ctrl+K)</TooltipContent>
      </Tooltip>
      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} />
    </>
  );

  const aegisButton =
    onToggleAegis != null ? (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            className={`h-8 shrink-0 rounded-md border px-2.5 gap-1.5 transition-all duration-200 ${
              aegisSidebarOpen
                ? 'border-border bg-muted/60 text-foreground'
                : 'border-border bg-transparent text-muted-foreground hover:text-foreground hover:bg-muted/40'
            }`}
            onClick={onToggleAegis}
            aria-pressed={aegisSidebarOpen}
            aria-label={aegisSidebarOpen ? 'Close Aegis' : 'Open Aegis'}
          >
            <AegisIcon className="h-4 w-4 shrink-0" />
            <span className="text-sm font-medium">Aegis</span>
          </Button>
        </TooltipTrigger>
        <TooltipContent side="bottom">
          {aegisSidebarOpen ? 'Close Aegis' : 'Open Aegis'}
        </TooltipContent>
      </Tooltip>
    ) : null;

  const rightContent = (
    <div className="flex items-center gap-2">
      {searchButton}
      {aegisButton}
    </div>
  );

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
      <AppHeader
        breadcrumb={[]}
        showSearch={false}
        showNewOrg={false}
        hideRightActions
        customRightContent={rightContent}
        customLeftContent={
          <nav className="flex items-center gap-2 text-sm">
            <img
              src="/images/logo.png"
              alt="Deptex"
              className="h-8 w-8 flex-shrink-0"
            />
            <div className="h-4 w-px bg-border flex-shrink-0 ml-1.5 mr-3" aria-hidden />
            <OrganizationSwitcher
              currentOrganizationId={organization.id}
              currentOrganizationName={organization.name}
              currentOrganizationAvatarUrl={organization.avatar_url}
              triggerVariant="full"
            />
          </nav>
        }
      />
    </div>
  );
}

// Custom comparison function to prevent re-renders when organization data is the same
const areEqual = (prevProps: OrganizationHeaderProps, nextProps: OrganizationHeaderProps) => {
  // Handle null cases
  if (!prevProps.organization || !nextProps.organization) {
    return prevProps.organization === nextProps.organization;
  }
  if (prevProps.aegisSidebarOpen !== nextProps.aegisSidebarOpen) return false;
  if (prevProps.onToggleAegis !== nextProps.onToggleAegis) return false;

  return (
    prevProps.organization.id === nextProps.organization.id &&
    prevProps.organization.name === nextProps.organization.name &&
    prevProps.organization.avatar_url === nextProps.organization.avatar_url &&
    JSON.stringify(prevProps.organization.permissions) === JSON.stringify(nextProps.organization.permissions)
  );
};

export default memo(OrganizationHeader, areEqual);

