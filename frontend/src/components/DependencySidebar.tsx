import { memo, useState, useMemo, useRef, useCallback, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, GitBranch, TowerControl, MessageSquareText } from 'lucide-react';
import { cn } from '../lib/utils';
import { api } from '../lib/api';

interface DependencySidebarProps {
  organizationId: string;
  projectId: string;
  dependencyId: string;
  dependencyName?: string;
  notesSidebarOpen?: boolean;
  onNotesClick?: () => void;
  notesCount?: number;
  watchtowerStatus?: 'safe' | 'unsafe' | 'not-good' | null;
}

const navItems = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard },
  { id: 'supply-chain', label: 'Supply Chain', path: 'supply-chain', icon: GitBranch },
  { id: 'watchtower', label: 'Watchtower', path: 'watchtower', icon: TowerControl },
];

function DependencySidebar({ organizationId, projectId, dependencyId, dependencyName, notesSidebarOpen = false, onNotesClick, notesCount = 0, watchtowerStatus = null }: DependencySidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [isHovered, setIsHovered] = useState(false);
  const prefetchTimeouts = useRef<Map<string, NodeJS.Timeout>>(new Map());

  // Extract current tab from pathname
  const pathParts = location.pathname.split('/');
  const currentTab = pathParts[pathParts.length - 1];

  // Determine active tab
  const activeTab = useMemo(() => {
    const matchingTab = navItems.find(tab => tab.path === currentTab);
    if (matchingTab) {
      return matchingTab.id;
    }
    if (currentTab === dependencyId) {
      return 'overview';
    }
    return 'overview';
  }, [currentTab, dependencyId]);

  const handleNavClick = (path: string) => {
    const basePath = `/organizations/${organizationId}/projects/${projectId}/dependencies/${dependencyId}`;
    navigate(`${basePath}/${path}`);
  };

  // Prefetch tab data on hover (100ms debounce to avoid accidental hovers)
  const handleTabHover = useCallback((tabId: string) => {
    // Don't prefetch the currently active tab
    if (tabId === activeTab) return;

    const existing = prefetchTimeouts.current.get(tabId);
    if (existing) clearTimeout(existing);

    const timeout = setTimeout(() => {
      if (tabId === 'overview') {
        api.prefetchDependencyOverview(organizationId, projectId, dependencyId);
      } else if (tabId === 'supply-chain') {
        api.prefetchDependencySupplyChain(organizationId, projectId, dependencyId);
      } else if (tabId === 'watchtower' && dependencyName) {
        api.prefetchWatchtowerData(dependencyName, dependencyId, organizationId);
      }
      prefetchTimeouts.current.delete(tabId);
    }, 100);

    prefetchTimeouts.current.set(tabId, timeout);
  }, [activeTab, organizationId, projectId, dependencyId, dependencyName]);

  const handleTabHoverEnd = useCallback((tabId: string) => {
    const timeout = prefetchTimeouts.current.get(tabId);
    if (timeout) {
      clearTimeout(timeout);
      prefetchTimeouts.current.delete(tabId);
    }
  }, []);

  // Prefetch Watchtower on mount when on another tab, so data may be ready when user clicks Watchtower
  useEffect(() => {
    if (!organizationId || !dependencyId || !dependencyName || activeTab === 'watchtower') return;
    const timeout = setTimeout(() => {
      api.prefetchWatchtowerData(dependencyName, dependencyId, organizationId);
    }, 500);
    return () => clearTimeout(timeout);
  }, [organizationId, dependencyId, dependencyName, activeTab]);

  return (
    <aside
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={cn(
        'fixed left-0 top-12 bottom-0 bg-background border-r border-border z-40 flex flex-col transition-[width] duration-200 overflow-hidden',
        isHovered ? 'w-48' : 'w-12'
      )}
    >
      <nav className="flex-1 py-2" aria-label="Dependency navigation">
        <div className="space-y-0.5 px-2">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            const Icon = item.icon;
            const isWatchtower = item.id === 'watchtower';

            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.path)}
                onMouseEnter={() => handleTabHover(item.id)}
                onMouseLeave={() => handleTabHoverEnd(item.id)}
                aria-current={isActive ? 'page' : undefined}
                className={cn(
                  'relative w-full flex items-center gap-2.5 h-9 px-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
                  isActive
                    ? 'text-foreground bg-background-card'
                    : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                )}
              >
                <Icon className="h-[1.3125rem] w-[1.3125rem] flex-shrink-0 tab-icon-shake" />
                <span
                  className={cn(
                    'truncate transition-opacity duration-200',
                    isHovered ? 'opacity-100' : 'opacity-0'
                  )}
                >
                  {item.label}
                </span>
                {isWatchtower && (watchtowerStatus === 'unsafe' || watchtowerStatus === 'not-good') && (
                  <span className="absolute -top-0.5 left-6 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[9px] font-bold text-white">
                    !
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Border separator */}
        <div className="my-3 mx-2 border-t border-border" />

        {/* Notes button */}
        <div className="px-2">
          <button
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onNotesClick?.();
            }}
            className={cn(
              'relative w-full flex items-center gap-2.5 h-9 px-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
              notesSidebarOpen
                ? 'text-foreground bg-background-card'
                : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
            )}
            title="Team Notes"
          >
            <MessageSquareText className="h-[1.3125rem] w-[1.3125rem] flex-shrink-0" />
            <span
              className={cn(
                'truncate transition-opacity duration-200',
                isHovered ? 'opacity-100' : 'opacity-0'
              )}
            >
              Notes
            </span>
            {notesCount > 0 && (
              <span className="absolute -top-0.5 left-6 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[9px] font-bold text-white">
                {notesCount > 99 ? '99+' : notesCount}
              </span>
            )}
          </button>
        </div>
      </nav>
    </aside>
  );
}

export default memo(DependencySidebar, (prevProps, nextProps) => {
  return (
    prevProps.organizationId === nextProps.organizationId &&
    prevProps.projectId === nextProps.projectId &&
    prevProps.dependencyId === nextProps.dependencyId &&
    prevProps.dependencyName === nextProps.dependencyName &&
    prevProps.notesSidebarOpen === nextProps.notesSidebarOpen &&
    prevProps.notesCount === nextProps.notesCount &&
    prevProps.watchtowerStatus === nextProps.watchtowerStatus
  );
});
