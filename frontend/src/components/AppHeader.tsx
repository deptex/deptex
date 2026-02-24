import { Fragment } from 'react';
import { User, HelpCircle, Settings, LogOut, BookOpen, Mail, Search, Plus, ChevronRight } from 'lucide-react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useUserProfile } from '../hooks/useUserProfile';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import { Button } from './ui/button';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';

interface BreadcrumbItem {
  label: string;
  path?: string;
}

interface AppHeaderProps {
  breadcrumb: BreadcrumbItem[];
  showSearch?: boolean;
  showNewOrg?: boolean;
  customLeftContent?: React.ReactNode;
}

export default function AppHeader({ breadcrumb, showSearch = false, showNewOrg = false, customLeftContent }: AppHeaderProps) {
  const { avatarUrl } = useUserProfile();
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const isOrganizationsPage = location.pathname === '/organizations';
  const isOrganizationDetailPage = location.pathname.startsWith('/organizations/') && location.pathname !== '/organizations';
  // Only remove border on organization detail pages (where tabs are shown)
  const showBorder = !isOrganizationDetailPage;

  return (
    <header className={`bg-background ${showBorder ? 'border-b border-border' : ''}`}>
      <div className="mx-auto w-full">
        <div className="flex h-12 items-center justify-between px-6">
          {/* Left side: Logo + Breadcrumb */}
          <div className="flex items-center gap-3">
            {customLeftContent ? (
              customLeftContent
            ) : (
              <nav className="flex items-center gap-2 text-sm">
                {isOrganizationsPage ? (
                  <img
                    src="/images/logo.png"
                    alt="Deptex"
                    className="h-8 w-8"
                  />
                ) : (
                  <Link to="/organizations" className="flex items-center hover:opacity-80 transition-opacity">
                    <img
                      src="/images/logo.png"
                      alt="Deptex"
                      className="h-8 w-8"
                    />
                  </Link>
                )}
                {breadcrumb.map((item, index) => (
                  <Fragment key={index}>
                    <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                    {item.path ? (
                      <Link to={item.path} className="text-muted-foreground font-medium hover:text-foreground transition-colors truncate max-w-[140px]">
                        {item.label}
                      </Link>
                    ) : (
                      <span className="text-foreground font-medium truncate">{item.label}</span>
                    )}
                  </Fragment>
                ))}
              </nav>
            )}
          </div>

          {/* Right side: Actions */}
          <div className="flex items-center gap-4">
            {/* Search bar (optional) */}
            {showSearch && (
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                <input
                  type="text"
                  placeholder="Find..."
                  className="pl-9 pr-4 py-1.5 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent w-48"
                />
              </div>
            )}

            {/* New organization button (optional) */}
            {showNewOrg && (
              <Button
                onClick={() => navigate('/organizations')}
                className="bg-primary text-primary-foreground hover:bg-primary/90 h-9"
              >
                <Plus className="h-4 w-4 mr-2" />
                New organization
              </Button>
            )}

            {/* Help dropdown */}
            <DropdownMenu>
              <Tooltip>
                <TooltipTrigger asChild>
                  <DropdownMenuTrigger asChild>
                    <button className="flex items-center justify-center rounded-md p-2 text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors">
                      <HelpCircle className="h-5 w-5" />
                    </button>
                  </DropdownMenuTrigger>
                </TooltipTrigger>
                <TooltipContent side="bottom">Help and support</TooltipContent>
              </Tooltip>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuLabel>Help & Support</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <a href="/docs" target="_blank" rel="noopener noreferrer" className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
                    <BookOpen className="h-4 w-4" />
                    Docs
                  </a>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a href="/support" target="_blank" rel="noopener noreferrer" className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
                    <Mail className="h-4 w-4" />
                    Contact Support
                  </a>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Profile dropdown */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center justify-center rounded-full border border-border bg-background-subtle overflow-hidden hover:bg-background-card transition-colors">
                  <img
                    src={avatarUrl}
                    alt={user?.email || 'User'}
                    className="h-8 w-8 rounded-full object-cover"
                    onError={(e) => {
                      e.currentTarget.src = '/images/blank_profile_image.png';
                    }}
                  />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-72">
                <DropdownMenuLabel className="p-0">
                  <div className="flex items-center gap-3 px-2 py-3">
                    <div className="flex-shrink-0">
                      <img
                        src={avatarUrl}
                        alt={user?.email || 'User'}
                        className="h-10 w-10 rounded-full object-cover border border-border"
                        onError={(e) => {
                          e.currentTarget.src = '/images/blank_profile_image.png';
                        }}
                      />
                    </div>
                    <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                      {user?.user_metadata?.full_name && (
                        <span className="text-sm font-medium text-foreground truncate">{user.user_metadata.full_name}</span>
                      )}
                      <span className="text-xs text-foreground-secondary truncate">{user?.email}</span>
                    </div>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link to="/settings" className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
                    <Settings className="h-4 w-4" />
                    Settings
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={async () => {
                    await signOut();
                    navigate('/');
                  }}
                  className="cursor-pointer text-foreground-secondary hover:text-foreground focus:bg-transparent focus:text-foreground flex items-center gap-2 transition-colors"
                >
                  <LogOut className="h-4 w-4" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </div>
    </header>
  );
}

