import { useNavigate, useLocation } from 'react-router-dom';
import { ChevronLeft, Search, Settings, Link2 } from 'lucide-react';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from './ui/sidebar';
import { useAuth } from '../contexts/AuthContext';
import { useUserProfile } from '../hooks/useUserProfile';

const navItems = [
  { id: 'general', label: 'General', path: '/settings/general', icon: Settings },
  { id: 'connected-accounts', label: 'Connected Accounts', path: '/settings/general/connected-accounts', icon: Link2 },
];

export default function PersonalSettingsSidebar() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const { user } = useAuth();
  const { avatarUrl } = useUserProfile();
  const displayName = user?.user_metadata?.full_name || user?.email || 'Account';

  return (
    <Sidebar collapsible="none" className="border-r border-border">
      <SidebarHeader className="px-2 py-2">
        <button
          onClick={() => navigate('/organizations')}
          className="nav-btn relative w-full flex items-center justify-center h-9 rounded-md px-3 text-sm font-medium text-foreground-secondary hover:bg-background-subtle/75 hover:text-foreground transition-colors"
        >
          <ChevronLeft className="absolute left-3 h-5 w-5 tab-icon-shake" />
          <span>Account</span>
        </button>
      </SidebarHeader>

      <div className="px-2 pb-1">
        <button
          type="button"
          className="w-full flex items-center gap-2 px-3 h-9 rounded-md bg-background-subtle/50 border border-border/50 text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors text-left"
        >
          <Search className="h-4 w-4 flex-shrink-0" />
          <span className="text-sm flex-1">Find...</span>
          <kbd className="flex items-center justify-center h-5 w-5 rounded border border-border text-[10px] font-medium text-foreground-secondary bg-background">
            F
          </kbd>
        </button>
      </div>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = pathname === item.path;
                return (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={isActive}
                      onClick={() => navigate(item.path)}
                      aria-current={isActive ? 'page' : undefined}
                    >
                      <Icon className="tab-icon-shake" />
                      <span>{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      {user && (
        <SidebarFooter className="border-t border-border px-2 py-2">
          <div className="w-full flex items-center gap-2.5 h-9 px-1.5 rounded-md text-sm font-medium">
            <img
              src={avatarUrl}
              alt=""
              className="h-7 w-7 rounded-full object-cover border border-border flex-shrink-0"
              onError={(e) => { e.currentTarget.src = '/images/blank_profile_image.png'; }}
            />
            <span className="truncate min-w-0 text-foreground">{displayName}</span>
          </div>
        </SidebarFooter>
      )}
    </Sidebar>
  );
}
