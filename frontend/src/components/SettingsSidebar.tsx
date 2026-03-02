import { Link, useLocation } from 'react-router-dom';
import { Settings, Link2, Shield, Bell } from 'lucide-react';

export default function SettingsSidebar() {
  const { pathname } = useLocation();
  const isGeneral = pathname === '/settings/general';
  const isConnectedAccounts = pathname === '/settings/general/connected-accounts';
  const isSecurity = pathname === '/settings/security';
  const isNotifications = pathname === '/settings/notifications';

  return (
    <aside className="w-64 flex-shrink-0">
      <div className="sticky top-0 pt-8">
        <nav className="space-y-1">
          <Link
            to="/settings/general"
            className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors group ${
              isGeneral ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
            }`}
          >
            <Settings className="h-4 w-4 tab-icon-shake" />
            General
          </Link>
          <Link
            to="/settings/general/connected-accounts"
            className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors group ${
              isConnectedAccounts ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
            }`}
          >
            <Link2 className="h-4 w-4 tab-icon-shake" />
            Connected Accounts
          </Link>
          <Link
            to="/settings/security"
            className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors group ${
              isSecurity ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
            }`}
          >
            <Shield className="h-4 w-4 tab-icon-shake" />
            Security
          </Link>
          <Link
            to="/settings/notifications"
            className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors group ${
              isNotifications ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
            }`}
          >
            <Bell className="h-4 w-4 tab-icon-shake" />
            Notifications
          </Link>
        </nav>
      </div>
    </aside>
  );
}

