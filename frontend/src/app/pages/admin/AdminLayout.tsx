import { NavLink, Outlet } from 'react-router-dom';
import AdminGate from '../../../components/AdminGate';

const TABS: { to: string; label: string; end: boolean }[] = [
  { to: '/admin', label: 'Overview', end: true },
  { to: '/admin/extraction-failures', label: 'Extraction', end: false },
];

/**
 * Shell for the Deptex-staff admin console. Gates the whole console once via
 * AdminGate (children no longer ping individually) and renders a top tab bar
 * above the active page. New admin areas slot in by adding a tab + a child route.
 */
export default function AdminLayout() {
  return (
    <AdminGate>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border bg-background-card">
          <div className="container mx-auto px-4 max-w-7xl">
            <div className="py-4">
              <h1 className="text-xl font-semibold text-foreground">Admin</h1>
              <p className="text-xs text-foreground-secondary">Deptex platform console</p>
            </div>
            <nav className="flex items-center gap-1 -mb-px">
              {TABS.map((t) => (
                <NavLink
                  key={t.to}
                  to={t.to}
                  end={t.end}
                  className={({ isActive }) =>
                    `px-3 py-2 text-sm font-medium border-b-2 transition-colors ${
                      isActive
                        ? 'border-primary text-foreground'
                        : 'border-transparent text-foreground-secondary hover:text-foreground hover:border-border'
                    }`
                  }
                >
                  {t.label}
                </NavLink>
              ))}
            </nav>
          </div>
        </header>
        <Outlet />
      </div>
    </AdminGate>
  );
}
