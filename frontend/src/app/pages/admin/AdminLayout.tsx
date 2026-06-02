import { NavLink, Outlet } from 'react-router-dom';
import AdminGate from '../../../components/AdminGate';

const TABS: { to: string; label: string; end: boolean }[] = [
  { to: '/admin', label: 'Overview', end: true },
  { to: '/admin/billing', label: 'Billing', end: false },
  { to: '/admin/extraction-failures', label: 'Extraction', end: false },
];

/**
 * Shell for the Deptex-staff admin console. Gates the whole console once via
 * AdminGate (children no longer ping individually) and renders an app-style
 * header + underlined tab bar above the active page. New admin areas slot in
 * by adding a tab + a child route.
 */
export default function AdminLayout() {
  return (
    <AdminGate>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border bg-background">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="pt-6">
              <h1 className="text-2xl font-bold tracking-tight text-foreground">Admin</h1>
              <p className="mt-1 text-sm text-foreground-secondary">
                Platform console · all organizations
              </p>
            </div>
            <nav className="mt-5 flex items-center gap-6">
              {TABS.map((t) => (
                <NavLink
                  key={t.to}
                  to={t.to}
                  end={t.end}
                  className={({ isActive }) =>
                    `-mb-px border-b-2 pb-3 text-sm font-medium transition-colors ${
                      isActive
                        ? 'border-emerald-500 text-foreground'
                        : 'border-transparent text-foreground-secondary hover:text-foreground'
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
