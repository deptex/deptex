import { Settings, CreditCard, Key } from 'lucide-react';

interface SettingsSidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
}

const settingsSections = [
  {
    id: 'general',
    label: 'General',
    icon: <Settings className="h-4 w-4 tab-icon-shake" />,
  },
  {
    id: 'billing',
    label: 'Billing Information',
    icon: <CreditCard className="h-4 w-4 tab-icon-shake" />,
  },
  {
    id: 'authentication',
    label: 'Connected Accounts',
    icon: <Key className="h-4 w-4 tab-icon-shake" />,
  },
];

export default function SettingsSidebar({ activeSection, onSectionChange }: SettingsSidebarProps) {
  return (
    <aside className="w-64 flex-shrink-0">
      <div className="sticky top-0 pt-8">
        <nav className="space-y-1">
          {settingsSections.map((section) => (
            <button
              key={section.id}
              onClick={() => onSectionChange(section.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors group ${activeSection === section.id
                ? 'text-foreground'
                : 'text-foreground-secondary hover:text-foreground'
                }`}
            >
              {section.icon}
              {section.label}
            </button>
          ))}
        </nav>
      </div>
    </aside>
  );
}

