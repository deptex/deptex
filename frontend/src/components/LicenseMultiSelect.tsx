import { useState, useRef, useEffect } from 'react';
import { ChevronDown, Check, Search, X } from 'lucide-react';

export const AVAILABLE_LICENSES = [
  'No license',
  'Apache License 2.0',
  'GNU General Public License v3.0',
  'MIT License',
  'MIT No Attribution (MIT-0)',
  'ISC License',
  'BSD Zero Clause License (0BSD)',
  'BSD 2-Clause "Simplified" License',
  'BSD 3-Clause "New" or "Revised" License',
  'Blue Oak Model License 1.0.0',
  'Boost Software License 1.0',
  'Creative Commons Zero v1.0 Universal',
  'Creative Commons Attribution 4.0',
  'Eclipse Public License 2.0',
  'GNU Affero General Public License v3.0',
  'GNU General Public License v2.0',
  'GNU Lesser General Public License v2.1',
  'Mozilla Public License 2.0',
  'Python License 2.0',
  'The Unlicense',
];

interface LicenseMultiSelectProps {
  value: string[];
  onChange: (licenses: string[]) => void;
  excludeLicenses?: string[];
  availableLicenses?: string[];
  className?: string;
  placeholder?: string;
  variant?: 'default' | 'modal';
}

export function LicenseMultiSelect({
  value,
  onChange,
  excludeLicenses = [],
  availableLicenses: customAvailableLicenses,
  className = '',
  placeholder = 'Search licenses',
  variant = 'default',
}: LicenseMultiSelectProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        setSearchQuery('');
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Focus search input when dropdown opens
  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      setTimeout(() => {
        searchInputRef.current?.focus();
      }, 100);
    }
  }, [isOpen]);

  // Filter available licenses
  const baseLicenses = customAvailableLicenses || AVAILABLE_LICENSES;
  const availableLicenses = baseLicenses.filter(
    license => !excludeLicenses.includes(license)
  );

  // Filter by search query
  const filteredLicenses = availableLicenses.filter(license =>
    license.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleToggleLicense = (license: string) => {
    if (value.includes(license)) {
      onChange(value.filter(l => l !== license));
    } else {
      onChange([...value, license]);
    }
  };

  const handleRemoveLicense = (license: string, e: React.MouseEvent) => {
    e.stopPropagation();
    onChange(value.filter(l => l !== license));
  };

  const getDisplayText = () => {
    if (value.length === 0) {
      return placeholder;
    }
    if (value.length === 1) {
      return value[0];
    }
    return placeholder; // Don't show count when multiple selected
  };

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full px-3 py-2 border border-border rounded-md text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent flex items-center justify-between transition-colors ${variant === 'modal'
          ? 'bg-background hover:bg-background/80'
          : 'bg-background-card hover:bg-background-card/80'
          }`}
      >
        <span className="text-left truncate flex-1 mr-2">{getDisplayText()}</span>
        <ChevronDown
          className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform ${isOpen ? 'transform rotate-180' : ''
            }`}
        />
      </button>

      {/* Selected licenses as chips (when closed) */}
      {!isOpen && value.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-2">
          {value.map((license) => (
            <div
              key={license}
              className="inline-flex items-center gap-1 px-2 py-1 bg-background-card border border-border rounded-md text-xs text-foreground"
            >
              <span className="truncate max-w-[200px]">{license}</span>
              <button
                type="button"
                onClick={(e) => handleRemoveLicense(license, e)}
                className="hover:text-destructive transition-colors"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>
      )}

      {isOpen && (
        <div className="absolute z-50 w-full mt-2 bg-background-card border border-border rounded-md shadow-lg max-h-80 overflow-hidden flex flex-col">
          {/* Search bar */}
          <div className="p-2 border-b border-border">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
              <input
                ref={searchInputRef}
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={placeholder}
                className="w-full pl-8 pr-3 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>
          </div>

          {/* License list */}
          <div className="overflow-y-auto max-h-60">
            {filteredLicenses.length === 0 ? (
              <div className="px-3 py-4 text-sm text-foreground-secondary text-center">
                No licenses found
              </div>
            ) : (
              <div className="py-1">
                {filteredLicenses.map((license) => {
                  const isSelected = value.includes(license);
                  return (
                    <button
                      key={license}
                      type="button"
                      onClick={() => handleToggleLicense(license)}
                      className="w-full px-3 py-2 flex items-center justify-between hover:bg-table-hover transition-colors text-left"
                    >
                      <span className="text-sm text-foreground">{license}</span>
                      {isSelected && <Check className="h-4 w-4 text-white flex-shrink-0" />}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

