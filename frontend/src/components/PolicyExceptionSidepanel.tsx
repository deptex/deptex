import { useState, useEffect, useRef } from 'react';
import { SendHorizontal, AlertCircle, ChevronDown, Check, FileWarning } from 'lucide-react';
import { LicenseMultiSelect, AVAILABLE_LICENSES } from './LicenseMultiSelect';
import { OrganizationPolicies, api } from '../lib/api';
import { Button } from './ui/button';

interface PolicyExceptionSidepanelProps {
  currentPolicies: OrganizationPolicies;
  onSubmit: (data: {
    reason: string;
    additional_licenses?: string[];
    slsa_enforcement?: string | null;
    slsa_level?: number | null;
  }) => Promise<void>;
  onCancel: () => void;
  isLoading?: boolean;
  projectName: string;
}

export function PolicyExceptionSidepanel({
  currentPolicies,
  onSubmit,
  onCancel,
  isLoading = false,
  projectName,
}: PolicyExceptionSidepanelProps) {
  const [additionalLicenses, setAdditionalLicenses] = useState<string[]>([]);
  const [slsaOverride, setSlsaOverride] = useState(false);
  const [slsaEnforcement, setSlsaEnforcement] = useState<OrganizationPolicies['slsa_enforcement']>('none');
  const [slsaLevel, setSlsaLevel] = useState<number | null>(null);
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);

  const [slsaLevelOpen, setSlsaLevelOpen] = useState(false);
  const slsaLevelRef = useRef<HTMLDivElement>(null);

  // Filter out already accepted licenses
  const acceptedLicenses = currentPolicies.accepted_licenses ?? [];
  const availableLicensesForException = AVAILABLE_LICENSES.filter(
    license => !acceptedLicenses.includes(license)
  );

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (slsaLevelRef.current && !slsaLevelRef.current.contains(event.target as Node)) {
        setSlsaLevelOpen(false);
      }
    };

    if (slsaLevelOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [slsaLevelOpen]);

  const handleSubmit = async () => {
    if (!reason.trim()) {
      setError('Please provide a reason for your exception request');
      return;
    }

    if (additionalLicenses.length === 0 && !slsaOverride) {
      setError('Please select at least one license exception or SLSA override');
      return;
    }

    setError(null);

    const data: any = {
      reason: reason.trim(),
    };

    if (additionalLicenses.length > 0) {
      data.additional_licenses = additionalLicenses;
    }

    if (slsaOverride) {
      data.slsa_enforcement = slsaEnforcement;
      if (slsaEnforcement === 'recommended') {
        data.slsa_level = slsaLevel || 1;
      }
    }

    try {
      await onSubmit(data);
    } catch (err: any) {
      setError(err.message || 'Failed to submit exception request');
    }
  };

  return (
    <div className="fixed inset-0 z-50">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={onCancel}
      />

      {/* Side Panel */}
      <div
        className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-5 border-b border-border flex items-center gap-3 flex-shrink-0">
          <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center shrink-0">
            <FileWarning className="h-4 w-4 text-amber-500" />
          </div>
          <div className="min-w-0">
            <h2 className="text-lg font-semibold text-foreground">Apply for Exception</h2>
            <p className="text-sm text-foreground-secondary mt-0.5 truncate">Request policy exceptions for {projectName}</p>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
          <div className="space-y-6">
            {/* Info Banner */}
            <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4 flex items-start gap-3">
              <FileWarning className="h-5 w-5 text-amber-500 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-medium text-foreground">Exception requests require approval</h4>
                <p className="text-xs text-foreground-secondary mt-1">
                  Your request will be sent to organization administrators for review. You'll be notified once it's approved or rejected.
                </p>
              </div>
            </div>

            {/* Error message */}
            {error && (
              <div className="bg-destructive/10 border border-destructive/20 rounded-md p-3 flex items-start gap-2">
                <AlertCircle className="h-5 w-5 text-destructive flex-shrink-0 mt-0.5" />
                <p className="text-sm text-destructive">{error}</p>
              </div>
            )}

            {/* Additional Licenses */}
            <div className="space-y-3">
              <div>
                <h3 className="text-base font-semibold text-foreground mb-1">Additional Licenses</h3>
                <p className="text-sm text-foreground-secondary">
                  Select licenses you need that aren't currently allowed by organization policy.
                </p>
              </div>

              {availableLicensesForException.length > 0 ? (
                <>
                  <LicenseMultiSelect
                    value={additionalLicenses}
                    onChange={setAdditionalLicenses}
                    placeholder="Search licenses to request..."
                    variant="default"
                    availableLicenses={availableLicensesForException}
                  />
                  {additionalLicenses.length > 0 && (
                    <p className="text-xs text-foreground-secondary">
                      {additionalLicenses.length} license{additionalLicenses.length !== 1 ? 's' : ''} selected for exception
                    </p>
                  )}
                </>
              ) : (
                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-3">
                  <p className="text-sm text-green-600 dark:text-green-400">
                    All available licenses are already accepted by the organization policy.
                  </p>
                </div>
              )}
            </div>

            {/* SLSA Override */}
            <div className="space-y-3 pt-4 border-t border-border">
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  id="slsa-override"
                  checked={slsaOverride}
                  onChange={(e) => setSlsaOverride(e.target.checked)}
                  className="mt-1 h-4 w-4 rounded border-border text-primary focus:ring-primary"
                />
                <label htmlFor="slsa-override" className="flex-1 cursor-pointer">
                  <span className="text-base font-semibold text-foreground">Request SLSA Override</span>
                  <p className="text-sm text-foreground-secondary mt-0.5">
                    Request different SLSA requirements for this project than the organization default.
                  </p>
                </label>
              </div>

              {slsaOverride && (
                <div className="ml-7 space-y-3 animate-in fade-in slide-in-from-top-2">
                  <div className="space-y-2">
                    {[
                      { value: 'none', label: 'No SLSA enforcement' },
                      { value: 'recommended', label: 'Recommended SLSA level' },
                      { value: 'require_provenance', label: 'Require provenance' },
                      { value: 'require_attestations', label: 'Require build attestations' },
                      { value: 'require_signed', label: 'Require signed artifacts' },
                    ].map((option) => (
                      <div key={option.value}>
                        <button
                          type="button"
                          onClick={() => {
                            setSlsaEnforcement(option.value as any);
                            if (option.value === 'recommended') {
                              if (!slsaLevel) setSlsaLevel(1);
                            } else {
                              setSlsaLevel(null);
                            }
                          }}
                          className={`w-full px-4 py-3 border rounded-lg flex items-center justify-between text-left transition-all ${slsaEnforcement === option.value
                            ? 'bg-primary/5 border-primary ring-1 ring-primary'
                            : 'bg-background-card border-border hover:border-foreground-secondary/50'
                          }`}
                        >
                          <span className={`text-sm ${slsaEnforcement === option.value ? 'font-medium text-foreground' : 'text-foreground'}`}>
                            {option.label}
                          </span>
                          {slsaEnforcement === option.value && (
                            <Check className="h-5 w-5 text-primary" />
                          )}
                        </button>

                        {option.value === 'recommended' && slsaEnforcement === 'recommended' && (
                          <div className="mt-2 ml-1 animate-in fade-in slide-in-from-top-1 px-3 py-2 border-l-2 border-primary/20">
                            <label className="text-xs text-foreground-secondary mb-1.5 block">Required SLSA Level</label>
                            <div className="relative" ref={slsaLevelRef}>
                              <button
                                type="button"
                                onClick={() => setSlsaLevelOpen(!slsaLevelOpen)}
                                className={`w-full max-w-[200px] px-3 py-2 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary flex items-center justify-between transition-all bg-background-card hover:border-foreground-secondary/30 ${slsaLevelOpen ? 'ring-2 ring-primary/50 border-primary' : ''}`}
                              >
                                <span className="text-left">Level {slsaLevel || 1}</span>
                                <ChevronDown className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform duration-200 ${slsaLevelOpen ? 'rotate-180' : ''}`} />
                              </button>

                              {slsaLevelOpen && (
                                <div className="absolute z-50 mt-1.5 w-full max-w-[200px] bg-background-card border border-border rounded-lg shadow-xl overflow-hidden animate-in fade-in-0 zoom-in-95 duration-100">
                                  <div className="py-1">
                                    {[1, 2, 3, 4].map((level) => (
                                      <button
                                        key={level}
                                        type="button"
                                        onClick={() => { setSlsaLevel(level); setSlsaLevelOpen(false); }}
                                        className="w-full px-3 py-2.5 flex items-center justify-between hover:bg-background-subtle/20 transition-colors text-left text-sm text-foreground"
                                      >
                                        Level {level}
                                        {slsaLevel === level && <Check className="h-4 w-4 text-primary" />}
                                      </button>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Reason */}
            <div className="space-y-3 pt-4 border-t border-border">
              <div>
                <h3 className="text-base font-semibold text-foreground mb-1">
                  Reason <span className="text-destructive">*</span>
                </h3>
                <p className="text-sm text-foreground-secondary">
                  Explain why this project needs these exceptions.
                </p>
              </div>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="e.g., This is an internal tool that doesn't distribute code publicly, so GPL dependencies are acceptable..."
                className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary h-32 resize-none"
              />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0">
          <Button variant="outline" onClick={onCancel} disabled={isLoading}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={isLoading || !reason.trim() || (additionalLicenses.length === 0 && !slsaOverride)}
            className="bg-primary text-primary-foreground hover:bg-primary/90"
          >
            {isLoading ? (
              <div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent" />
            ) : (
              <SendHorizontal className="h-4 w-4 mr-2" />
            )}
            Submit Request
          </Button>
        </div>
      </div>
    </div>
  );
}
