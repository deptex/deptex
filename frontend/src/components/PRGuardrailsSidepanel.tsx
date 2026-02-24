import { useState } from 'react';
import { X, AlertTriangle, Scale, Layers } from 'lucide-react';
import { ProjectPRGuardrails } from '../lib/api';
import { Button } from './ui/button';

interface PRGuardrailsSidepanelProps {
  guardrails: ProjectPRGuardrails;
  onSave: (data: Partial<ProjectPRGuardrails>) => Promise<void>;
  onCancel: () => void;
  isLoading?: boolean;
  projectName: string;
}

export function PRGuardrailsSidepanel({
  guardrails,
  onSave,
  onCancel,
  isLoading = false,
  projectName,
}: PRGuardrailsSidepanelProps) {
  // Vulnerability blocking
  const [blockCritical, setBlockCritical] = useState(guardrails.block_critical_vulns);
  const [blockHigh, setBlockHigh] = useState(guardrails.block_high_vulns);
  const [blockMedium, setBlockMedium] = useState(guardrails.block_medium_vulns);
  const [blockLow, setBlockLow] = useState(guardrails.block_low_vulns);

  // Policy and transitive
  const [blockPolicyViolations, setBlockPolicyViolations] = useState(guardrails.block_policy_violations);
  const [blockTransitiveVulns, setBlockTransitiveVulns] = useState(guardrails.block_transitive_vulns);

  const handleSave = async () => {
    await onSave({
      block_critical_vulns: blockCritical,
      block_high_vulns: blockHigh,
      block_medium_vulns: blockMedium,
      block_low_vulns: blockLow,
      block_policy_violations: blockPolicyViolations,
      block_transitive_vulns: blockTransitiveVulns,
    });
  };

  const hasChanges =
    blockCritical !== guardrails.block_critical_vulns ||
    blockHigh !== guardrails.block_high_vulns ||
    blockMedium !== guardrails.block_medium_vulns ||
    blockLow !== guardrails.block_low_vulns ||
    blockPolicyViolations !== guardrails.block_policy_violations ||
    blockTransitiveVulns !== guardrails.block_transitive_vulns;

  const Toggle = ({
    checked,
    onChange,
  }: {
    checked: boolean;
    onChange: (checked: boolean) => void;
  }) => (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background ${
        checked ? 'bg-primary' : 'bg-background-subtle'
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
          checked ? 'translate-x-4' : 'translate-x-0'
        }`}
      />
    </button>
  );

  return (
    <div className="fixed inset-0 z-50">
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={onCancel}
      />

      <div
        className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 py-5 border-b border-border flex items-center justify-between flex-shrink-0">
          <div>
            <h2 className="text-xl font-semibold text-foreground">PR Guardrails</h2>
            <p className="text-sm text-foreground-secondary mt-0.5">Configure merge blocking rules for {projectName}</p>
          </div>
          <button
            onClick={onCancel}
            className="text-foreground-secondary hover:text-foreground transition-colors"
            disabled={isLoading}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
          <div className="space-y-8">
            {/* Vulnerability Blocking Section */}
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-foreground-secondary" />
                <h3 className="text-base font-semibold text-foreground">Vulnerability Blocking</h3>
              </div>
              <p className="text-sm text-foreground-secondary">
                Block merging when new dependencies introduce vulnerabilities.
              </p>

              <div className="space-y-3">
                <div className="flex items-center justify-between py-1">
                  <div>
                    <span className="text-sm font-medium text-foreground">Critical</span>
                    <span className="text-xs text-red-500 ml-2">CVSS 9.0+</span>
                  </div>
                  <Toggle checked={blockCritical} onChange={setBlockCritical} />
                </div>

                <div className="flex items-center justify-between py-1">
                  <div>
                    <span className="text-sm font-medium text-foreground">High</span>
                    <span className="text-xs text-orange-500 ml-2">CVSS 7.0-8.9</span>
                  </div>
                  <Toggle checked={blockHigh} onChange={setBlockHigh} />
                </div>

                <div className="flex items-center justify-between py-1">
                  <div>
                    <span className="text-sm font-medium text-foreground">Medium</span>
                    <span className="text-xs text-amber-500 ml-2">CVSS 4.0-6.9</span>
                  </div>
                  <Toggle checked={blockMedium} onChange={setBlockMedium} />
                </div>

                <div className="flex items-center justify-between py-1">
                  <div>
                    <span className="text-sm font-medium text-foreground">Low</span>
                    <span className="text-xs text-blue-500 ml-2">CVSS 0.1-3.9</span>
                  </div>
                  <Toggle checked={blockLow} onChange={setBlockLow} />
                </div>
              </div>
            </div>

            {/* Block policy violations (license) */}
            <div className="space-y-4 pt-6 border-t border-border">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Scale className="h-5 w-5 text-foreground-secondary" />
                  <h3 className="text-base font-semibold text-foreground">Project policy (license)</h3>
                </div>
                <Toggle checked={blockPolicyViolations} onChange={setBlockPolicyViolations} />
              </div>
              <p className="text-sm text-foreground-secondary">
                Block when new dependencies don&apos;t comply with this project&apos;s policy (accepted licenses).
              </p>
            </div>

            {/* Block transitive vulnerabilities */}
            <div className="space-y-4 pt-6 border-t border-border">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers className="h-5 w-5 text-foreground-secondary" />
                  <h3 className="text-base font-semibold text-foreground">Transitive vulnerabilities</h3>
                </div>
                <Toggle checked={blockTransitiveVulns} onChange={setBlockTransitiveVulns} />
              </div>
              <p className="text-sm text-foreground-secondary">
                Block when new or updated transitive dependencies have vulnerabilities at the levels configured above.
                Also blocks if a new transitive has a license that doesn&apos;t comply with project policy.
              </p>
            </div>
          </div>
        </div>

        <div className="px-6 py-4 border-t border-border flex items-center justify-end gap-3 flex-shrink-0">
          <Button variant="outline" onClick={onCancel} disabled={isLoading}>
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            disabled={isLoading || !hasChanges}
          >
            {isLoading ? (
              <>
                <div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent"></div>
                Saving
              </>
            ) : (
              'Save Changes'
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
