import { useState } from 'react';
import { Plus, Trash2, Tag, Zap, Send } from 'lucide-react';
import { Button } from '../../components/ui/button';
import { Switch } from '../../components/ui/switch';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '../../components/ui/sheet';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../../components/ui/select';
import { Slider } from '../../components/ui/slider';

type TriggerType = 'weekly_digest' | 'vulnerability_discovered' | 'custom_code_pipeline';
type IntegrationType = 'slack' | 'jira' | 'linear' | 'asana' | 'email';

interface NotificationRule {
  id: string;
  name: string;
  triggerType: TriggerType;
  minDepscoreThreshold?: number;
  customCode?: string;
  destinations: Array<{ integrationType: IntegrationType; targetId: string }>;
  active: boolean;
}

interface DestinationAction {
  id: string;
  integrationType: IntegrationType;
  targetId: string;
}

const TRIGGER_LABELS: Record<TriggerType, string> = {
  weekly_digest: 'Weekly Digest',
  vulnerability_discovered: 'Vulnerability Discovered',
  custom_code_pipeline: 'Custom Code Pipeline',
};

const INTEGRATION_LABELS: Record<IntegrationType, string> = {
  slack: 'Slack',
  jira: 'Jira',
  linear: 'Linear',
  asana: 'Asana',
  email: 'Email',
};

const MOCK_TARGETS: Record<IntegrationType, { id: string; label: string }[]> = {
  slack: [
    { id: '#security-alerts', label: '#security-alerts' },
    { id: '#engineering', label: '#engineering' },
    { id: '#devops', label: '#devops' },
  ],
  jira: [
    { id: 'project-a', label: 'Project A' },
    { id: 'project-b', label: 'Project B' },
  ],
  linear: [
    { id: 'frontend-board', label: 'Frontend Board' },
    { id: 'backend-board', label: 'Backend Board' },
  ],
  asana: [
    { id: 'engineering', label: 'Engineering' },
    { id: 'security', label: 'Security' },
  ],
  email: [
    { id: 'org-default', label: 'Organization default' },
    { id: 'team-leads', label: 'Team leads' },
  ],
};

function formatDestinations(destinations: NotificationRule['destinations']): string {
  return destinations
    .map(
      (d) =>
        `${INTEGRATION_LABELS[d.integrationType]} ${
          MOCK_TARGETS[d.integrationType]?.find((t) => t.id === d.targetId)?.label ?? d.targetId
        }`
    )
    .join(', ');
}

const MOCK_RULES: NotificationRule[] = [
  {
    id: '1',
    name: 'Critical Backend Alerts',
    triggerType: 'vulnerability_discovered',
    minDepscoreThreshold: 75,
    destinations: [
      { integrationType: 'slack', targetId: '#security-alerts' },
      { integrationType: 'email', targetId: 'org-default' },
    ],
    active: true,
  },
  {
    id: '2',
    name: 'Weekly Security Digest',
    triggerType: 'weekly_digest',
    destinations: [{ integrationType: 'slack', targetId: '#engineering' }],
    active: true,
  },
  {
    id: '3',
    name: 'High-Risk Frontend Issues',
    triggerType: 'custom_code_pipeline',
    customCode: 'return context.depscore > 80 && context.ecosystem === "npm";',
    destinations: [
      { integrationType: 'linear', targetId: 'frontend-board' },
      { integrationType: 'jira', targetId: 'project-a' },
    ],
    active: false,
  },
];

const DEFAULT_CUSTOM_CODE = `// Return true to trigger notification
function shouldNotify(context) {
  return context.depscore > 75;
}
return shouldNotify(context);
`;

export default function NotificationRulesSection() {
  const [rules, setRules] = useState<NotificationRule[]>(MOCK_RULES);
  const [createSheetOpen, setCreateSheetOpen] = useState(false);
  const [ruleName, setRuleName] = useState('');
  const [triggerType, setTriggerType] = useState<TriggerType>('weekly_digest');
  const [minDepscoreThreshold, setMinDepscoreThreshold] = useState(75);
  const [customCode, setCustomCode] = useState(DEFAULT_CUSTOM_CODE);
  const [destinations, setDestinations] = useState<DestinationAction[]>([
    { id: crypto.randomUUID(), integrationType: 'slack', targetId: '#security-alerts' },
  ]);

  const handleToggleActive = (ruleId: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === ruleId ? { ...r, active: !r.active } : r))
    );
  };

  const resetForm = () => {
    setRuleName('');
    setTriggerType('weekly_digest');
    setMinDepscoreThreshold(75);
    setCustomCode(DEFAULT_CUSTOM_CODE);
    setDestinations([
      { id: crypto.randomUUID(), integrationType: 'slack', targetId: '#security-alerts' },
    ]);
  };

  const handleCreateRule = () => {
    const newRule: NotificationRule = {
      id: crypto.randomUUID(),
      name: ruleName || 'Untitled Rule',
      triggerType,
      destinations: destinations.map(({ integrationType, targetId }) => ({
        integrationType,
        targetId,
      })),
      active: true,
    };
    if (triggerType === 'vulnerability_discovered') {
      newRule.minDepscoreThreshold = minDepscoreThreshold;
    }
    if (triggerType === 'custom_code_pipeline') {
      newRule.customCode = customCode;
    }
    setRules((prev) => [...prev, newRule]);
    resetForm();
    setCreateSheetOpen(false);
  };

  const addDestination = () => {
    const firstType: IntegrationType = 'slack';
    const firstTarget = MOCK_TARGETS[firstType]?.[0]?.id ?? '';
    setDestinations((prev) => [
      ...prev,
      { id: crypto.randomUUID(), integrationType: firstType, targetId: firstTarget },
    ]);
  };

  const removeDestination = (id: string) => {
    if (destinations.length <= 1) return;
    setDestinations((prev) => prev.filter((d) => d.id !== id));
  };

  const updateDestination = (id: string, field: 'integrationType' | 'targetId', value: string) => {
    setDestinations((prev) =>
      prev.map((d) => {
        if (d.id !== id) return d;
        if (field === 'integrationType') {
          const targets = MOCK_TARGETS[value as IntegrationType];
          const targetId = targets?.[0]?.id ?? '';
          return { ...d, integrationType: value as IntegrationType, targetId };
        }
        return { ...d, targetId: value };
      })
    );
  };

  const availableTargets = (integrationType: IntegrationType) =>
    MOCK_TARGETS[integrationType] ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Notification Rules</h2>
        <Button onClick={() => setCreateSheetOpen(true)}>
          <Plus className="h-4 w-4" />
          Create Rule
        </Button>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <table className="w-full table-fixed">
          <colgroup>
            <col className="w-[220px]" />
            <col className="w-[200px]" />
            <col />
            <col className="w-[100px]" />
          </colgroup>
          <thead className="bg-background-card-header border-b border-border">
            <tr>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Rule Name
              </th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Trigger Type
              </th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Destinations
              </th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rules.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-12 text-center text-sm text-foreground-secondary">
                  No notification rules. Create one to get started.
                </td>
              </tr>
            ) : (
              rules.map((rule) => (
                <tr key={rule.id} className="group hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-sm font-medium text-foreground">{rule.name}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-foreground-secondary">
                      {TRIGGER_LABELS[rule.triggerType]}
                      {rule.triggerType === 'vulnerability_discovered' &&
                        rule.minDepscoreThreshold != null && (
                          <span className="text-foreground-muted ml-1">
                            (&gt;{rule.minDepscoreThreshold})
                          </span>
                        )}
                    </span>
                  </td>
                  <td className="px-4 py-3 min-w-0">
                    <span className="text-sm text-foreground-secondary truncate block">
                      {formatDestinations(rule.destinations)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <Switch
                      checked={rule.active}
                      onCheckedChange={() => handleToggleActive(rule.id)}
                    />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <Sheet
        open={createSheetOpen}
        onOpenChange={(open) => {
          setCreateSheetOpen(open);
          if (!open) resetForm();
        }}
      >
        <SheetContent
          side="right"
          className="sm:max-w-lg w-full max-w-lg p-0 flex flex-col gap-0 border-l border-border"
        >
          <SheetHeader className="px-6 py-5 border-b border-border bg-background-card-header flex-shrink-0">
            <SheetTitle className="text-xl font-semibold text-foreground">
              Create Notification Rule
            </SheetTitle>
          </SheetHeader>

          <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
            <div className="space-y-6">
              {/* A. Rule Basics */}
              <div className="space-y-3">
                <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                  <Tag className="h-5 w-5 text-foreground-secondary" />
                  Rule Name
                </label>
                <input
                  type="text"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all"
                />
              </div>

              <div className="border-t border-border" />

              {/* B. Trigger */}
              <div className="space-y-3">
                <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                  <Zap className="h-5 w-5 text-foreground-secondary" />
                  Trigger Type
                </label>
                <Select
                  value={triggerType}
                  onValueChange={(v) => setTriggerType(v as TriggerType)}
                >
                  <SelectTrigger className="rounded-lg">
                    <SelectValue placeholder="Select trigger type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="weekly_digest">{TRIGGER_LABELS.weekly_digest}</SelectItem>
                    <SelectItem value="vulnerability_discovered">
                      {TRIGGER_LABELS.vulnerability_discovered}
                    </SelectItem>
                    <SelectItem value="custom_code_pipeline">
                      {TRIGGER_LABELS.custom_code_pipeline}
                    </SelectItem>
                  </SelectContent>
                </Select>

                {triggerType === 'vulnerability_discovered' && (
                  <div className="space-y-2 pt-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-foreground">
                        Minimum Depscore Threshold
                      </span>
                      <span className="text-sm text-foreground-muted">{minDepscoreThreshold}</span>
                    </div>
                    <Slider
                      min={0}
                      max={100}
                      value={minDepscoreThreshold}
                      onValueChange={setMinDepscoreThreshold}
                    />
                    <p className="text-xs text-foreground-muted">
                      Only alert if Depscore &gt; {minDepscoreThreshold}
                    </p>
                  </div>
                )}

                {triggerType === 'custom_code_pipeline' && (
                  <div className="space-y-2 pt-2">
                    <span className="text-sm font-medium text-foreground">Pipeline Code</span>
                    <textarea
                      className="font-mono text-sm bg-background-card text-foreground rounded-lg border border-border p-3 min-h-[120px] w-full resize-y focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all placeholder:text-foreground-secondary"
                      value={customCode}
                      onChange={(e) => setCustomCode(e.target.value)}
                    />
                  </div>
                )}
              </div>

              <div className="border-t border-border" />

              {/* C. Destinations */}
              <div className="space-y-3">
                <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                  <Send className="h-5 w-5 text-foreground-secondary" />
                  Destinations
                </label>
                <div className="space-y-3">
                  {destinations.map((dest) => (
                    <div key={dest.id} className="flex gap-2 items-start">
                      <Select
                        value={dest.integrationType}
                        onValueChange={(v) => updateDestination(dest.id, 'integrationType', v)}
                      >
                        <SelectTrigger className="flex-1 min-w-0 rounded-lg">
                          <SelectValue placeholder="Integration" />
                        </SelectTrigger>
                        <SelectContent>
                          {(Object.keys(INTEGRATION_LABELS) as IntegrationType[]).map((type) => (
                            <SelectItem key={type} value={type}>
                              {INTEGRATION_LABELS[type]}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Select
                        value={dest.targetId}
                        onValueChange={(v) => updateDestination(dest.id, 'targetId', v)}
                      >
                        <SelectTrigger className="flex-1 min-w-0 rounded-lg">
                          <SelectValue placeholder="Target" />
                        </SelectTrigger>
                        <SelectContent>
                          {availableTargets(dest.integrationType).map((t) => (
                            <SelectItem key={t.id} value={t.id}>
                              {t.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="h-9 w-9 shrink-0 text-foreground-secondary hover:text-destructive rounded-lg"
                        onClick={() => removeDestination(dest.id)}
                        disabled={destinations.length <= 1}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>
                <Button type="button" variant="outline" size="sm" onClick={addDestination} className="rounded-lg">
                  <Plus className="h-4 w-4" />
                  Add destination
                </Button>
              </div>
            </div>
          </div>

          <div className="px-6 py-4 border-t border-border flex items-center justify-end gap-3 flex-shrink-0">
            <Button variant="outline" onClick={() => setCreateSheetOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateRule}>Create Rule</Button>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
