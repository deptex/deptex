import React, { useState, useEffect, useCallback } from 'react';
import {
  Settings2, DollarSign, Zap, Brain, BookOpen,
  BarChart3, FileText, Search, Plus, Trash2, Edit2, Download, Pause,
  MoreHorizontal, Clock,
} from 'lucide-react';
import { RolePermissions } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Input } from '../ui/input';
import { Switch } from '../ui/switch';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Label } from '../ui/label';
import { useToast } from '../../hooks/use-toast';
import { LearningDashboard } from './LearningDashboard';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface AegisManagementConsoleProps {
  organizationId: string;
  userPermissions?: RolePermissions | null;
}

type OperatingMode = 'read_only' | 'propose' | 'autopilot';

async function fetchWithAuth(url: string, options: RequestInit = {}) {
  const { data: { session } } = await supabase.auth.getSession();
  const res = await fetch(`${API_BASE_URL}${url}`, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${session?.access_token}`,
      'Content-Type': 'application/json',
    },
  });
  return res.json().catch(() => ({}));
}

const TOOL_CATEGORIES = [
  { id: 'security', label: 'Security', tools: ['getProjectVulnerabilities', 'explainVulnerability', 'triggerAiFix', 'analyzeReachability'] },
  { id: 'teams', label: 'Teams', tools: ['listTeams', 'addMemberToTeam', 'moveAllMembers'] },
  { id: 'members', label: 'Members', tools: ['listMembers'] },
  { id: 'policies', label: 'Policies', tools: ['listPolicies', 'getPolicy'] },
  { id: 'projects', label: 'Projects', tools: ['listProjects', 'getProjectOverview'] },
  { id: 'automations', label: 'Automations', tools: ['listAutomations', 'runAutomation'] },
  { id: 'integrations', label: 'Integrations', tools: ['listIntegrations'] },
  { id: 'reporting', label: 'Reporting', tools: ['generateSecurityReport'] },
  { id: 'memory', label: 'Memory', tools: ['storeMemory', 'retrieveMemory'] },
  { id: 'external', label: 'External', tools: ['webSearch', 'fetchUrl'] },
];

const TABS = [
  { id: 'configuration', label: 'Configuration', icon: Settings2 },
  { id: 'spending', label: 'Spending', icon: DollarSign },
  { id: 'automations', label: 'Automations', icon: Zap },
  { id: 'memory', label: 'Memory', icon: Brain },
  { id: 'learning', label: 'Learning', icon: BookOpen },
  { id: 'usage', label: 'Usage', icon: BarChart3 },
  { id: 'audit', label: 'Audit Log', icon: FileText },
];

function SkeletonRow({ cols = 4 }: { cols?: number }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-muted animate-pulse rounded w-3/4" />
        </td>
      ))}
    </tr>
  );
}

export function AegisManagementConsole({ organizationId, userPermissions }: AegisManagementConsoleProps) {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<string>('configuration');
  const [operatingMode, setOperatingMode] = useState<OperatingMode>('read_only');
  const [toolPermissions, setToolPermissions] = useState<Record<string, boolean>>({});
  const [prReviewMode, setPrReviewMode] = useState<string>('advisory');

  // Settings
  const [settings, setSettings] = useState<any>(null);
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [savingSettings, setSavingSettings] = useState(false);

  // Tasks
  const [tasks, setTasks] = useState<any[]>([]);
  const [loadingTasks, setLoadingTasks] = useState(false);

  // Approvals
  const [approvals, setApprovals] = useState<any[]>([]);
  const [loadingApprovals, setLoadingApprovals] = useState(false);

  // Memories
  const [memories, setMemories] = useState<any[]>([]);
  const [loadingMemories, setLoadingMemories] = useState(false);
  const [memorySearch, setMemorySearch] = useState('');
  const [memoryCategory, setMemoryCategory] = useState<string>('all');

  // Automations
  const [automations, setAutomations] = useState<any[]>([]);
  const [loadingAutomations, setLoadingAutomations] = useState(false);

  // Tool executions (audit)
  const [toolExecutions, setToolExecutions] = useState<any[]>([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditFilter, setAuditFilter] = useState<string>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  // Spending
  const [spending, setSpending] = useState<any>(null);
  const [loadingSpending, setLoadingSpending] = useState(false);
  const [monthlyBudget, setMonthlyBudget] = useState('');
  const [dailyBudget, setDailyBudget] = useState('');
  const [perTaskBudget, setPerTaskBudget] = useState('');

  // Usage
  const [usage, setUsage] = useState<any>(null);
  const [loadingUsage, setLoadingUsage] = useState(false);

  const loadSettings = useCallback(async () => {
    setLoadingSettings(true);
    try {
      const data = await fetchWithAuth(`/api/aegis/settings/${organizationId}`);
      if (data && !data.error) {
        setSettings(data);
        setOperatingMode((data.operating_mode as OperatingMode) || 'read_only');
        setMonthlyBudget(data.monthly_budget != null ? String(data.monthly_budget) : '');
        setDailyBudget(data.daily_budget != null ? String(data.daily_budget) : '');
        setPerTaskBudget(data.per_task_budget != null ? String(data.per_task_budget) : '');
        setPrReviewMode(data.pr_review_mode ?? 'advisory');
        const perms = data.tool_permissions && typeof data.tool_permissions === 'object' ? data.tool_permissions : {};
        const merged: Record<string, boolean> = {};
        TOOL_CATEGORIES.forEach((cat) => {
          merged[cat.id] = perms[cat.id] !== false;
        });
        setToolPermissions(merged);
      }
    } catch {
      toast({ title: 'Failed to load Aegis settings', variant: 'destructive' });
    } finally {
      setLoadingSettings(false);
    }
  }, [organizationId, toast]);

  const saveSettings = async () => {
    setSavingSettings(true);
    try {
      await fetchWithAuth(`/api/aegis/settings/${organizationId}`, {
        method: 'PUT',
        body: JSON.stringify({
          operating_mode: operatingMode,
          monthly_budget: monthlyBudget ? Number(monthlyBudget) : null,
          daily_budget: dailyBudget ? Number(dailyBudget) : null,
          per_task_budget: perTaskBudget ? Number(perTaskBudget) : null,
          tool_permissions: toolPermissions,
          pr_review_mode: prReviewMode,
          ...settings,
        }),
      });
      toast({ title: 'Settings saved' });
    } catch {
      toast({ title: 'Failed to save settings', variant: 'destructive' });
    } finally {
      setSavingSettings(false);
    }
  };

  const loadTasks = useCallback(async () => {
    setLoadingTasks(true);
    try {
      const data = await fetchWithAuth(`/api/aegis/tasks/${organizationId}`);
      setTasks(Array.isArray(data) ? data : data?.tasks ?? []);
    } catch {
      setTasks([]);
    } finally {
      setLoadingTasks(false);
    }
  }, [organizationId]);

  const loadApprovals = useCallback(async () => {
    setLoadingApprovals(true);
    try {
      const data = await fetchWithAuth(`/api/aegis/approvals/${organizationId}`);
      setApprovals(Array.isArray(data) ? data : data?.approvals ?? []);
    } catch {
      setApprovals([]);
    } finally {
      setLoadingApprovals(false);
    }
  }, [organizationId]);

  const handleApprove = async (id: string) => {
    try {
      await fetchWithAuth(`/api/aegis/approvals/${organizationId}/approve`, {
        method: 'POST',
        body: JSON.stringify({ approval_id: id }),
      });
      loadApprovals();
    } catch {
      toast({ title: 'Failed to approve', variant: 'destructive' });
    }
  };

  const handleReject = async (id: string) => {
    try {
      await fetchWithAuth(`/api/aegis/approvals/${organizationId}/reject`, {
        method: 'POST',
        body: JSON.stringify({ approval_id: id }),
      });
      loadApprovals();
    } catch {
      toast({ title: 'Failed to reject', variant: 'destructive' });
    }
  };

  const loadMemories = useCallback(async () => {
    setLoadingMemories(true);
    try {
      const data = await fetchWithAuth(`/api/aegis/memory/${organizationId}`);
      setMemories(Array.isArray(data) ? data : data?.memories ?? []);
    } catch {
      setMemories([]);
    } finally {
      setLoadingMemories(false);
    }
  }, [organizationId]);

  const loadAutomations = useCallback(async () => {
    setLoadingAutomations(true);
    try {
      const data = await fetchWithAuth(`/api/aegis/automations/${organizationId}`);
      setAutomations(Array.isArray(data) ? data : data?.automations ?? []);
    } catch {
      setAutomations([]);
    } finally {
      setLoadingAutomations(false);
    }
  }, [organizationId]);

  const toggleAutomation = async (id: string, enabled: boolean) => {
    try {
      await fetchWithAuth(`/api/aegis/automations/${organizationId}/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      });
      loadAutomations();
    } catch {
      toast({ title: 'Failed to update automation', variant: 'destructive' });
    }
  };

  const loadToolExecutions = useCallback(async () => {
    setLoadingAudit(true);
    try {
      const data = await fetchWithAuth(`/api/aegis/tool-executions/${organizationId}`);
      setToolExecutions(Array.isArray(data) ? data : data?.executions ?? []);
    } catch {
      setToolExecutions([]);
    } finally {
      setLoadingAudit(false);
    }
  }, [organizationId]);

  const loadSpending = useCallback(async () => {
    setLoadingSpending(true);
    try {
      const data = await fetchWithAuth(`/api/aegis/spending/${organizationId}`);
      setSpending(data);
      if (data?.monthly_budget != null) setMonthlyBudget(String(data.monthly_budget));
      if (data?.daily_budget != null) setDailyBudget(String(data.daily_budget));
      if (data?.per_task_budget != null) setPerTaskBudget(String(data.per_task_budget));
    } catch {
      setSpending(null);
    } finally {
      setLoadingSpending(false);
    }
  }, [organizationId]);

  const loadUsage = useCallback(async () => {
    setLoadingUsage(true);
    try {
      const data = await fetchWithAuth(`/api/aegis/usage-stats/${organizationId}`);
      setUsage(data);
    } catch {
      setUsage(null);
    } finally {
      setLoadingUsage(false);
    }
  }, [organizationId]);

  useEffect(() => { loadSettings(); }, [loadSettings]);
  useEffect(() => {
    if (activeTab === 'memory') loadMemories();
  }, [activeTab, loadMemories]);
  useEffect(() => {
    if (activeTab === 'automations') loadAutomations();
  }, [activeTab, loadAutomations]);
  useEffect(() => {
    if (activeTab === 'audit') loadToolExecutions();
  }, [activeTab, loadToolExecutions]);
  useEffect(() => {
    if (activeTab === 'spending') loadSpending();
  }, [activeTab, loadSpending]);
  useEffect(() => {
    if (activeTab === 'usage') loadUsage();
  }, [activeTab, loadUsage]);

  const exportAuditCsv = () => {
    const headers = ['Timestamp', 'Tool', 'Status', 'Duration (ms)', 'User'];
    const rows = (toolExecutions || []).map((e: any) => [
      e.timestamp ?? e.created_at ?? '',
      e.tool_name ?? '',
      e.status ?? '',
      e.duration_ms ?? '',
      e.user_email ?? e.user_id ?? '',
    ]);
    const csv = [headers.join(','), ...rows.map((r: any[]) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `aegis-audit-${organizationId}.csv`;
    a.click();
  };

  const filteredMemories = memories.filter((m: any) => {
    const matchSearch = !memorySearch || (m.key?.toLowerCase?.() || '').includes(memorySearch.toLowerCase()) ||
      (m.content?.toLowerCase?.() || '').includes(memorySearch.toLowerCase());
    const matchCat = memoryCategory === 'all' || (m.category ?? 'general') === memoryCategory;
    return matchSearch && matchCat;
  });

  const filteredExecutions = (toolExecutions || []).filter((e: any) => {
    if (auditFilter === 'all') return true;
    return (e.status ?? e.tool_name) === auditFilter;
  });

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-foreground">Aegis</h2>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border overflow-x-auto">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px whitespace-nowrap transition-colors ${
                activeTab === tab.id
                  ? 'border-foreground text-foreground'
                  : 'border-transparent text-foreground-secondary hover:text-foreground'
              }`}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div className="mt-6">
        {activeTab === 'configuration' && (
          <div className="space-y-8">
            {loadingSettings ? (
              <div className="space-y-4">
                <div className="h-10 bg-muted animate-pulse rounded w-48" />
                <div className="h-32 bg-muted animate-pulse rounded" />
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <Label className="text-foreground">Operating mode</Label>
                  <Select value={operatingMode} onValueChange={(v) => setOperatingMode(v as OperatingMode)}>
                    <SelectTrigger className="w-full max-w-xs bg-background-card border-border">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="read_only">Read-Only — Aegis only answers, no actions</SelectItem>
                      <SelectItem value="propose">Propose — Aegis suggests actions for your approval</SelectItem>
                      <SelectItem value="autopilot">Autopilot — Aegis can run approved actions automatically</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label className="text-foreground">Tool categories</Label>
                  <p className="text-sm text-foreground-secondary">
                    Allow or block entire tool categories. Disabled categories are hidden from Aegis.
                  </p>
                  <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
                    {TOOL_CATEGORIES.map((cat) => (
                      <label
                        key={cat.id}
                        className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-table-hover transition-colors"
                      >
                        <span className="font-medium text-foreground">{cat.label}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-foreground-secondary">{cat.tools.length} tools</span>
                          <Switch
                            checked={toolPermissions[cat.id] !== false}
                            onCheckedChange={(checked) => setToolPermissions((p) => ({ ...p, [cat.id]: checked }))}
                          />
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                <p className="text-sm text-foreground-secondary">
                  Aegis uses your organization&apos;s AI provider. Configure providers in <strong>AI Configuration</strong>.
                </p>

                <div className="space-y-2">
                  <Label className="text-foreground">PR review</Label>
                  <Select value={prReviewMode} onValueChange={setPrReviewMode}>
                    <SelectTrigger className="w-full max-w-xs bg-background-card border-border">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="advisory">Advisory — Comment on PRs only, do not block merge</SelectItem>
                      <SelectItem value="blocking">Blocking — Block merge when policy or security checks fail</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button onClick={saveSettings} disabled={savingSettings}>
                  {savingSettings ? 'Saving…' : 'Save configuration'}
                </Button>
              </>
            )}
          </div>
        )}

        {activeTab === 'spending' && (
          <div className="space-y-6">
            <div className="grid gap-4 md:grid-cols-3">
              {loadingSpending ? (
                <>
                  {[1, 2, 3].map((i) => (
                    <Card key={i} className="bg-background-card border-border">
                      <CardContent className="pt-6">
                        <div className="h-16 bg-muted animate-pulse rounded" />
                      </CardContent>
                    </Card>
                  ))}
                </>
              ) : (
                <>
                  <Card className="bg-background-card border-border">
                    <CardHeader>
                      <CardTitle className="text-foreground text-base">Monthly Budget</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-2xl font-semibold text-primary">
                        ${spending?.monthly_spent ?? 0}
                      </p>
                      <p className="text-foreground-secondary text-sm">of ${spending?.monthly_budget ?? '—'} limit</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-background-card border-border">
                    <CardHeader>
                      <CardTitle className="text-foreground text-base">Daily Budget</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-2xl font-semibold">${spending?.daily_spent ?? 0}</p>
                      <p className="text-foreground-secondary text-sm">of ${spending?.daily_budget ?? '—'} limit</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-background-card border-border">
                    <CardHeader>
                      <CardTitle className="text-foreground text-base">Per-Task Budget</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-2xl font-semibold">${spending?.per_task_limit ?? '—'}</p>
                      <p className="text-foreground-secondary text-sm">max per task</p>
                    </CardContent>
                  </Card>
                </>
              )}
            </div>

            <Card className="bg-background-card border-border">
              <CardHeader>
                <CardTitle className="text-foreground">Spending by Category</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-48 flex items-center justify-center text-foreground-secondary border border-border rounded-lg border-dashed">
                  Bar chart placeholder
                </div>
              </CardContent>
            </Card>

            <Card className="bg-background-card border-border">
              <CardHeader>
                <CardTitle className="text-foreground">Budget Limits</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm text-foreground-secondary">Monthly ($)</label>
                  <Input
                    type="number"
                    value={monthlyBudget}
                    onChange={(e) => setMonthlyBudget(e.target.value)}
                    className="bg-background-card border-border text-foreground mt-1"
                  />
                </div>
                <div>
                  <label className="text-sm text-foreground-secondary">Daily ($)</label>
                  <Input
                    type="number"
                    value={dailyBudget}
                    onChange={(e) => setDailyBudget(e.target.value)}
                    className="bg-background-card border-border text-foreground mt-1"
                  />
                </div>
                <div>
                  <label className="text-sm text-foreground-secondary">Per task ($)</label>
                  <Input
                    type="number"
                    value={perTaskBudget}
                    onChange={(e) => setPerTaskBudget(e.target.value)}
                    className="bg-background-card border-border text-foreground mt-1"
                  />
                </div>
                <Button onClick={saveSettings} disabled={savingSettings}>
                  Save Budgets
                </Button>
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === 'automations' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <p className="text-foreground-secondary">Schedule and manage Aegis automations.</p>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Create Automation
              </Button>
            </div>
            <Card className="bg-background-card border-border">
              <CardContent className="pt-6">
                {loadingAutomations ? (
                  <div className="space-y-3">
                    {[1, 2, 3].map((i) => (
                      <div key={i} className="h-14 bg-muted animate-pulse rounded" />
                    ))}
                  </div>
                ) : automations.length === 0 ? (
                  <p className="text-foreground-secondary text-sm">No automations yet.</p>
                ) : (
                  <div className="space-y-3">
                    {automations.map((a: any) => (
                      <div
                        key={a.id}
                        className="flex items-center justify-between border border-border rounded-lg p-4"
                      >
                        <div>
                          <p className="font-medium">{a.name ?? 'Automation'}</p>
                          <p className="text-sm text-foreground-secondary">{a.schedule ?? a.prompt ?? ''}</p>
                        </div>
                        <Switch
                          checked={a.enabled !== false}
                          onCheckedChange={(v) => toggleAutomation(a.id, v)}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === 'memory' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center gap-4 flex-wrap">
              <div className="flex gap-2 flex-1 min-w-[200px]">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                  <Input
                    placeholder="Search memories..."
                    value={memorySearch}
                    onChange={(e) => setMemorySearch(e.target.value)}
                    className="pl-9 bg-background-card border-border text-foreground"
                  />
                </div>
                <select
                  value={memoryCategory}
                  onChange={(e) => setMemoryCategory(e.target.value)}
                  className="rounded-md border border-border bg-background-card text-foreground px-3 py-2 text-sm"
                >
                  <option value="all">All categories</option>
                  <option value="general">General</option>
                  <option value="project">Project</option>
                  <option value="security">Security</option>
                  <option value="policy">Policy</option>
                </select>
              </div>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Teach Aegis
              </Button>
            </div>
            <Card className="bg-background-card border-border">
              <CardContent className="pt-6">
                {loadingMemories ? (
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Key</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Category</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Updated</th>
                        <th className="w-16" />
                      </tr>
                    </thead>
                    <tbody>
                      {[1, 2, 3, 4].map((i) => <SkeletonRow key={i} cols={4} />)}
                    </tbody>
                  </table>
                ) : filteredMemories.length === 0 ? (
                  <p className="text-foreground-secondary text-sm">No memories match your filters.</p>
                ) : (
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Key</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Category</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Updated</th>
                        <th className="w-24" />
                      </tr>
                    </thead>
                    <tbody>
                      {filteredMemories.map((m: any) => (
                        <tr key={m.id} className="border-b border-border hover:bg-muted/30">
                          <td className="py-3 px-4">{m.key ?? m.id}</td>
                          <td className="py-3 px-4 text-foreground-secondary">{m.category ?? 'general'}</td>
                          <td className="py-3 px-4 text-foreground-secondary">
                            {m.updated_at ? new Date(m.updated_at).toLocaleDateString() : '—'}
                          </td>
                          <td className="py-3 px-4">
                            <div className="flex gap-1">
                              <Button size="icon" variant="ghost" className="h-8 w-8">
                                <Edit2 className="h-4 w-4" />
                              </Button>
                              <Button size="icon" variant="ghost" className="h-8 w-8 text-red-400">
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === 'learning' && (
          <LearningDashboard orgId={organizationId} />
        )}

        {activeTab === 'usage' && (
          <div className="space-y-6">
            <div className="grid gap-4 md:grid-cols-4">
              {loadingUsage ? (
                <>
                  {[1, 2, 3, 4].map((i) => (
                    <Card key={i} className="bg-background-card border-border">
                      <CardContent className="pt-6">
                        <div className="h-12 bg-muted animate-pulse rounded" />
                      </CardContent>
                    </Card>
                  ))}
                </>
              ) : (
                <>
                  <Card className="bg-background-card border-border">
                    <CardContent className="pt-6">
                      <p className="text-foreground-secondary text-sm">Messages today</p>
                      <p className="text-2xl font-semibold">{usage?.messages_today ?? 0}</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-background-card border-border">
                    <CardContent className="pt-6">
                      <p className="text-foreground-secondary text-sm">Tools used today</p>
                      <p className="text-2xl font-semibold">{usage?.tools_today ?? 0}</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-background-card border-border">
                    <CardContent className="pt-6">
                      <p className="text-foreground-secondary text-sm">This month</p>
                      <p className="text-2xl font-semibold">{usage?.messages_month ?? 0}</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-background-card border-border">
                    <CardContent className="pt-6">
                      <p className="text-foreground-secondary text-sm">Token usage</p>
                      <p className="text-2xl font-semibold">{usage?.tokens_month ?? 0}</p>
                    </CardContent>
                  </Card>
                </>
              )}
            </div>
            <Card className="bg-background-card border-border">
              <CardHeader>
                <CardTitle className="text-foreground">Messages per Day</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-48 flex items-center justify-center text-foreground-secondary border border-border rounded-lg border-dashed">
                  Chart placeholder
                </div>
              </CardContent>
            </Card>
            <Card className="bg-background-card border-border">
              <CardHeader>
                <CardTitle className="text-foreground">Most Used Tools</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-48 flex items-center justify-center text-foreground-secondary border border-border rounded-lg border-dashed">
                  Bar chart placeholder
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center gap-4 flex-wrap">
              <select
                value={auditFilter}
                onChange={(e) => setAuditFilter(e.target.value)}
                className="rounded-md border border-border bg-background-card text-foreground px-3 py-2 text-sm"
              >
                <option value="all">All</option>
                <option value="success">Success</option>
                <option value="error">Error</option>
              </select>
              <Button variant="outline" onClick={exportAuditCsv}>
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </Button>
            </div>
            <Card className="bg-background-card border-border">
              <CardContent className="pt-6 overflow-x-auto">
                {loadingAudit ? (
                  <table className="w-full min-w-[600px]">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Timestamp</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Tool</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Status</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">User</th>
                        <th className="w-10" />
                      </tr>
                    </thead>
                    <tbody>
                      {[1, 2, 3, 4, 5].map((i) => <SkeletonRow key={i} cols={5} />)}
                    </tbody>
                  </table>
                ) : filteredExecutions.length === 0 ? (
                  <p className="text-foreground-secondary text-sm">No tool executions match your filters.</p>
                ) : (
                  <table className="w-full min-w-[600px]">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Timestamp</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Tool</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">Status</th>
                        <th className="text-left py-3 px-4 text-foreground-secondary font-medium">User</th>
                        <th className="w-10" />
                      </tr>
                    </thead>
                    <tbody>
                      {filteredExecutions.map((e: any) => (
                        <React.Fragment key={e.id}>
                          <tr
                            className="border-b border-border hover:bg-muted/30 cursor-pointer"
                            onClick={() => setExpandedRow(expandedRow === e.id ? null : e.id)}
                          >
                            <td className="py-3 px-4">
                              {e.timestamp ? new Date(e.timestamp).toLocaleString() : e.created_at ?? '—'}
                            </td>
                            <td className="py-3 px-4">{e.tool_name ?? '—'}</td>
                            <td className="py-3 px-4">
                              <Badge
                                variant={e.status === 'error' ? 'destructive' : 'default'}
                                className="border-border"
                              >
                                {e.status ?? '—'}
                              </Badge>
                            </td>
                            <td className="py-3 px-4 text-foreground-secondary">{e.user_email ?? e.user_id ?? '—'}</td>
                            <td className="py-3 px-4">
                              {expandedRow === e.id ? (
                                <Pause className="h-4 w-4 rotate-90 text-foreground-secondary" />
                              ) : (
                                <span className="text-foreground-secondary">▼</span>
                              )}
                            </td>
                          </tr>
                          {expandedRow === e.id && (
                            <tr className="bg-background-subtle border-b border-border">
                              <td colSpan={5} className="py-3 px-4">
                                <pre className="text-xs text-foreground-secondary overflow-x-auto whitespace-pre-wrap">
                                  {JSON.stringify(e, null, 2)}
                                </pre>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                    </tbody>
                  </table>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
