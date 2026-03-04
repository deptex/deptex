import { useState, useEffect, useRef, useCallback } from 'react';
import { Plus, Trash2, Check, Pencil, MoreVertical, Mail, ChevronDown, Loader2, Webhook, BookOpen, X, Clock, Play, Info, LayoutGrid, Calendar, ShieldAlert, FileWarning, BarChart2, Bell } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '../../components/ui/button';
import { cn } from '../../lib/utils';
import { PolicyCodeEditor } from '../../components/PolicyCodeEditor';
import { NotificationAIAssistant } from '../../components/NotificationAIAssistant';
import { useAuth } from '../../contexts/AuthContext';
import { useUserProfile } from '../../hooks/useUserProfile';
import { useToast } from '../../hooks/use-toast';
import { api, type OrganizationNotificationRule, type CiCdConnection, type CiCdProvider, type OrganizationMember } from '../../lib/api';
import { Avatar, AvatarImage, AvatarFallback } from '../../components/ui/avatar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuSubContent,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';

const DESTINATION_PROVIDERS = ['slack', 'discord', 'jira', 'linear', 'asana', 'pagerduty', 'custom_notification', 'custom_ticketing', 'email'] as const;

function getConnectionIconSrc(conn: CiCdConnection): string | null {
  const isCustom = conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing';
  const isEmail = conn.provider === 'email';
  if (isCustom && conn.metadata?.icon_url) return conn.metadata.icon_url;
  if (isEmail) return null;
  if (conn.provider === 'slack') return '/images/integrations/slack.png';
  if (conn.provider === 'discord') return '/images/integrations/discord.png';
  if (conn.provider === 'jira') return '/images/integrations/jira.png';
  if (conn.provider === 'linear') return '/images/integrations/linear.png';
  if (conn.provider === 'asana') return '/images/integrations/asana.png';
  if (conn.provider === 'pagerduty') return '/images/integrations/pagerduty.png';
  return null;
}

function getProviderLabel(conn: CiCdConnection): string {
  const isCustom = conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing';
  if (isCustom) return 'Custom';
  if (conn.provider === 'email') return 'Email';
  if (conn.provider === 'slack') return 'Slack';
  if (conn.provider === 'discord') return 'Discord';
  if (conn.provider === 'jira') return conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira';
  if (conn.provider === 'linear') return 'Linear';
  if (conn.provider === 'asana') return 'Asana';
  if (conn.provider === 'pagerduty') return 'PagerDuty';
  return conn.provider;
}

function getConnectionName(conn: CiCdConnection): string {
  const isCustom = conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing';
  const isEmail = conn.provider === 'email';
  if (isCustom) return conn.metadata?.custom_name || conn.display_name || (conn.metadata?.webhook_url ? conn.metadata.webhook_url.replace(/^https?:\/\//, '').slice(0, 45) : 'Webhook');
  if (isEmail) return conn.metadata?.email || conn.display_name || 'Email';
  if (conn.provider === 'slack') {
    const channelRaw = conn.metadata?.channel || conn.metadata?.incoming_webhook?.channel || null;
    const channel = channelRaw ? (channelRaw.startsWith('#') ? channelRaw : `#${channelRaw}`) : null;
    const workspace = conn.display_name || conn.metadata?.team_name || 'Slack Workspace';
    return channel ? `${workspace} · ${channel}` : workspace;
  }
  if (conn.provider === 'discord') return conn.display_name !== 'Discord Server' ? (conn.display_name || '') : (conn.metadata?.guild_name || 'Discord Server');
  if (conn.provider === 'jira' || conn.provider === 'linear' || conn.provider === 'asana') return conn.display_name || 'Connected';
  return conn.display_name || conn.provider;
}

function getConnectionLabel(conn: CiCdConnection): string {
  return `${getProviderLabel(conn)} · ${getConnectionName(conn)}`;
}

interface DestinationAction {
  id: string;
  connectionId: string;
}

function formatDestinations(
  destinations: OrganizationNotificationRule['destinations'],
  connections: CiCdConnection[]
): string {
  return destinations
    .map((d) => {
      const conn = connections.find((c) => c.id === d.targetId);
      return conn ? getConnectionLabel(conn) : `${d.integrationType} (${d.targetId.slice(0, 8)}…)`;
    })
    .join(', ');
}

function DestinationIcons({
  destinations,
  connections,
}: {
  destinations: OrganizationNotificationRule['destinations'];
  connections: CiCdConnection[];
}) {
  const conns = destinations
    .map((d) => connections.find((c) => c.id === d.targetId))
    .filter((c): c is CiCdConnection => !!c);
  const uniqueConns = [...new Map(conns.map((c) => [c.id, c])).values()];
  return (
    <div className="flex items-center gap-1.5">
      {uniqueConns.slice(0, 3).map((conn) => {
        const src = getConnectionIconSrc(conn);
        const isEmail = conn.provider === 'email';
        if (src) {
          return <img key={conn.id} src={src} alt="" className="h-5 w-5 rounded-sm flex-shrink-0 object-contain" />;
        }
        if (isEmail) {
          return <Mail key={conn.id} className="h-5 w-5 text-foreground-secondary flex-shrink-0" />;
        }
        return <Webhook key={conn.id} className="h-5 w-5 text-foreground-secondary flex-shrink-0" />;
      })}
      {uniqueConns.length > 3 && (
        <span className="text-xs text-foreground-secondary">+{uniqueConns.length - 3}</span>
      )}
    </div>
  );
}

const DEFAULT_CUSTOM_CODE = `// Return true to trigger notification, false to skip
return false;
`;

/** Default samples when API returns none or fails */
const DEFAULT_SAMPLES: { id: string; name: string; description: string; code: string; icon: LucideIcon }[] = [
  { id: 'weekly-digest', name: 'Weekly digest', description: 'Weekly summary of security events across projects', code: "// Fires on weekly_digest batch\nreturn context.event?.type === 'weekly_digest' || (context.batch && context.batch.total > 0);", icon: Calendar },
  { id: 'vuln-above-score', name: 'New vulnerability with score above 70', description: 'Notify when a vulnerability is discovered with Depscore greater than 70 (higher = more severe)', code: "if (context.event.type !== 'vulnerability_discovered') return false;\nif (!context.vulnerability) return false;\nreturn (context.vulnerability.depscore || 0) > 70;", icon: ShieldAlert },
  { id: 'policy-violation', name: 'Policy violation', description: 'Alert when a dependency violates package or license policy', code: "return context.event.type === 'policy_violation';", icon: FileWarning },
  { id: 'new-dep-low-score', name: 'New dependency with low score', description: 'Alert when a new dependency is added with a low reputation score', code: "if (context.event.type !== 'dependency_added') return false;\nreturn context.dependency && context.dependency.score < 50;", icon: BarChart2 },
];

/** Connection dropdown with icon */
function ConnectionDropdown({
  value,
  connections,
  onChange,
  placeholder = 'Select integration',
  className = '',
}: {
  value: string;
  connections: CiCdConnection[];
  onChange: (connectionId: string) => void;
  placeholder?: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const selected = connections.find((c) => c.id === value);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div ref={ref} className={cn('relative', className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full px-3 py-2.5 border border-border rounded-lg bg-background-card hover:border-foreground-secondary/30 flex items-center justify-between gap-2 text-sm text-foreground transition-all text-left"
      >
        <div className="flex items-center gap-2 min-w-0">
          {selected ? (
            <>
              {getConnectionIconSrc(selected) ? (
                <img src={getConnectionIconSrc(selected)!} alt="" className="h-5 w-5 rounded-sm flex-shrink-0 object-contain" />
              ) : selected.provider === 'email' ? (
                <Mail className="h-5 w-5 flex-shrink-0 text-foreground-secondary" />
              ) : (
                <Webhook className="h-5 w-5 flex-shrink-0 text-foreground-secondary" />
              )}
              <div className="flex flex-col min-w-0 truncate text-left">
                <span className="text-xs font-medium text-foreground-secondary">{getProviderLabel(selected)}</span>
                <span className="text-sm text-foreground truncate">{getConnectionName(selected)}</span>
              </div>
            </>
          ) : (
            <span className="text-foreground-secondary">{placeholder}</span>
          )}
        </div>
        <ChevronDown className={cn('h-4 w-4 flex-shrink-0 text-foreground-secondary transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="absolute z-50 left-0 right-0 mt-1 py-0.5 bg-background-card border border-border rounded-lg shadow-xl overflow-hidden animate-in fade-in-0 zoom-in-95 duration-100 max-h-60 overflow-y-auto">
          {connections.map((conn) => (
            <button
              key={conn.id}
              type="button"
              className="w-full px-3 py-3 flex items-center justify-between gap-3 hover:bg-table-hover transition-colors text-left"
              onClick={() => {
                onChange(conn.id);
                setOpen(false);
              }}
            >
              <div className="flex items-center gap-3 min-w-0">
                {getConnectionIconSrc(conn) ? (
                  <img src={getConnectionIconSrc(conn)!} alt="" className="h-6 w-6 rounded-sm flex-shrink-0 object-contain" />
                ) : conn.provider === 'email' ? (
                  <Mail className="h-6 w-6 flex-shrink-0 text-foreground-secondary" />
                ) : (
                  <Webhook className="h-6 w-6 flex-shrink-0 text-foreground-secondary" />
                )}
                <div className="flex flex-col min-w-0 text-left">
                  <span className="text-xs font-medium text-foreground-secondary">{getProviderLabel(conn)}</span>
                  <span className="text-sm text-foreground truncate">{getConnectionName(conn)}</span>
                </div>
              </div>
              {value === conn.id && (
                <div className="h-4 w-4 rounded-full border-2 border-foreground bg-foreground flex-shrink-0 flex items-center justify-center">
                  <Check className="h-2.5 w-2.5 text-background" />
                </div>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

interface NotificationRulesSectionProps {
  organizationId?: string;
  projectId?: string;
  teamId?: string;
  /** When true, hide the header (title + Create Rule button) for use in Project Settings where they appear above the tabs */
  hideTitle?: boolean;
  /** When true, hide only the rules list so the Create Rule sidebar can still open (e.g. when on History sub-tab in Org Settings) */
  hideListContent?: boolean;
  /** Ref to register the create-rule handler so the parent can trigger it (e.g. button above tabs) */
  createHandlerRef?: React.MutableRefObject<(() => void) | null>;
  /** Pre-loaded connections when in project context (org + project merged) */
  connections?: CiCdConnection[];
}

export default function NotificationRulesSection({ organizationId = '', projectId, teamId, hideTitle, hideListContent, createHandlerRef, connections: externalConnections }: NotificationRulesSectionProps) {
  const { user } = useAuth();
  const { fullName } = useUserProfile();
  const { toast } = useToast();
  const [rules, setRules] = useState<OrganizationNotificationRule[]>([]);
  const [connections, setConnections] = useState<CiCdConnection[]>([]);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarPanelVisible, setSidebarPanelVisible] = useState(false);
  const sidebarCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [ruleName, setRuleName] = useState('');
  const [customCode, setCustomCode] = useState(DEFAULT_CUSTOM_CODE);
  const destinationConnections = connections.filter((c) =>
    DESTINATION_PROVIDERS.includes(c.provider as (typeof DESTINATION_PROVIDERS)[number])
  );
  const [destinations, setDestinations] = useState<DestinationAction[]>([
    { id: crypto.randomUUID(), connectionId: '' },
  ]);
  const [validationChecks, setValidationChecks] = useState<{ name: string; pass: boolean; error?: string }[] | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResults, setTestResults] = useState<{ eventType: string; wouldNotify: boolean; message?: string; executionTime?: number; error?: string }[] | null>(null);
  const [snoozingRuleId, setSnoozingRuleId] = useState<string | null>(null);
  const [templates, setTemplates] = useState<{ id: string; name: string; description: string; code: string }[]>([]);
  const [showTemplatePicker, setShowTemplatePicker] = useState(false);
  const [createRuleMode, setCreateRuleMode] = useState<'ai' | 'samples'>('ai');
  const [loadingTemplates, setLoadingTemplates] = useState(false);
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(null);
  const aiAssistantRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!organizationId) {
      setRules([]);
      setConnections([]);
      setMembers([]);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);

    // Rules: use team/project/org API based on context (parallelized)
    const rulesPromise = teamId
      ? api.getTeamNotificationRules(organizationId, teamId)
      : projectId
        ? api.getProjectNotificationRules(organizationId, projectId)
        : api.getOrganizationNotificationRules(organizationId);

    // Connections: for team/project, parent provides them (avoids duplicate fetches with Destinations tab).
    // If not yet loaded, use [] so rules render immediately; connections sync via useEffect when parent loads.
    const connectionsPromise =
      teamId || projectId
        ? Promise.resolve(externalConnections ?? [])
        : externalConnections && externalConnections.length > 0
          ? Promise.resolve(externalConnections)
          : api.getOrganizationConnections(organizationId).catch(() => [] as CiCdConnection[]);

    // Members: org members for created-by avatars (parallelized with rules + connections)
    const membersPromise = api.getOrganizationMembers(organizationId).catch(() => [] as OrganizationMember[]);

    Promise.all([rulesPromise, connectionsPromise, membersPromise])
      .then(([rulesData, conns, membersData]) => {
        if (!cancelled) {
          setRules(rulesData);
          setConnections(conns);
          setMembers(membersData);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          toast({ title: 'Failed to load rules', description: err.message, variant: 'destructive' });
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [organizationId, teamId, projectId, toast]);

  // When parent passes pre-loaded connections (team/project/org Integrations tab), keep in sync
  useEffect(() => {
    if (teamId || projectId) {
      if (externalConnections) setConnections(externalConnections);
    } else if (externalConnections && externalConnections.length > 0) {
      setConnections(externalConnections);
    }
  }, [externalConnections, teamId, projectId]);

  useEffect(() => {
    if (sidebarOpen) {
      setSidebarPanelVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setSidebarPanelVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setSidebarPanelVisible(false);
    }
  }, [sidebarOpen]);

  useEffect(
    () => () => {
      if (sidebarCloseTimeoutRef.current) clearTimeout(sidebarCloseTimeoutRef.current);
    },
    []
  );

  useEffect(() => {
    if (createHandlerRef) {
      createHandlerRef.current = handleCreateClick;
      return () => {
        createHandlerRef.current = null;
      };
    }
  }, [createHandlerRef]);

  useEffect(() => {
    if (!sidebarOpen) return;
    const w = window as any;
    if (!w.monaco) return;
    const lib = w.monaco.languages.typescript.javascriptDefaults.addExtraLib(`
      declare const context: {
        event: { type: string; timestamp: string; source: string };
        project: { id: string; name: string; asset_tier: string; health_score: number; status: string; status_is_passing: boolean; dependencies_count: number; team_name: string | null };
        dependency: { name: string; version: string; license: string | null; is_direct: boolean; score: number; openssf_score: number | null; weekly_downloads: number | null; malicious_indicator: any; slsa_level: number; vulnerabilities: any[] } | null;
        vulnerability: { osv_id: string; severity: string; cvss_score: number; epss_score: number; depscore: number; is_reachable: boolean; cisa_kev: boolean; fixed_versions: string[]; summary: string } | null;
        pr: { number: number; title: string; author: string; check_result: string; check_summary: string; deps_added: number; deps_updated: number; deps_removed: number } | null;
        previous: { status?: string; health_score?: number } | null;
        batch: { total: number; by_type: Record<string, number>; events: any[] } | null;
      };
      declare function fetch(url: string, options?: any): Promise<any>;
    `, 'notification-context.d.ts');
    return () => lib?.dispose();
  }, [sidebarOpen]);

  const resetForm = () => {
    setRuleName('');
    setCustomCode(DEFAULT_CUSTOM_CODE);
    setDestinations([{ id: crypto.randomUUID(), connectionId: destinationConnections[0]?.id ?? '' }]);
    setEditingRuleId(null);
    setValidationChecks(null);
    setTestResults(null);
    setShowTemplatePicker(false);
    setCreateRuleMode('ai');
    setSelectedSampleId(null);
  };

  const closeSidebar = () => {
    setSidebarPanelVisible(false);
    if (sidebarCloseTimeoutRef.current) clearTimeout(sidebarCloseTimeoutRef.current);
    sidebarCloseTimeoutRef.current = setTimeout(() => {
      sidebarCloseTimeoutRef.current = null;
      setSidebarOpen(false);
      resetForm();
    }, 150);
  };

  const loadRuleIntoForm = (rule: OrganizationNotificationRule) => {
    setRuleName(rule.name);
    setCustomCode(rule.customCode ?? DEFAULT_CUSTOM_CODE);
    setDestinations(
      rule.destinations.length > 0
        ? rule.destinations.map((d) => ({
            id: crypto.randomUUID(),
            connectionId: d.targetId,
          }))
        : [{ id: crypto.randomUUID(), connectionId: destinationConnections[0]?.id ?? '' }]
    );
  };

  const handleSaveRule = async () => {
    if (!organizationId) return;
    const name = ruleName?.trim() || 'Untitled Rule';
    const dests = destinations
      .filter((d) => d.connectionId)
      .map((d) => {
        const conn = destinationConnections.find((c) => c.id === d.connectionId);
        return conn ? { integrationType: conn.provider, targetId: conn.id } : null;
      })
      .filter((x): x is { integrationType: CiCdProvider; targetId: string } => x !== null);
    if (dests.length === 0) {
      toast({ title: 'Add a destination', description: 'Select at least one integration to receive notifications.', variant: 'destructive' });
      return;
    }
    if (createRuleMode === 'samples' && !editingRuleId && !selectedSampleId) {
      toast({ title: 'Select a sample', description: 'Choose a sample from the list above.', variant: 'destructive' });
      return;
    }
    const createdByName = fullName || user?.user_metadata?.full_name || user?.email || 'Unknown';
    const payload = { name, triggerType: 'custom_code_pipeline' as const, customCode, destinations: dests };

    setSaving(true);
    setValidationChecks(null);
    try {
      if (editingRuleId) {
        const updated = teamId
          ? await api.updateTeamNotificationRule(organizationId, teamId, editingRuleId, payload)
          : projectId
            ? await api.updateProjectNotificationRule(organizationId, projectId, editingRuleId, payload)
            : await api.updateOrganizationNotificationRule(organizationId, editingRuleId, payload);
        setRules((prev) => prev.map((r) => (r.id === editingRuleId ? updated : r)));
        toast({ title: 'Rule updated', description: 'Notification rule saved successfully.' });
      } else {
        const createPayload = { ...payload, createdByName };
        const newRule = teamId
          ? await api.createTeamNotificationRule(organizationId, teamId, createPayload)
          : projectId
            ? await api.createProjectNotificationRule(organizationId, projectId, createPayload)
            : await api.createOrganizationNotificationRule(organizationId, createPayload);
        setRules((prev) => [newRule, ...prev]);
        toast({ title: 'Rule created', description: 'Notification rule saved successfully.' });
      }
      closeSidebar();
    } catch (err: any) {
      if (err.checks && Array.isArray(err.checks)) {
        setValidationChecks(err.checks);
      } else {
        try {
          const parsed = typeof err.body === 'string' ? JSON.parse(err.body) : err.body;
          if (parsed?.checks) {
            setValidationChecks(parsed.checks);
          }
        } catch {
          // not a validation error
        }
      }
      toast({ title: 'Failed to save', description: err.message || 'Could not save rule', variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleCreateClick = () => {
    resetForm();
    setEditingRuleId(null);
    setShowTemplatePicker(true);
    setSidebarOpen(true);
    fetchTemplates();
  };

  const handleEdit = (rule: OrganizationNotificationRule, e: React.MouseEvent) => {
    e.stopPropagation();
    loadRuleIntoForm(rule);
    setEditingRuleId(rule.id);
    setSidebarOpen(true);
  };

  const handleDelete = async (ruleId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!organizationId) return;
    const previousRules = rules;
    setRules((prev) => prev.filter((r) => r.id !== ruleId));
    if (editingRuleId === ruleId) closeSidebar();
    try {
      if (teamId) {
        await api.deleteTeamNotificationRule(organizationId, teamId, ruleId);
      } else if (projectId) {
        await api.deleteProjectNotificationRule(organizationId, projectId, ruleId);
      } else {
        await api.deleteOrganizationNotificationRule(organizationId, ruleId);
      }
    } catch (err: any) {
      setRules(previousRules);
      toast({ title: 'Failed to delete', description: err.message || 'Could not delete rule', variant: 'destructive' });
    }
  };

  const getToken = async () => {
    const { supabase: sb } = await import('../../lib/supabase');
    const session = await sb.auth.getSession();
    return session.data.session?.access_token || '';
  };

  const handleTestRule = async () => {
    if (!organizationId) return;
    setTesting(true);
    setTestResults(null);
    const apiBase = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || 'http://localhost:3001';
    try {
      const token = await getToken();
      const res = await fetch(`${apiBase}/api/organizations/${organizationId}/test-notification-rule`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ code: customCode }),
      });
      const text = await res.text();
      let data: { results?: unknown[]; error?: string } = {};
      if (text) {
        try {
          data = JSON.parse(text);
        } catch {
          toast({ title: 'Test failed', description: 'Invalid response from server', variant: 'destructive' });
          return;
        }
      }
      if (!res.ok) {
        toast({ title: 'Test failed', description: (data as { error?: string }).error || res.statusText || 'Request failed', variant: 'destructive' });
        return;
      }
      if (data.results && Array.isArray(data.results)) {
        setTestResults(data.results);
      } else if (data.error) {
        toast({ title: 'Test failed', description: data.error, variant: 'destructive' });
      }
    } catch (err: any) {
      toast({ title: 'Test failed', description: err.message || 'Could not test rule', variant: 'destructive' });
    } finally {
      setTesting(false);
    }
  };

  const handleSnooze = async (ruleId: string, duration: string) => {
    if (!organizationId) return;
    setSnoozingRuleId(ruleId);
    try {
      const token = await getToken();
      const baseUrl = teamId
        ? `/api/organizations/${organizationId}/teams/${teamId}/notification-rules/${ruleId}/snooze`
        : projectId
          ? `/api/organizations/${organizationId}/projects/${projectId}/notification-rules/${ruleId}/snooze`
          : `/api/organizations/${organizationId}/notification-rules/${ruleId}/snooze`;
      const res = await fetch(`${import.meta.env.VITE_API_URL || ''}${baseUrl}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ duration }),
      });
      if (!res.ok) throw new Error('Failed to snooze');
      toast({ title: 'Rule snoozed', description: `Notifications paused for ${duration}.` });
    } catch (err: any) {
      toast({ title: 'Snooze failed', description: err.message, variant: 'destructive' });
    } finally {
      setSnoozingRuleId(null);
    }
  };

  const fetchTemplates = useCallback(async () => {
    if (!organizationId) return;
    setLoadingTemplates(true);
    try {
      const token = await getToken();
      const baseUrl = teamId
        ? `/api/organizations/${organizationId}/teams/${teamId}/notification-rule-templates`
        : projectId
          ? `/api/organizations/${organizationId}/projects/${projectId}/notification-rule-templates`
          : `/api/organizations/${organizationId}/notification-rule-templates`;
      const res = await fetch(`${import.meta.env.VITE_API_URL || ''}${baseUrl}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setTemplates(Array.isArray(data) ? data : data.templates || []);
      }
    } catch {
      // templates are optional — fail silently
    } finally {
      setLoadingTemplates(false);
    }
  }, [organizationId, teamId, projectId]);

  const addDestination = () => {
    setDestinations((prev) => [
      ...prev,
      { id: crypto.randomUUID(), connectionId: destinationConnections[0]?.id ?? '' },
    ]);
  };

  const removeDestination = (id: string) => {
    if (destinations.length <= 1) return;
    setDestinations((prev) => prev.filter((d) => d.id !== id));
  };

  const updateDestination = (id: string, connectionId: string) => {
    setDestinations((prev) => prev.map((d) => (d.id === id ? { ...d, connectionId } : d)));
  };

  return (
    <div className="space-y-6">
      {!hideTitle && (
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-bold text-foreground">Notifications</h2>
          <Button
            onClick={handleCreateClick}
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
          >
            <Plus className="h-4 w-4 mr-2" />
            Create Rule
          </Button>
        </div>
      )}

      {/* Table-style list (hidden when hideListContent so Create Rule sidebar can open from History tab) */}
      <div style={hideListContent ? { display: 'none' } : undefined} className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="divide-y divide-border">
          {loading && (
            <>
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="px-4 py-3 flex items-center gap-3 animate-pulse">
                  <div className="flex items-center gap-1.5">
                    <div className="h-5 w-5 rounded-sm bg-muted flex-shrink-0" />
                    <div className="h-5 w-5 rounded-sm bg-muted flex-shrink-0" />
                  </div>
                  <div className="flex-1 min-w-0 space-y-1.5">
                    <div className="h-4 bg-muted rounded w-32 max-w-full" />
                    <div className="h-3 bg-muted/70 rounded w-48 max-w-full" />
                  </div>
                  <div className="h-6 w-6 rounded-full bg-muted flex-shrink-0 hidden sm:block" />
                  <div className="h-6 w-6 rounded bg-muted flex-shrink-0" />
                </div>
              ))}
            </>
          )}

          {/* Empty state - None row (colour matches delivery history empty state) */}
          {!loading && rules.length === 0 && (
            <div className="px-4 py-4 flex items-center gap-3">
              <div className="h-8 w-8 rounded-md border border-border bg-background-card flex items-center justify-center text-foreground-secondary">
                <Mail className="h-4 w-4" />
              </div>
              <span className="text-sm font-medium text-foreground-secondary">None</span>
            </div>
          )}

          {/* Rule rows */}
          {!loading &&
            rules.map((rule) => (
              <div key={rule.id} className="px-4 py-3 flex items-center gap-3 hover:bg-table-hover transition-colors">
                <DestinationIcons destinations={rule.destinations} connections={connections} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-foreground truncate">{rule.name}</div>
                  {rule.destinations.length > 0 && (
                    <div className="text-xs text-foreground-secondary truncate mt-0.5">
                      {formatDestinations(rule.destinations, connections)}
                    </div>
                  )}
                </div>
                {rule.createdByUserId && (() => {
                  const member = members.find(m => m.user_id === rule.createdByUserId);
                  return (
                    <Avatar className="h-6 w-6 flex-shrink-0 hidden sm:flex">
                      <AvatarImage src={member?.avatar_url || undefined} alt={member?.full_name || rule.createdByName || ''} />
                      <AvatarFallback className="text-[9px] bg-background-subtle">
                        {(member?.full_name || rule.createdByName || '?').trim().slice(0, 2).toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                  );
                })()}
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <button
                      type="button"
                      className="p-1.5 rounded-md text-foreground-secondary hover:text-foreground hover:bg-background-subtle"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={(e) => handleEdit(rule, e)}>
                      <Pencil className="h-3.5 w-3.5 mr-2" />
                      Edit
                    </DropdownMenuItem>
                    <DropdownMenuSub>
                      <DropdownMenuSubTrigger>
                        <Clock className="h-3.5 w-3.5 mr-2" />
                        Snooze
                      </DropdownMenuSubTrigger>
                      <DropdownMenuSubContent>
                        {[
                          { label: '1 hour', value: '1h' },
                          { label: '4 hours', value: '4h' },
                          { label: '24 hours', value: '24h' },
                          { label: '1 week', value: '1w' },
                        ].map((opt) => (
                          <DropdownMenuItem
                            key={opt.value}
                            disabled={snoozingRuleId === rule.id}
                            onClick={(e) => { e.stopPropagation(); handleSnooze(rule.id, opt.value); }}
                          >
                            {opt.label}
                          </DropdownMenuItem>
                        ))}
                      </DropdownMenuSubContent>
                    </DropdownMenuSub>
                    <DropdownMenuItem
                      onClick={(e) => handleDelete(rule.id, e)}
                      className="text-destructive focus:text-destructive"
                    >
                      <Trash2 className="h-3.5 w-3.5 mr-2" />
                      Delete
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            ))}
        </div>
      </div>

      {/* Create/Edit sidebar – Vercel-style, matches Create Role */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              sidebarPanelVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeSidebar}
          />

          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[680px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              sidebarPanelVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0 flex items-start justify-between gap-4">
              <h2 className="text-xl font-semibold text-foreground text-left">
                {editingRuleId ? 'Edit Notification Rule' : 'Create Notification Rule'}
              </h2>
              <Link to="/docs/notification-rules" target="_blank" rel="noopener noreferrer" className="shrink-0">
                <Button variant="outline" size="sm" className="text-xs">
                  <BookOpen className="h-3.5 w-3.5 mr-1.5" />
                  Docs
                </Button>
              </Link>
            </div>

            <div className="flex-1 flex flex-col min-h-0 overflow-hidden items-stretch">
              {/* Template picker for new rules */}
              {showTemplatePicker && !editingRuleId ? (
                <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4 flex flex-col items-stretch">
                  <div className="space-y-4 w-full text-left">
                    <label className="block text-sm font-medium text-foreground text-left">Choose a starting point</label>
                    <div className="grid grid-cols-2 gap-3">
                      <button
                        type="button"
                        onClick={() => {
                          setShowTemplatePicker(false);
                          setCreateRuleMode('ai');
                          setCustomCode(DEFAULT_CUSTOM_CODE);
                          requestAnimationFrame(() => {
                            requestAnimationFrame(() => aiAssistantRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }));
                          });
                        }}
                        className="p-4 rounded-lg border border-border bg-background-card hover:border-foreground-secondary/40 hover:bg-muted/30 transition-colors text-left group"
                      >
                        <div className="rounded-md bg-[#0a0c0e] border border-border/60 w-9 h-9 flex items-center justify-center mb-3 text-foreground-secondary group-hover:text-foreground transition-colors">
                          <Info className="h-4 w-4" />
                        </div>
                        <span className="text-sm font-medium text-foreground block mb-0.5">Use AI Assistant</span>
                        <p className="text-xs text-foreground-secondary group-hover:text-foreground transition-colors">Describe what you want and let AI write the rule.</p>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setShowTemplatePicker(false);
                          setCreateRuleMode('samples');
                          setSelectedSampleId(null);
                          setCustomCode(DEFAULT_CUSTOM_CODE);
                        }}
                        className="p-4 rounded-lg border border-border bg-background-card hover:border-foreground-secondary/40 hover:bg-muted/30 transition-colors text-left group"
                      >
                        <div className="rounded-md bg-[#0a0c0e] border border-border/60 w-9 h-9 flex items-center justify-center mb-3 text-foreground-secondary group-hover:text-foreground transition-colors">
                          <LayoutGrid className="h-4 w-4" />
                        </div>
                        <span className="text-sm font-medium text-foreground block mb-0.5">Choose from samples</span>
                        <p className="text-xs text-foreground-secondary group-hover:text-foreground transition-colors">Weekly digest, new vulnerabilities, and more.</p>
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <>
                  <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4 flex flex-col items-stretch">
                    <div className="space-y-4 w-full text-left">
                      <div>
                        <label className="block text-sm font-medium text-foreground mb-1.5 text-left">Name</label>
                        <input
                          type="text"
                          value={ruleName}
                          onChange={(e) => setRuleName(e.target.value)}
                          className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all text-left"
                          placeholder=""
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-foreground mb-2 text-left">Destinations</label>
                        {destinationConnections.length === 0 ? (
                          <p className="text-sm text-foreground-secondary">
                            Connect integrations in Organization Settings first.
                          </p>
                        ) : (
                          <>
                            <div className="space-y-2">
                              {destinations.map((dest) => (
                                <div key={dest.id} className="flex gap-2 items-center">
                                  <ConnectionDropdown
                                    value={dest.connectionId}
                                    connections={destinationConnections}
                                    onChange={(connectionId) => updateDestination(dest.id, connectionId)}
                                    placeholder="Select integration"
                                    className="flex-1 min-w-0"
                                  />
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
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              onClick={addDestination}
                              className="mt-2 rounded-lg"
                            >
                              <Plus className="h-4 w-4" />
                              Add destination
                            </Button>
                          </>
                        )}
                      </div>

                      {createRuleMode === 'samples' && !editingRuleId ? (
                        <div>
                          <label className="block text-sm font-medium text-foreground mb-2 text-left">Sample</label>
                          {loadingTemplates ? (
                            <div className="flex items-center justify-center py-8">
                              <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
                            </div>
                          ) : (() => {
                            const withCode = templates.filter((t): t is typeof t & { code: string } => !!t.code);
                            const samplesToShow = withCode.length > 0 ? withCode : DEFAULT_SAMPLES;
                            return (
                              <div className="grid grid-cols-1 gap-2">
                                {samplesToShow.map((tpl) => {
                                  const Icon = (('icon' in tpl && tpl.icon ? tpl.icon : Bell) as LucideIcon);
                                  const isSelected = selectedSampleId === tpl.id;
                                  return (
                                    <button
                                      key={tpl.id}
                                      type="button"
                                      onClick={() => {
                                        setCustomCode(tpl.code);
                                        setSelectedSampleId(tpl.id);
                                      }}
                                      className={cn(
                                        'p-4 rounded-lg border text-left transition-colors flex items-start gap-3 group',
                                        isSelected
                                          ? 'border-foreground/50 bg-muted/50 ring-2 ring-foreground/20 ring-inset'
                                          : 'border-border bg-background-card hover:border-foreground-secondary/40 hover:bg-muted/30'
                                      )}
                                    >
                                      <div className={cn(
                                        'h-10 w-10 rounded-md flex items-center justify-center flex-shrink-0 border border-border/60 transition-colors',
                                        isSelected ? 'bg-[#0a0c0e] text-foreground' : 'bg-[#0a0c0e] text-foreground-secondary group-hover:text-foreground'
                                      )}>
                                        <Icon className="h-5 w-5" />
                                      </div>
                                      <div className="min-w-0 flex-1">
                                        <span className="text-sm font-medium text-foreground block">{tpl.name}</span>
                                        {tpl.description && (
                                          <p className="text-xs text-foreground-secondary group-hover:text-foreground transition-colors mt-1 line-clamp-2">{tpl.description}</p>
                                        )}
                                      </div>
                                    </button>
                                  );
                                })}
                              </div>
                            );
                          })()}
                        </div>
                      ) : (
                        <>
                      <div>
                        <label className="block text-sm font-medium text-foreground mb-2 text-left">Trigger logic</label>
                        <div className="rounded-lg border border-border overflow-hidden">
                          <PolicyCodeEditor
                            value={customCode}
                            onChange={(v) => { setCustomCode(v); setValidationChecks(null); }}
                            readOnly={false}
                            fitContent
                          />
                        </div>

                        {/* Validation checks display */}
                        {validationChecks && (
                          <div className="mt-2 space-y-1">
                            {validationChecks.map((check, i) => (
                              <div key={i} className="flex items-start gap-2 text-xs">
                                {check.pass ? (
                                  <Check className="h-3.5 w-3.5 text-green-500 mt-0.5 flex-shrink-0" />
                                ) : (
                                  <X className="h-3.5 w-3.5 text-destructive mt-0.5 flex-shrink-0" />
                                )}
                                <div>
                                  <span className={check.pass ? 'text-green-500' : 'text-destructive'}>{check.name}</span>
                                  {check.error && <p className="text-foreground-secondary mt-0.5">{check.error}</p>}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Test Rule button + results */}
                        <div className="mt-3">
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={handleTestRule}
                            disabled={testing}
                            className="rounded-lg"
                          >
                            {testing ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Play className="h-3.5 w-3.5 mr-1.5" />}
                            Test Rule
                          </Button>
                          {testResults && (
                            <div className="mt-2 rounded-lg border border-border bg-background-card overflow-hidden">
                              <div className="px-3 py-2 bg-background-card-header border-b border-border">
                                <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Test Results</span>
                              </div>
                              <div className="divide-y divide-border">
                                {testResults.map((r, i) => (
                                  <div key={i} className="px-3 py-2 flex items-start gap-2">
                                    {r.error ? (
                                      <X className="h-3.5 w-3.5 text-destructive mt-0.5 flex-shrink-0" />
                                    ) : r.wouldNotify ? (
                                      <Check className="h-3.5 w-3.5 text-green-500 mt-0.5 flex-shrink-0" />
                                    ) : (
                                      <span className="h-3.5 w-3.5 text-foreground-secondary mt-0.5 flex-shrink-0 text-center leading-[14px]">—</span>
                                    )}
                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-center gap-2">
                                        <span className="text-xs font-medium text-foreground">{r.eventType}</span>
                                        {r.executionTime != null && (
                                          <span className="text-[10px] text-foreground-secondary">{r.executionTime}ms</span>
                                        )}
                                      </div>
                                      {r.message && <p className="text-xs text-foreground-secondary mt-0.5 truncate">{r.message}</p>}
                                      {r.error && <p className="text-xs text-destructive mt-0.5">{r.error}</p>}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                        </>
                      )}

                    </div>
                  </div>

                  {(createRuleMode === 'ai' || editingRuleId) && (
                    <div ref={aiAssistantRef} className="flex-shrink-0 flex flex-col">
                      <NotificationAIAssistant
                      organizationId={organizationId}
                      currentCode={customCode}
                      onUpdateCode={setCustomCode}
                      onClose={() => {}}
                      embedded
                      variant="inline"
                    />
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
              <Button variant="outline" onClick={closeSidebar}>
                Cancel
              </Button>
              <Button
                onClick={handleSaveRule}
                disabled={saving}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              >
                {saving ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : null}
                {editingRuleId ? 'Save' : 'Create Rule'}
              </Button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
