import { useState, useEffect, useRef } from 'react';
import { Plus, Trash2, Check, Pencil, MoreVertical, Mail, ChevronDown, Loader2, Webhook, BookOpen } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '../../components/ui/button';
import { cn } from '../../lib/utils';
import { PolicyCodeEditor } from '../../components/PolicyCodeEditor';
import { NotificationAIAssistant } from '../../components/NotificationAIAssistant';
import { useAuth } from '../../contexts/AuthContext';
import { useUserProfile } from '../../hooks/useUserProfile';
import { useToast } from '../../hooks/use-toast';
import { api, type OrganizationNotificationRule, type CiCdConnection, type OrganizationMember } from '../../lib/api';
import { Avatar, AvatarImage, AvatarFallback } from '../../components/ui/avatar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';

const DESTINATION_PROVIDERS = ['slack', 'discord', 'jira', 'linear', 'asana', 'custom_notification', 'custom_ticketing', 'email'] as const;

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
  /** When true, hide the header (title + Create Rule button) for use in Project Settings where they appear above the tabs */
  hideTitle?: boolean;
  /** Ref to register the create-rule handler so the parent can trigger it (e.g. button above tabs) */
  createHandlerRef?: React.MutableRefObject<(() => void) | null>;
  /** Pre-loaded connections when in project context (org + project merged) */
  connections?: CiCdConnection[];
}

export default function NotificationRulesSection({ organizationId = '', projectId, hideTitle, createHandlerRef, connections: externalConnections }: NotificationRulesSectionProps) {
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

    // Use pre-loaded connections when provided (e.g. from parent OrganizationSettingsPage) to avoid duplicate fetches
    const connectionsPromise =
      externalConnections && externalConnections.length > 0
        ? Promise.resolve(externalConnections)
        : api.getOrganizationConnections(organizationId).catch(() => [] as CiCdConnection[]);

    Promise.all([
      api.getOrganizationNotificationRules(organizationId),
      connectionsPromise,
      api.getOrganizationMembers(organizationId).catch(() => [] as OrganizationMember[]),
    ])
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
  }, [organizationId, toast]);

  // When parent passes pre-loaded connections (e.g. from Integrations tab), use them so we stay in sync
  useEffect(() => {
    if (externalConnections && externalConnections.length > 0) {
      setConnections(externalConnections);
    }
  }, [externalConnections]);

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

  const resetForm = () => {
    setRuleName('');
    setCustomCode(DEFAULT_CUSTOM_CODE);
    setDestinations([{ id: crypto.randomUUID(), connectionId: destinationConnections[0]?.id ?? '' }]);
    setEditingRuleId(null);
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
      .filter((x): x is { integrationType: string; targetId: string } => !!x);
    if (dests.length === 0) {
      toast({ title: 'Add a destination', description: 'Select at least one integration to receive notifications.', variant: 'destructive' });
      return;
    }
    const createdByName = fullName || user?.user_metadata?.full_name || user?.email || 'Unknown';

    setSaving(true);
    try {
      if (editingRuleId) {
        const updated = await api.updateOrganizationNotificationRule(organizationId, editingRuleId, {
          name,
          triggerType: 'custom_code_pipeline',
          customCode,
          destinations: dests,
        });
        setRules((prev) => prev.map((r) => (r.id === editingRuleId ? updated : r)));
        toast({ title: 'Rule updated', description: 'Notification rule saved successfully.' });
      } else {
        const newRule = await api.createOrganizationNotificationRule(organizationId, {
          name,
          triggerType: 'custom_code_pipeline',
          customCode,
          destinations: dests,
          createdByName,
        });
        setRules((prev) => [newRule, ...prev]);
        toast({ title: 'Rule created', description: 'Notification rule saved successfully.' });
      }
      closeSidebar();
    } catch (err: any) {
      toast({ title: 'Failed to save', description: err.message || 'Could not save rule', variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleCreateClick = () => {
    resetForm();
    setEditingRuleId(null);
    setSidebarOpen(true);
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
      await api.deleteOrganizationNotificationRule(organizationId, ruleId);
    } catch (err: any) {
      setRules(previousRules);
      toast({ title: 'Failed to delete', description: err.message || 'Could not delete rule', variant: 'destructive' });
    }
  };

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

      {/* Table-style list */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-2.5 bg-background-card-header border-b border-border">
          <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
            Notification Rules
          </span>
        </div>
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

          {/* Empty state - None row */}
          {!loading && rules.length === 0 && (
            <div className="px-4 py-4 flex items-center gap-3">
              <div className="h-8 w-8 rounded-md border border-border bg-background-card flex items-center justify-center text-foreground-muted">
                <Mail className="h-4 w-4" />
              </div>
              <span className="text-sm font-medium text-foreground-muted">None</span>
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
                    {destinationConnections.length === 0 && (
                      <p className="text-xs text-foreground-muted mt-1">
                        Connect Slack, Jira, Linear, or other integrations in Organization Settings first.
                      </p>
                    )}
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={addDestination}
                      className="mt-2 rounded-lg"
                      disabled={destinationConnections.length === 0}
                    >
                      <Plus className="h-4 w-4" />
                      Add destination
                    </Button>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-foreground mb-2 text-left">Trigger logic</label>
                    <div className="rounded-lg border border-border overflow-hidden">
                      <PolicyCodeEditor
                        value={customCode}
                        onChange={setCustomCode}
                        readOnly={false}
                        fitContent
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex-shrink-0 flex flex-col">
                <NotificationAIAssistant
                  organizationId={organizationId}
                  currentCode={customCode}
                  onUpdateCode={setCustomCode}
                  onClose={() => {}}
                  embedded
                  variant="inline"
                />
              </div>
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
                ) : (
                  <Plus className="h-4 w-4 mr-2" />
                )}
                {editingRuleId ? 'Save' : 'Create Rule'}
              </Button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
