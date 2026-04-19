import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Key, Check, X, AlertCircle, Loader2, BarChart3,
  Users, Clock, Settings, Shield, Zap, ChevronLeft,
  ChevronRight, Eye, EyeOff, Radio,
} from 'lucide-react';
import { api, AIProviderConfig, AIUsageSummary } from '../../lib/api';
import { Button } from '../ui/button';
import { useToast } from '../../hooks/use-toast';

interface AIConfigurationSectionProps {
  organizationId: string;
}

type ProviderKey = 'openai' | 'anthropic' | 'google';

interface ProviderMeta {
  key: ProviderKey;
  name: string;
  description: string;
  icon: string;
  models: string[];
}

const PROVIDERS: ProviderMeta[] = [
  {
    key: 'openai',
    name: 'OpenAI',
    description: 'GPT-4o, o1, and more',
    icon: '◯',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'o1', 'o1-mini'],
  },
  {
    key: 'anthropic',
    name: 'Anthropic',
    description: 'Claude Sonnet, Haiku',
    icon: '◈',
    models: ['claude-sonnet-4-20250514', 'claude-3-5-sonnet-20241022', 'claude-3-haiku-20240307'],
  },
  {
    key: 'google',
    name: 'Google',
    description: 'Gemini Flash & Pro',
    icon: '◆',
    models: ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-pro'],
  },
];

const DEFAULT_COST_CAP = 100;
const LOGS_PER_PAGE = 10;

function formatCurrency(value: number): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(value);
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function formatModelName(model: string): string {
  return model
    .replace('gpt-4o-mini', 'GPT-4o Mini')
    .replace('gpt-4o', 'GPT-4o')
    .replace('gpt-4-turbo', 'GPT-4 Turbo')
    .replace('o1-mini', 'o1 Mini')
    .replace('claude-sonnet-4-20250514', 'Claude Sonnet 4')
    .replace('claude-3-5-sonnet-20241022', 'Claude 3.5 Sonnet')
    .replace('claude-3-haiku-20240307', 'Claude 3 Haiku')
    .replace('gemini-2.5-flash', 'Gemini 2.5 Flash')
    .replace('gemini-2.0-flash', 'Gemini 2.0 Flash')
    .replace('gemini-1.5-pro', 'Gemini 1.5 Pro');
}

export default function AIConfigurationSection({ organizationId }: AIConfigurationSectionProps) {
  const { toast } = useToast();

  const [providers, setProviders] = useState<AIProviderConfig[]>([]);
  const [loadingProviders, setLoadingProviders] = useState(true);

  const [usage, setUsage] = useState<AIUsageSummary | null>(null);
  const [loadingUsage, setLoadingUsage] = useState(true);

  const [logs, setLogs] = useState<any[]>([]);
  const [logsTotal, setLogsTotal] = useState(0);
  const [logsPage, setLogsPage] = useState(1);
  const [loadingLogs, setLoadingLogs] = useState(false);

  const [connectModal, setConnectModal] = useState<ProviderMeta | null>(null);
  const [modalApiKey, setModalApiKey] = useState('');
  const [modalModel, setModalModel] = useState('');
  const [modalCostCap, setModalCostCap] = useState(String(DEFAULT_COST_CAP));
  const [showApiKey, setShowApiKey] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; error?: string } | null>(null);
  const [saving, setSaving] = useState(false);

  const [settingDefault, setSettingDefault] = useState<string | null>(null);
  const [disconnecting, setDisconnecting] = useState<string | null>(null);

  const loadProviders = useCallback(async () => {
    try {
      const data = await api.getAIProviders(organizationId);
      setProviders(data);
    } catch {
      toast({ title: 'Failed to load AI providers', variant: 'destructive' });
    } finally {
      setLoadingProviders(false);
    }
  }, [organizationId, toast]);

  const loadUsage = useCallback(async () => {
    try {
      const data = await api.getAIUsage(organizationId);
      setUsage(data);
    } catch {
      /* usage may not be available yet */
    } finally {
      setLoadingUsage(false);
    }
  }, [organizationId]);

  const loadLogs = useCallback(async (page: number) => {
    setLoadingLogs(true);
    try {
      const data = await api.getAIUsageLogs(organizationId, page, LOGS_PER_PAGE);
      setLogs(data.logs);
      setLogsTotal(data.total);
    } catch {
      /* silent */
    } finally {
      setLoadingLogs(false);
    }
  }, [organizationId]);

  useEffect(() => { loadProviders(); }, [loadProviders]);
  useEffect(() => { loadUsage(); }, [loadUsage]);
  useEffect(() => { loadLogs(logsPage); }, [loadLogs, logsPage]);

  const providerMap = useMemo(() => {
    const map: Partial<Record<ProviderKey, AIProviderConfig>> = {};
    for (const p of providers) map[p.provider] = p;
    return map;
  }, [providers]);

  const openConnectModal = (provider: ProviderMeta) => {
    setConnectModal(provider);
    setModalApiKey('');
    setModalModel(provider.models[0]);
    setModalCostCap(String(DEFAULT_COST_CAP));
    setShowApiKey(false);
    setTesting(false);
    setTestResult(null);
    setSaving(false);
  };

  const closeConnectModal = () => {
    setConnectModal(null);
  };

  const handleTest = async () => {
    if (!connectModal || !modalApiKey.trim()) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testAIProvider(organizationId, connectModal.key, modalApiKey.trim(), modalModel || undefined);
      setTestResult(result);
    } catch (err: any) {
      setTestResult({ success: false, error: err.message || 'Connection test failed' });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!connectModal || !modalApiKey.trim()) return;
    setSaving(true);
    try {
      const cap = parseFloat(modalCostCap) || DEFAULT_COST_CAP;
      await api.addAIProvider(organizationId, connectModal.key, modalApiKey.trim(), modalModel || undefined, cap);
      toast({ title: `${connectModal.name} connected successfully` });
      closeConnectModal();
      await loadProviders();
    } catch (err: any) {
      toast({ title: 'Failed to connect provider', description: err.message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleSetDefault = async (providerId: string) => {
    setSettingDefault(providerId);
    try {
      await api.setDefaultAIProvider(organizationId, providerId);
      await loadProviders();
    } catch (err: any) {
      toast({ title: 'Failed to set default provider', description: err.message, variant: 'destructive' });
    } finally {
      setSettingDefault(null);
    }
  };

  const handleDisconnect = async (providerId: string, providerName: string) => {
    setDisconnecting(providerId);
    try {
      const result = await api.deleteAIProvider(organizationId, providerId);
      toast({ title: `${providerName} disconnected`, description: result.warning });
      await loadProviders();
    } catch (err: any) {
      toast({ title: 'Failed to disconnect', description: err.message, variant: 'destructive' });
    } finally {
      setDisconnecting(null);
    }
  };

  const costCapPercent = usage
    ? Math.min(100, (usage.totalEstimatedCost / (usage.monthlyCostCap || 1)) * 100)
    : 0;

  const featureEntries = usage ? Object.entries(usage.byFeature) : [];
  const maxFeatureCost = featureEntries.reduce((max, [, v]) => Math.max(max, v.cost), 0) || 1;

  const totalLogsPages = Math.ceil(logsTotal / LOGS_PER_PAGE);

  return (
    <div className="space-y-8 pt-8">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-foreground">AI Configuration</h2>
        <p className="mt-1 text-sm text-foreground-secondary">
          Connect your own API keys for AI-powered features like Aegis and Aider. Your keys are encrypted at rest and never shared.
        </p>
      </div>

      {/* Provider Cards */}
      <div>
        <h3 className="text-lg font-semibold text-foreground mb-4">Providers</h3>
        <div className="grid gap-4 sm:grid-cols-3">
          {PROVIDERS.map((meta) => {
            const config = providerMap[meta.key];
            const isConnected = !!config?.connected;
            const isDefault = !!config?.is_default;

            return (
              <div
                key={meta.key}
                className="rounded-lg border border-border bg-background-card p-5 flex flex-col gap-4"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-lg bg-background-subtle border border-border flex items-center justify-center text-lg font-semibold text-foreground-secondary">
                      {meta.icon}
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-foreground">{meta.name}</p>
                      <p className="text-xs text-foreground-secondary">{meta.description}</p>
                    </div>
                  </div>
                  {isConnected && (
                    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                      Connected
                    </span>
                  )}
                </div>

                {isConnected && config ? (
                  <div className="space-y-3">
                    {config.model_preference && (
                      <div className="text-xs text-foreground-secondary">
                        Model: <span className="text-foreground">{formatModelName(config.model_preference)}</span>
                      </div>
                    )}
                    <div className="text-xs text-foreground-secondary">
                      Cost cap: <span className="text-foreground">{formatCurrency(config.monthly_cost_cap)}/mo</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleSetDefault(config.id)}
                        disabled={isDefault || settingDefault === config.id}
                        className={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-md transition-colors ${
                          isDefault
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 cursor-default'
                            : 'border border-border text-foreground-secondary hover:text-foreground hover:bg-background-subtle'
                        }`}
                      >
                        {settingDefault === config.id ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : isDefault ? (
                          <Check className="h-3 w-3" />
                        ) : (
                          <Radio className="h-3 w-3" />
                        )}
                        {isDefault ? 'Default' : 'Set default'}
                      </button>

                      <button
                        onClick={() => handleDisconnect(config.id, meta.name)}
                        disabled={disconnecting === config.id}
                        className="flex items-center gap-1 text-xs font-medium px-2.5 py-1 rounded-md border border-border text-foreground-secondary hover:text-destructive hover:border-destructive/30 transition-colors"
                      >
                        {disconnecting === config.id ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <X className="h-3 w-3" />
                        )}
                        Disconnect
                      </button>
                    </div>
                  </div>
                ) : (
                  <Button
                    onClick={() => openConnectModal(meta)}
                    disabled={loadingProviders}
                    className="w-full mt-auto bg-background-subtle border border-border text-foreground hover:bg-background-subtle/80 h-8 text-xs"
                  >
                    <Key className="h-3.5 w-3.5 mr-1.5" />
                    Connect
                  </Button>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Cost explainer */}
      <div className="rounded-lg border border-border bg-background-card p-4 flex items-start gap-3">
        <AlertCircle className="h-4 w-4 text-foreground-secondary mt-0.5 flex-shrink-0" />
        <div className="text-xs text-foreground-secondary leading-relaxed">
          <p className="font-medium text-foreground mb-1">Bring Your Own Key (BYOK)</p>
          <p>
            AI features like Aegis and Aider use your organization's API keys.
            Costs are billed directly by each provider.
            Set a monthly cost cap per provider to prevent unexpected charges.
            Deptex tracks usage and will pause AI features when the cap is reached.
          </p>
        </div>
      </div>

      {/* AI Usage Dashboard */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <BarChart3 className="h-5 w-5 text-foreground-secondary" />
          <h3 className="text-lg font-semibold text-foreground">AI Usage Dashboard</h3>
        </div>

        {loadingUsage ? (
          <div className="grid gap-4 sm:grid-cols-2">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="rounded-lg border border-border bg-background-card p-5">
                <div className="h-4 w-24 bg-muted animate-pulse rounded mb-3" />
                <div className="h-6 w-32 bg-muted animate-pulse rounded" />
              </div>
            ))}
          </div>
        ) : usage ? (
          <div className="space-y-6">
            {/* Monthly Summary */}
            <div className="rounded-lg border border-border bg-background-card overflow-hidden">
              <div className="px-5 py-3 border-b border-border bg-black/20">
                <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <Zap className="h-4 w-4 text-foreground-secondary" />
                  Monthly Summary
                </h4>
              </div>
              <div className="p-5 space-y-5">
                <div className="grid gap-6 sm:grid-cols-3">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wider text-foreground-secondary mb-1">Total Tokens</p>
                    <p className="text-xl font-bold text-foreground">
                      {formatTokens(usage.totalInputTokens + usage.totalOutputTokens)}
                    </p>
                    <p className="text-xs text-foreground-secondary mt-0.5">
                      {formatTokens(usage.totalInputTokens)} in / {formatTokens(usage.totalOutputTokens)} out
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wider text-foreground-secondary mb-1">Estimated Cost</p>
                    <p className="text-xl font-bold text-foreground">{formatCurrency(usage.totalEstimatedCost)}</p>
                  </div>
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wider text-foreground-secondary mb-1">Cost Cap</p>
                    <p className="text-xl font-bold text-foreground">{formatCurrency(usage.monthlyCostCap)}</p>
                  </div>
                </div>

                {/* Progress bar */}
                <div>
                  <div className="flex items-center justify-between text-xs text-foreground-secondary mb-1.5">
                    <span>Usage against cap</span>
                    <span>{costCapPercent.toFixed(1)}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-background-subtle overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        costCapPercent > 90 ? 'bg-destructive' : costCapPercent > 70 ? 'bg-warning' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${costCapPercent}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Cost Breakdown by Feature */}
            {featureEntries.length > 0 && (
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <div className="px-5 py-3 border-b border-border bg-black/20">
                  <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Settings className="h-4 w-4 text-foreground-secondary" />
                    Cost Breakdown by Feature
                  </h4>
                </div>
                <div className="p-5 space-y-3">
                  {featureEntries.map(([feature, data]) => (
                    <div key={feature} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-foreground font-medium capitalize">{feature.replace(/_/g, ' ')}</span>
                        <span className="text-foreground-secondary">
                          {formatCurrency(data.cost)} &middot; {data.count} calls
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full bg-background-subtle overflow-hidden">
                        <div
                          className="h-full rounded-full bg-emerald-500/70 transition-all duration-300"
                          style={{ width: `${(data.cost / maxFeatureCost) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Cost by User */}
            {usage.byUser.length > 0 && (
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <div className="px-5 py-3 border-b border-border bg-black/20">
                  <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Users className="h-4 w-4 text-foreground-secondary" />
                    Cost by User
                  </h4>
                </div>
                <table className="w-full">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">User</th>
                      <th className="text-right px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Tokens</th>
                      <th className="text-right px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Cost</th>
                      <th className="text-right px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Requests</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {usage.byUser.map((u) => (
                      <tr key={u.userId} className="hover:bg-table-hover transition-colors">
                        <td className="px-5 py-2.5 text-sm text-foreground font-mono">{u.userId.slice(0, 8)}...</td>
                        <td className="px-5 py-2.5 text-sm text-foreground-secondary text-right">{formatTokens(u.tokens)}</td>
                        <td className="px-5 py-2.5 text-sm text-foreground text-right">{formatCurrency(u.cost)}</td>
                        <td className="px-5 py-2.5 text-sm text-foreground-secondary text-right">{u.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Recent Activity Log */}
            <div className="rounded-lg border border-border bg-background-card overflow-hidden">
              <div className="px-5 py-3 border-b border-border bg-black/20 flex items-center justify-between">
                <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <Clock className="h-4 w-4 text-foreground-secondary" />
                  Recent Activity
                </h4>
                {totalLogsPages > 1 && (
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setLogsPage((p) => Math.max(1, p - 1))}
                      disabled={logsPage <= 1 || loadingLogs}
                      className="h-7 w-7 rounded-md border border-border bg-background-card flex items-center justify-center text-foreground-secondary hover:bg-background-subtle disabled:opacity-40 transition-colors"
                    >
                      <ChevronLeft className="h-3.5 w-3.5" />
                    </button>
                    <span className="text-xs text-foreground-secondary px-2">
                      {logsPage} / {totalLogsPages}
                    </span>
                    <button
                      onClick={() => setLogsPage((p) => Math.min(totalLogsPages, p + 1))}
                      disabled={logsPage >= totalLogsPages || loadingLogs}
                      className="h-7 w-7 rounded-md border border-border bg-background-card flex items-center justify-center text-foreground-secondary hover:bg-background-subtle disabled:opacity-40 transition-colors"
                    >
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}
              </div>

              {loadingLogs ? (
                <div className="p-8 flex items-center justify-center">
                  <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
                </div>
              ) : logs.length === 0 ? (
                <div className="p-8 text-center text-sm text-foreground-secondary">No activity recorded yet.</div>
              ) : (
                <table className="w-full">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Timestamp</th>
                      <th className="text-left px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Feature</th>
                      <th className="text-left px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                      <th className="text-right px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Tokens</th>
                      <th className="text-right px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Cost</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {logs.map((log, i) => (
                      <tr key={log.id || i} className="hover:bg-table-hover transition-colors">
                        <td className="px-5 py-2.5 text-xs text-foreground-secondary whitespace-nowrap">
                          {log.created_at ? new Date(log.created_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
                        </td>
                        <td className="px-5 py-2.5 text-sm text-foreground capitalize">{(log.feature || '—').replace(/_/g, ' ')}</td>
                        <td className="px-5 py-2.5 text-sm text-foreground-secondary capitalize">{log.provider || '—'}</td>
                        <td className="px-5 py-2.5 text-sm text-foreground-secondary text-right">{formatTokens((log.input_tokens || 0) + (log.output_tokens || 0))}</td>
                        <td className="px-5 py-2.5 text-sm text-foreground text-right">{formatCurrency(log.estimated_cost || 0)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        ) : (
          <div className="rounded-lg border border-border bg-background-card p-8 text-center">
            <Shield className="h-8 w-8 text-foreground-secondary mx-auto mb-3" />
            <p className="text-sm text-foreground-secondary">Connect a provider to start tracking AI usage.</p>
          </div>
        )}
      </div>

      {/* Connect Provider Modal */}
      {connectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={closeConnectModal} />
          <div className="relative w-full max-w-md rounded-lg border border-border bg-background-card shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="h-8 w-8 rounded-lg bg-background-subtle border border-border flex items-center justify-center text-sm font-semibold text-foreground-secondary">
                  {connectModal.icon}
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-foreground">Connect {connectModal.name}</h3>
                  <p className="text-xs text-foreground-secondary">Enter your API key to connect</p>
                </div>
              </div>
              <button
                onClick={closeConnectModal}
                className="h-7 w-7 rounded-md flex items-center justify-center text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              {/* API Key */}
              <div>
                <label className="block text-xs font-medium text-foreground-secondary mb-1.5">API Key</label>
                <div className="relative">
                  <input
                    type={showApiKey ? 'text' : 'password'}
                    value={modalApiKey}
                    onChange={(e) => setModalApiKey(e.target.value)}
                    placeholder={`sk-...`}
                    className="w-full h-9 px-3 pr-9 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-foreground-muted focus:ring-2 focus:ring-primary/50 focus:border-primary outline-none transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setShowApiKey(!showApiKey)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-foreground-secondary hover:text-foreground transition-colors"
                  >
                    {showApiKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>

              {/* Model selector */}
              <div>
                <label className="block text-xs font-medium text-foreground-secondary mb-1.5">Preferred Model</label>
                <select
                  value={modalModel}
                  onChange={(e) => setModalModel(e.target.value)}
                  className="w-full h-9 px-3 bg-background border border-border rounded-md text-sm text-foreground focus:ring-2 focus:ring-primary/50 focus:border-primary outline-none transition-colors appearance-none cursor-pointer"
                >
                  {connectModal.models.map((m) => (
                    <option key={m} value={m}>{formatModelName(m)}</option>
                  ))}
                </select>
              </div>

              {/* Monthly cost cap */}
              <div>
                <label className="block text-xs font-medium text-foreground-secondary mb-1.5">Monthly Cost Cap (USD)</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-sm text-foreground-secondary">$</span>
                  <input
                    type="number"
                    min="1"
                    step="1"
                    value={modalCostCap}
                    onChange={(e) => setModalCostCap(e.target.value)}
                    className="w-full h-9 pl-7 pr-3 bg-background border border-border rounded-md text-sm text-foreground focus:ring-2 focus:ring-primary/50 focus:border-primary outline-none transition-colors"
                  />
                </div>
              </div>

              {/* Test result */}
              {testResult && (
                <div className={`flex items-start gap-2 rounded-md p-3 text-xs ${
                  testResult.success
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'bg-destructive/10 text-destructive border border-destructive/20'
                }`}>
                  {testResult.success ? <Check className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" /> : <AlertCircle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />}
                  <span>{testResult.success ? 'Connection successful. Your API key is valid.' : (testResult.error || 'Connection failed.')}</span>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between px-5 py-4 border-t border-border bg-black/20">
              <Button
                onClick={handleTest}
                disabled={!modalApiKey.trim() || testing}
                className="bg-background-subtle border border-border text-foreground hover:bg-background-subtle/80 h-8 text-xs"
              >
                {testing ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Zap className="h-3.5 w-3.5 mr-1.5" />}
                Test Connection
              </Button>
              <div className="flex items-center gap-2">
                <Button
                  onClick={closeConnectModal}
                  className="bg-transparent border border-border text-foreground-secondary hover:text-foreground hover:bg-background-subtle h-8 text-xs"
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleSave}
                  disabled={!modalApiKey.trim() || saving}
                  className="bg-primary text-primary-foreground border border-primary/50 hover:bg-primary/90 h-8 text-xs"
                >
                  {saving ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Key className="h-3.5 w-3.5 mr-1.5" />}
                  Connect
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
