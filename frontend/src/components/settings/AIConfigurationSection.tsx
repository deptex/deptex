import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Key, Check, X, AlertCircle, Loader2, BarChart3,
  Users, Clock, Settings, Shield, Zap, ChevronLeft,
  ChevronRight, Eye, EyeOff, Radio, Plus, SlidersHorizontal,
} from 'lucide-react';
import { SiOpenai, SiAnthropic, SiGoogle } from '@icons-pack/react-simple-icons';
import { api, AIProviderConfig, AIUsageSummary } from '../../lib/api';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '../ui/dialog';
import { Label } from '../ui/label';
import { Input } from '../ui/input';
import { cn } from '../../lib/utils';
import { useToast } from '../../hooks/use-toast';

interface AIConfigurationSectionProps {
  organizationId: string;
}

type ProviderKey = 'openai' | 'anthropic' | 'google';

const PROVIDER_ICONS = {
  openai: SiOpenai,
  anthropic: SiAnthropic,
  google: SiGoogle,
} as const;

const PROVIDER_COLORS: Record<ProviderKey, string> = {
  openai: '#10a37f',
  anthropic: '#cc785c',
  google: '#4285F4',
};

interface ProviderMeta {
  key: ProviderKey;
  name: string;
  description: string;
  models: string[];
}

const PROVIDERS: ProviderMeta[] = [
  {
    key: 'openai',
    name: 'OpenAI',
    description: 'GPT-4o, o1, and more',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-4.5', 'gpt-5', 'o1', 'o1-mini'],
  },
  {
    key: 'anthropic',
    name: 'Anthropic',
    description: 'Claude Sonnet, Haiku',
    models: ['claude-sonnet-4-20250514', 'claude-3-5-sonnet-20241022', 'claude-3-haiku-20240307'],
  },
  {
    key: 'google',
    name: 'Google',
    description: 'Gemini Flash & Pro',
    models: ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-pro'],
  },
];

const CUSTOM_OPENAI_MODELS = ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-4.5', 'gpt-5', 'o1', 'o1-mini'];

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
  const known: Record<string, string> = {
    'gpt-4o-mini': 'GPT-4o Mini',
    'gpt-4o': 'GPT-4o',
    'gpt-4-turbo': 'GPT-4 Turbo',
    'gpt-4.5': 'GPT-4.5',
    'gpt-5': 'GPT-5',
    'o1-mini': 'o1 Mini',
    'o1': 'o1',
    'claude-sonnet-4-20250514': 'Claude Sonnet 4',
    'claude-3-5-sonnet-20241022': 'Claude 3.5 Sonnet',
    'claude-3-haiku-20240307': 'Claude 3 Haiku',
    'gemini-2.5-flash': 'Gemini 2.5 Flash',
    'gemini-2.0-flash': 'Gemini 2.0 Flash',
    'gemini-1.5-pro': 'Gemini 1.5 Pro',
  };
  return known[model] ?? model.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
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
  const [customModalOpen, setCustomModalOpen] = useState(false);
  const [modalApiKey, setModalApiKey] = useState('');
  const [modalCostCap, setModalCostCap] = useState(String(DEFAULT_COST_CAP));
  const [modalDisplayName, setModalDisplayName] = useState('');
  const [modalApiRoute, setModalApiRoute] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; error?: string } | null>(null);
  const [saving, setSaving] = useState(false);

  const [settingDefault, setSettingDefault] = useState<string | null>(null);
  const [disconnecting, setDisconnecting] = useState<string | null>(null);
  const [updatingModelId, setUpdatingModelId] = useState<string | null>(null);
  const [aiConfigSubTab, setAiConfigSubTab] = useState<'providers' | 'usage'>('providers');

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
    for (const p of providers) {
      if (p.provider !== 'custom') map[p.provider as ProviderKey] = p;
    }
    return map;
  }, [providers]);

  const builtInMeta = (key: ProviderKey) => PROVIDERS.find((m) => m.key === key);

  const openConnectModal = (provider: ProviderMeta) => {
    setConnectModal(provider);
    setModalApiKey('');
    setModalCostCap(String(DEFAULT_COST_CAP));
    setShowApiKey(false);
    setTesting(false);
    setTestResult(null);
    setSaving(false);
  };

  const closeConnectModal = () => {
    setConnectModal(null);
  };

  const openCustomModal = () => {
    setCustomModalOpen(true);
    setModalDisplayName('');
    setModalApiRoute('');
    setModalApiKey('');
    setShowApiKey(false);
    setTesting(false);
    setTestResult(null);
    setSaving(false);
  };

  const closeCustomModal = () => {
    setCustomModalOpen(false);
  };

  const handleTest = async () => {
    if (!connectModal || !modalApiKey.trim()) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testAIProvider(organizationId, connectModal.key, modalApiKey.trim(), {});
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
      await api.addAIProvider(organizationId, connectModal.key, modalApiKey.trim(), {});
      toast({ title: `${connectModal.name} connected successfully` });
      closeConnectModal();
      await loadProviders();
    } catch (err: any) {
      toast({ title: 'Failed to connect provider', description: err.message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleTestCustom = async () => {
    if (!modalApiKey.trim() || !modalApiRoute.trim()) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testAIProvider(organizationId, 'custom', modalApiKey.trim(), { api_base_url: modalApiRoute.trim() });
      setTestResult(result);
    } catch (err: any) {
      setTestResult({ success: false, error: err.message || 'Connection test failed' });
    } finally {
      setTesting(false);
    }
  };

  const handleSaveCustom = async () => {
    if (!modalDisplayName.trim() || !modalApiKey.trim() || !modalApiRoute.trim()) return;
    setSaving(true);
    try {
      await api.addAIProvider(organizationId, 'custom', modalApiKey.trim(), {
        display_name: modalDisplayName.trim(),
        api_base_url: modalApiRoute.trim().replace(/\/$/, ''),
      });
      toast({ title: 'Custom provider added' });
      closeCustomModal();
      await loadProviders();
    } catch (err: any) {
      toast({ title: 'Failed to add custom provider', description: err.message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleModelChange = async (providerId: string, model: string) => {
    setUpdatingModelId(providerId);
    try {
      await api.updateAIProvider(organizationId, providerId, { model_preference: model || null });
      await loadProviders();
    } catch (err: any) {
      toast({ title: 'Failed to update model', description: err.message, variant: 'destructive' });
    } finally {
      setUpdatingModelId(null);
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
    <div className="space-y-6 pt-8">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">AI Configuration</h2>
      </div>

      {/* Sub-tabs – same style as Members / Notifications */}
      <div className="flex items-center gap-6 border-b border-border mb-6">
        <button
          type="button"
          onClick={() => setAiConfigSubTab('providers')}
          className={cn(
            'pb-3 text-sm font-medium transition-colors',
            aiConfigSubTab === 'providers'
              ? 'text-foreground border-b-2 border-foreground'
              : 'text-foreground-secondary hover:text-foreground'
          )}
        >
          Providers
        </button>
        <button
          type="button"
          onClick={() => setAiConfigSubTab('usage')}
          className={cn(
            'pb-3 text-sm font-medium transition-colors',
            aiConfigSubTab === 'usage'
              ? 'text-foreground border-b-2 border-foreground'
              : 'text-foreground-secondary hover:text-foreground'
          )}
        >
          Usage
        </button>
      </div>

      {aiConfigSubTab === 'providers' && (
        <>
          {/* Add providers – styled cards */}
          <div>
            <h3 className="text-lg font-semibold text-foreground mb-4">Add providers</h3>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {PROVIDERS.map((meta) => {
                const config = providerMap[meta.key];
                const isConnected = !!config?.connected;
                const color = PROVIDER_COLORS[meta.key];
                return (
                  <div
                    key={meta.key}
                    className="rounded-xl border border-border bg-background-card/80 p-5 flex flex-col gap-4 transition-colors hover:border-foreground-secondary/30 hover:bg-background-card"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="h-11 w-11 rounded-xl bg-background-subtle/80 flex items-center justify-center flex-shrink-0 [&>svg]:size-6" style={{ color }}>
                          {(() => {
                            const IconComponent = PROVIDER_ICONS[meta.key];
                            return IconComponent ? <IconComponent size={22} color={color} /> : null;
                          })()}
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-foreground truncate">{meta.name}</p>
                          <p className="text-xs text-foreground-secondary truncate">{meta.description}</p>
                        </div>
                      </div>
                      {isConnected && (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-500 flex-shrink-0">
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                          Connected
                        </span>
                      )}
                    </div>
                    {!isConnected && (
                      <Button
                        onClick={() => openConnectModal(meta)}
                        disabled={loadingProviders}
                        variant="outline"
                        className="w-full mt-auto h-9 text-sm font-medium rounded-lg bg-background-card/50 border-border text-foreground hover:bg-background-card/80 hover:border-foreground-secondary/30"
                      >
                        {loadingProviders ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <>
                            <Key className="h-4 w-4 mr-2" />
                            Connect
                          </>
                        )}
                      </Button>
                    )}
                  </div>
                );
              })}
              <div
                className="rounded-xl border border-border bg-background-card/80 p-5 flex flex-col gap-4 transition-colors hover:border-foreground-secondary/30 hover:bg-background-card"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="h-11 w-11 rounded-xl bg-background-subtle/80 flex items-center justify-center flex-shrink-0 text-violet-400">
                      <SlidersHorizontal className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-foreground truncate">Custom</p>
                      <p className="text-xs text-foreground-secondary truncate">OpenAI-compatible API</p>
                    </div>
                  </div>
                </div>
                <Button
                  onClick={openCustomModal}
                  disabled={loadingProviders}
                  variant="outline"
                  className="w-full mt-auto h-9 text-sm font-medium rounded-lg bg-background-card/50 border-border text-foreground hover:bg-background-card/80 hover:border-foreground-secondary/30"
                >
                  {loadingProviders ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <>
                      <Plus className="h-4 w-4 mr-2" />
                      Add custom
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>

          {/* Your providers: list with model + API route + actions */}
          {providers.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold text-foreground mb-4">Your providers</h3>
              <p className="text-sm text-foreground-secondary mb-4">Select which provider to use as default and choose the model for each.</p>
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                      <th className="text-left px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">API route</th>
                      <th className="text-left px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Model</th>
                      <th className="text-right px-5 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {providers.map((config) => {
                      const meta = config.provider !== 'custom' ? builtInMeta(config.provider as ProviderKey) : null;
                      const displayName = config.provider === 'custom' ? (config.display_name || 'Custom') : (meta?.name ?? config.provider);
                      const apiRoute = config.api_base_url || (config.provider === 'openai' ? 'api.openai.com' : config.provider === 'anthropic' ? 'api.anthropic.com' : config.provider === 'google' ? 'generativelanguage.googleapis.com' : '—');
                      const models = config.provider === 'custom' ? CUSTOM_OPENAI_MODELS : meta?.models ?? [];
                      const color = config.provider !== 'custom' ? PROVIDER_COLORS[config.provider as ProviderKey] : undefined;
                      return (
                        <tr key={config.id} className="hover:bg-table-hover transition-colors">
                          <td className="px-5 py-2.5">
                            <div className="flex items-center gap-2">
                              {config.provider !== 'custom' && PROVIDER_ICONS[config.provider as ProviderKey] ? (
                                <span className="flex items-center justify-center [&>svg]:size-4" style={{ color }}>
                                  {(() => {
                                    const IconComponent = PROVIDER_ICONS[config.provider as ProviderKey];
                                    return IconComponent ? <IconComponent size={16} color={color} /> : null;
                                  })()}
                                </span>
                              ) : (
                                <SlidersHorizontal className="h-4 w-4 text-violet-400" />
                              )}
                              <span className="text-sm font-medium text-foreground">{displayName}</span>
                              {config.is_default && (
                                <span className="text-xs font-medium text-emerald-400">Default</span>
                              )}
                            </div>
                          </td>
                          <td className="px-5 py-2.5 text-xs text-foreground-secondary font-mono max-w-[200px] truncate" title={apiRoute}>{apiRoute}</td>
                          <td className="px-5 py-2.5">
                            {models.length > 0 ? (
                              <select
                                value={config.model_preference || ''}
                                onChange={(e) => handleModelChange(config.id, e.target.value)}
                                disabled={updatingModelId === config.id}
                                className="h-8 px-2 pr-6 bg-background border border-border rounded-md text-xs text-foreground focus:ring-2 focus:ring-primary/50 focus:border-primary outline-none appearance-none cursor-pointer"
                              >
                                <option value="">Default</option>
                                {models.map((m) => (
                                  <option key={m} value={m}>{formatModelName(m)}</option>
                                ))}
                              </select>
                            ) : (
                              <span className="text-xs text-foreground-secondary">—</span>
                            )}
                            {updatingModelId === config.id && <Loader2 className="inline h-3 w-3 animate-spin ml-1 text-foreground-secondary" />}
                          </td>
                          <td className="px-5 py-2.5 text-right">
                            <div className="flex items-center justify-end gap-1">
                              <button
                                onClick={() => handleSetDefault(config.id)}
                                disabled={config.is_default || settingDefault === config.id}
                                className="flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-md border border-border text-foreground-secondary hover:text-foreground hover:bg-background-subtle disabled:opacity-50"
                              >
                                {settingDefault === config.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Radio className="h-3 w-3" />}
                                {config.is_default ? 'Default' : 'Set default'}
                              </button>
                              <button
                                onClick={() => handleDisconnect(config.id, displayName)}
                                disabled={disconnecting === config.id}
                                className="flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-md border border-border text-foreground-secondary hover:text-destructive hover:border-destructive/30"
                              >
                                {disconnecting === config.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <X className="h-3 w-3" />}
                                Disconnect
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div className="rounded-xl border border-border bg-background-card/50 p-4 flex items-start gap-3">
            <AlertCircle className="h-4 w-4 text-foreground-secondary mt-0.5 flex-shrink-0" />
            <div className="text-xs text-foreground-secondary leading-relaxed">
              <p className="font-medium text-foreground mb-1">Bring Your Own Key (BYOK)</p>
              <p>
                AI features like Aegis and Aider use your organization&apos;s API keys. Costs are billed directly by each provider.
                Custom providers use an OpenAI-compatible API endpoint.
              </p>
            </div>
          </div>
        </>
      )}

      {aiConfigSubTab === 'usage' && (
      <>
      <div className="space-y-10">
        {loadingUsage ? (
          <div className="grid gap-4 sm:grid-cols-3">
            {[0, 1, 2].map((i) => (
              <div key={i} className="rounded-xl border border-border bg-background-card/50 p-6">
                <div className="h-3 w-24 bg-muted/50 animate-pulse rounded mb-3" />
                <div className="h-8 w-28 bg-muted/50 animate-pulse rounded" />
              </div>
            ))}
          </div>
        ) : usage ? (
          <>
            {/* Stats row – three cards like BYOK tone */}
            <div className="grid gap-4 sm:grid-cols-3">
              <div className="rounded-xl border border-border bg-background-card/50 p-5">
                <p className="text-xs font-medium text-foreground-secondary mb-1">Total tokens</p>
                <p className="text-2xl font-semibold tracking-tight text-foreground">
                  {formatTokens(usage.totalInputTokens + usage.totalOutputTokens)}
                </p>
                <p className="text-xs text-foreground-secondary mt-1">
                  {formatTokens(usage.totalInputTokens)} in / {formatTokens(usage.totalOutputTokens)} out
                </p>
              </div>
              <div className="rounded-xl border border-border bg-background-card/50 p-5">
                <p className="text-xs font-medium text-foreground-secondary mb-1">Estimated cost</p>
                <p className="text-2xl font-semibold tracking-tight text-foreground">{formatCurrency(usage.totalEstimatedCost)}</p>
              </div>
              <div className="rounded-xl border border-border bg-background-card/50 p-5">
                <p className="text-xs font-medium text-foreground-secondary mb-1">Monthly cost cap</p>
                <p className="text-2xl font-semibold tracking-tight text-foreground">{formatCurrency(usage.monthlyCostCap)}</p>
              </div>
            </div>

            {/* Usage vs cap – compact */}
            <div className="rounded-xl border border-border bg-background-card/50 p-5">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium text-foreground">Usage against cap</span>
                <span className="text-sm tabular-nums text-foreground-secondary">{costCapPercent.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 rounded-full bg-background-subtle overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full transition-all duration-500',
                    costCapPercent > 90 ? 'bg-destructive' : costCapPercent > 70 ? 'bg-amber-500' : 'bg-foreground-secondary/60'
                  )}
                  style={{ width: `${Math.min(100, costCapPercent)}%` }}
                />
              </div>
            </div>

            {featureEntries.length > 0 && (
              <div className="rounded-xl border border-border bg-background-card/50 overflow-hidden">
                <div className="px-5 py-3 border-b border-border">
                  <h4 className="text-sm font-medium text-foreground">Cost by feature</h4>
                </div>
                <div className="p-5 space-y-3">
                  {featureEntries.map(([feature, data]) => (
                    <div key={feature} className="flex items-center justify-between gap-4">
                      <span className="text-sm text-foreground capitalize">{feature.replace(/_/g, ' ')}</span>
                      <span className="text-sm text-foreground-secondary tabular-nums">{formatCurrency(data.cost)} · {data.count} calls</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {usage.byUser.length > 0 && (
              <div className="rounded-xl border border-border bg-background-card/50 overflow-hidden">
                <div className="px-5 py-3 border-b border-border">
                  <h4 className="text-sm font-medium text-foreground">Cost by user</h4>
                </div>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left px-5 py-2.5 font-medium text-foreground-secondary">User</th>
                      <th className="text-right px-5 py-2.5 font-medium text-foreground-secondary">Tokens</th>
                      <th className="text-right px-5 py-2.5 font-medium text-foreground-secondary">Cost</th>
                      <th className="text-right px-5 py-2.5 font-medium text-foreground-secondary">Requests</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {usage.byUser.map((u) => (
                      <tr key={u.userId} className="hover:bg-background-subtle/30">
                        <td className="px-5 py-2.5 font-mono text-foreground">{u.userId.slice(0, 8)}…</td>
                        <td className="px-5 py-2.5 text-right text-foreground-secondary tabular-nums">{formatTokens(u.tokens)}</td>
                        <td className="px-5 py-2.5 text-right text-foreground tabular-nums">{formatCurrency(u.cost)}</td>
                        <td className="px-5 py-2.5 text-right text-foreground-secondary tabular-nums">{u.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Recent activity */}
            <div className="rounded-xl border border-border bg-background-card/50 overflow-hidden">
              <div className="px-5 py-3 border-b border-border flex items-center justify-between">
                <h4 className="text-sm font-medium text-foreground">Recent activity</h4>
                {totalLogsPages > 1 && (
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setLogsPage((p) => Math.max(1, p - 1))}
                      disabled={logsPage <= 1 || loadingLogs}
                      className="h-7 w-7 rounded-md border border-border flex items-center justify-center text-foreground-secondary hover:bg-background-subtle hover:text-foreground disabled:opacity-40"
                    >
                      <ChevronLeft className="h-3.5 w-3.5" />
                    </button>
                    <span className="text-xs text-foreground-secondary px-1.5">{logsPage}/{totalLogsPages}</span>
                    <button
                      onClick={() => setLogsPage((p) => Math.min(totalLogsPages, p + 1))}
                      disabled={logsPage >= totalLogsPages || loadingLogs}
                      className="h-7 w-7 rounded-md border border-border flex items-center justify-center text-foreground-secondary hover:bg-background-subtle hover:text-foreground disabled:opacity-40"
                    >
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}
              </div>
              {loadingLogs ? (
                <div className="p-10 flex items-center justify-center">
                  <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
                </div>
              ) : logs.length === 0 ? (
                <div className="p-10 flex flex-col items-center justify-center text-center">
                  <div className="h-12 w-12 rounded-full bg-background-subtle flex items-center justify-center mb-3">
                    <Clock className="h-6 w-6 text-foreground-secondary" />
                  </div>
                  <p className="text-sm font-medium text-foreground">No activity yet</p>
                  <p className="text-xs text-foreground-secondary mt-1 max-w-[260px]">Usage will appear here once you use Aegis or other AI features.</p>
                </div>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left px-5 py-2.5 font-medium text-foreground-secondary">Time</th>
                      <th className="text-left px-5 py-2.5 font-medium text-foreground-secondary">Feature</th>
                      <th className="text-left px-5 py-2.5 font-medium text-foreground-secondary">Provider</th>
                      <th className="text-right px-5 py-2.5 font-medium text-foreground-secondary">Tokens</th>
                      <th className="text-right px-5 py-2.5 font-medium text-foreground-secondary">Cost</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {logs.map((log, i) => (
                      <tr key={log.id || i} className="hover:bg-background-subtle/30">
                        <td className="px-5 py-2.5 text-foreground-secondary whitespace-nowrap">
                          {log.created_at ? new Date(log.created_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
                        </td>
                        <td className="px-5 py-2.5 text-foreground capitalize">{(log.feature || '—').replace(/_/g, ' ')}</td>
                        <td className="px-5 py-2.5 text-foreground-secondary capitalize">{log.provider || '—'}</td>
                        <td className="px-5 py-2.5 text-right text-foreground-secondary tabular-nums">{formatTokens((log.input_tokens || 0) + (log.output_tokens || 0))}</td>
                        <td className="px-5 py-2.5 text-right text-foreground tabular-nums">{formatCurrency(log.estimated_cost || 0)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        ) : (
          <div className="rounded-xl border border-border bg-background-card/50 p-12 flex flex-col items-center justify-center text-center">
            <div className="h-14 w-14 rounded-full bg-background-subtle flex items-center justify-center mb-4">
              <BarChart3 className="h-7 w-7 text-foreground-secondary" />
            </div>
            <p className="text-sm font-medium text-foreground">No usage data</p>
            <p className="text-xs text-foreground-secondary mt-1 max-w-[280px]">Connect a provider in the Providers tab to start tracking AI usage.</p>
          </div>
        )}
      </div>
      </>
      )}

      {/* Connect Provider Dialog – Integrations-style */}
      <Dialog open={!!connectModal} onOpenChange={(open) => { if (!open) closeConnectModal(); }}>
        <DialogContent hideClose className="sm:max-w-[440px] bg-background p-0 gap-0 overflow-hidden">
          {connectModal && (
            <>
              <div className="px-6 pt-6 pb-4 border-b border-border">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-xl bg-background-subtle flex items-center justify-center [&>svg]:size-5 flex-shrink-0" style={{ color: PROVIDER_COLORS[connectModal.key] }}>
                    {(() => {
                      const IconComponent = PROVIDER_ICONS[connectModal.key];
                      return IconComponent ? <IconComponent size={20} color={PROVIDER_COLORS[connectModal.key]} /> : null;
                    })()}
                  </div>
                  <div>
                    <DialogTitle>Connect {connectModal.name}</DialogTitle>
                    <DialogDescription className="mt-1">Enter your API key. Choose model in Your providers after connecting.</DialogDescription>
                  </div>
                </div>
              </div>

              <div className="px-6 py-4 grid gap-4 bg-background">
                <div className="grid gap-2">
                  <Label htmlFor="connect-api-key">API Key</Label>
                  <div className="relative">
                    <Input
                      id="connect-api-key"
                      type={showApiKey ? 'text' : 'password'}
                      value={modalApiKey}
                      onChange={(e) => setModalApiKey(e.target.value)}
                      placeholder="sk-..."
                      className="pr-9"
                    />
                    <button
                      type="button"
                      onClick={() => setShowApiKey(!showApiKey)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-foreground-secondary hover:text-foreground"
                    >
                      {showApiKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>
                <p className="text-xs text-foreground-secondary">View and manage monthly cost cap in the Usage tab.</p>
              </div>

              <DialogFooter className="px-6 py-4 bg-background">
                <Button variant="outline" onClick={closeConnectModal}>Cancel</Button>
                <Button
                  onClick={handleSave}
                  disabled={!modalApiKey.trim() || saving}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {saving ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Key className="h-3.5 w-3.5 mr-1.5" />}
                  Connect
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Custom provider Dialog – Integrations-style */}
      <Dialog open={customModalOpen} onOpenChange={(open) => { if (!open) closeCustomModal(); }}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden">
          <div className="px-6 pt-6 pb-4 border-b border-border">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-background-subtle flex items-center justify-center text-violet-400 flex-shrink-0">
                <SlidersHorizontal className="h-5 w-5" />
              </div>
              <div>
                <DialogTitle>Add custom provider</DialogTitle>
                <DialogDescription className="mt-1">OpenAI-compatible API. Enter a name, base URL, and API key.</DialogDescription>
              </div>
            </div>
          </div>

          <div className="px-6 py-4 grid gap-4 bg-background">
            <div className="grid gap-2">
              <Label htmlFor="custom-name">Name</Label>
              <Input
                id="custom-name"
                value={modalDisplayName}
                onChange={(e) => setModalDisplayName(e.target.value)}
                placeholder="e.g. Kimi K2"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="custom-api-route">API route</Label>
              <Input
                id="custom-api-route"
                type="url"
                value={modalApiRoute}
                onChange={(e) => setModalApiRoute(e.target.value)}
                placeholder="https://api.example.com/v1"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="custom-api-key">API Key</Label>
              <div className="relative">
                <Input
                  id="custom-api-key"
                  type={showApiKey ? 'text' : 'password'}
                  value={modalApiKey}
                  onChange={(e) => setModalApiKey(e.target.value)}
                  placeholder="sk-..."
                  className="pr-9"
                />
                <button
                  type="button"
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-foreground-secondary hover:text-foreground"
                >
                  {showApiKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>
          </div>

          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={closeCustomModal}>Cancel</Button>
            <Button
              onClick={handleSaveCustom}
              disabled={!modalDisplayName.trim() || !modalApiKey.trim() || !modalApiRoute.trim() || saving}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
            >
              {saving ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Plus className="h-3.5 w-3.5 mr-1.5" />}
              Add provider
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
