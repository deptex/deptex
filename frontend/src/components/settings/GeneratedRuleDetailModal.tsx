import { useEffect, useMemo, useState } from 'react';
import MonacoEditor, { type BeforeMount } from '@monaco-editor/react';
import {
  Loader2, AlertCircle, CheckCircle2, Clock, ShieldCheck, RefreshCw, History, X, ChevronRight,
} from 'lucide-react';
import {
  api,
  type GeneratedRuleDetail,
  type GeneratedRulePreviousVersion,
  type ReachabilitySettings,
} from '../../lib/api';
import { Button } from '../ui/button';
import { Dialog, DialogContent } from '../ui/dialog';
import { Badge } from '../ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';

interface GeneratedRuleDetailModalProps {
  organizationId: string;
  ruleId: string | null;
  settings: ReachabilitySettings | null;
  onClose: () => void;
  onChanged: () => void;
  canManage: boolean;
}

const PROVIDER_MODELS: Record<'anthropic' | 'openai' | 'google', { value: string; label: string }[]> = {
  anthropic: [
    { value: 'claude-sonnet-4-6', label: 'Claude Sonnet 4.6' },
    { value: 'claude-haiku-4-5-20251001', label: 'Claude Haiku 4.5' },
    { value: 'claude-3-5-sonnet-20241022', label: 'Claude 3.5 Sonnet' },
  ],
  openai: [
    { value: 'gpt-4o', label: 'GPT-4o' },
    { value: 'gpt-4o-mini', label: 'GPT-4o Mini' },
    { value: 'o1-mini', label: 'o1 Mini' },
  ],
  google: [
    { value: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash' },
    { value: 'gemini-1.5-pro', label: 'Gemini 1.5 Pro' },
  ],
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

function statusVariant(status: string): 'success' | 'warning' | 'destructive' | 'default' {
  switch (status) {
    case 'validated': return 'success';
    case 'pending': return 'warning';
    case 'failed_validation': return 'destructive';
    case 'manual_override': return 'default';
    default: return 'default';
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'validated': return 'Validated';
    case 'pending': return 'Pending';
    case 'failed_validation': return 'Validation failed';
    case 'manual_override': return 'Manual override';
    default: return status;
  }
}

const beforeMount: BeforeMount = (monaco) => {
  // Define the Deptex theme once per modal mount.
  monaco.editor.defineTheme('deptex-rule-detail', {
    base: 'vs-dark',
    inherit: true,
    rules: [],
    colors: {
      'editor.background': '#0b0b0e',
    },
  });
};

export default function GeneratedRuleDetailModal({
  organizationId,
  ruleId,
  settings,
  onClose,
  onChanged,
  canManage,
}: GeneratedRuleDetailModalProps) {
  const { toast } = useToast();
  const [rule, setRule] = useState<GeneratedRuleDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<'rule' | 'fixtures' | 'validation' | 'history'>('rule');
  const [regenProvider, setRegenProvider] = useState<'anthropic' | 'openai' | 'google'>('anthropic');
  const [regenModel, setRegenModel] = useState<string>('');
  const [regenBusy, setRegenBusy] = useState(false);
  const [overrideBusy, setOverrideBusy] = useState(false);
  const [expandedVersionIdx, setExpandedVersionIdx] = useState<number | null>(null);

  useEffect(() => {
    if (!ruleId) {
      setRule(null);
      setTab('rule');
      return;
    }
    setLoading(true);
    setRule(null);
    setTab('rule');
    setExpandedVersionIdx(null);
    api.getGeneratedRule(organizationId, ruleId)
      .then((data) => {
        setRule(data);
        // Default regen targets to current settings (or rule's own provider/model).
        const defaultProvider = settings?.ai_provider ?? (data.generated_with_provider as 'anthropic' | 'openai' | 'google');
        const defaultModel = settings?.ai_model ?? data.generated_with_model;
        setRegenProvider(defaultProvider);
        setRegenModel(defaultModel);
      })
      .catch((err: Error) => {
        toast({ title: 'Failed to load rule', description: err.message, variant: 'destructive' });
      })
      .finally(() => setLoading(false));
  }, [organizationId, ruleId, settings, toast]);

  const validationLogPretty = useMemo(() => {
    if (!rule?.validation_log) return null;
    try {
      return JSON.stringify(rule.validation_log, null, 2);
    } catch {
      return String(rule.validation_log);
    }
  }, [rule]);

  const handleRegenerate = async () => {
    if (!rule || !regenProvider || !regenModel.trim()) return;
    setRegenBusy(true);
    try {
      const result = await api.regenerateGeneratedRule(organizationId, rule.id, {
        provider: regenProvider,
        model: regenModel.trim(),
      });
      setRule(result.rule);
      onChanged();
      toast({
        title: 'Regeneration queued',
        description: result.message,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to queue regeneration';
      toast({ title: 'Regeneration failed', description: message, variant: 'destructive' });
    } finally {
      setRegenBusy(false);
    }
  };

  const handleManualOverride = async () => {
    if (!rule) return;
    setOverrideBusy(true);
    try {
      const updated = await api.updateGeneratedRule(organizationId, rule.id, {
        validation_status: 'manual_override',
      });
      setRule({ ...rule, ...updated });
      onChanged();
      toast({ title: 'Marked as manual override' });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to override';
      toast({ title: 'Override failed', description: message, variant: 'destructive' });
    } finally {
      setOverrideBusy(false);
    }
  };

  const isOpen = ruleId != null;
  const previousVersions = rule?.previous_versions ?? [];

  return (
    <Dialog open={isOpen} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent
        hideClose
        className="sm:max-w-[920px] bg-background p-0 gap-0 overflow-hidden max-h-[88vh] flex flex-col"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-border flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            {rule ? (
              <>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-base font-semibold text-foreground">{rule.cve_id}</span>
                  <Badge variant={statusVariant(rule.validation_status)}>
                    {statusLabel(rule.validation_status)}
                  </Badge>
                  {!rule.enabled && <Badge variant="muted">Disabled</Badge>}
                </div>
                <div className="mt-1.5 flex items-center gap-3 text-xs text-foreground-secondary flex-wrap">
                  <span className="font-mono truncate" title={rule.package_purl}>{rule.package_purl}</span>
                  <span>·</span>
                  <span className="capitalize">{rule.ecosystem}</span>
                  <span>·</span>
                  <span>{rule.reachability_level}</span>
                </div>
              </>
            ) : (
              <div className="h-5 w-48 bg-muted/40 animate-pulse rounded" />
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-foreground-secondary hover:text-foreground p-1 -m-1"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Metadata strip */}
        {rule && (
          <div className="px-6 py-3 border-b border-border grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <p className="text-foreground-secondary mb-0.5">Generated</p>
              <p className="text-foreground tabular-nums">{formatDate(rule.generated_at)}</p>
            </div>
            <div>
              <p className="text-foreground-secondary mb-0.5">Model</p>
              <p className="text-foreground truncate" title={`${rule.generated_with_provider}/${rule.generated_with_model}`}>
                {rule.generated_with_provider} / {rule.generated_with_model}
              </p>
            </div>
            <div>
              <p className="text-foreground-secondary mb-0.5">Generation cost</p>
              <p className="text-foreground tabular-nums">${rule.generation_cost_usd.toFixed(4)}</p>
            </div>
            <div>
              <p className="text-foreground-secondary mb-0.5">Used in scans</p>
              <p className="text-foreground tabular-nums">{rule.use_count}</p>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="px-6 border-b border-border flex items-center gap-6">
          {([
            { id: 'rule', label: 'Rule YAML' },
            { id: 'fixtures', label: 'Fixtures' },
            { id: 'validation', label: 'Validation log' },
            { id: 'history', label: `History${previousVersions.length > 0 ? ` (${previousVersions.length})` : ''}` },
          ] as const).map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={cn(
                'pb-3 pt-3 text-sm font-medium transition-colors',
                tab === t.id
                  ? 'text-foreground border-b-2 border-foreground'
                  : 'text-foreground-secondary hover:text-foreground',
              )}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto custom-scrollbar">
          {loading ? (
            <div className="p-12 flex items-center justify-center">
              <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
            </div>
          ) : !rule ? (
            <div className="p-12 text-center text-sm text-foreground-secondary">Rule not available.</div>
          ) : (
            <>
              {tab === 'rule' && (
                <div className="p-6">
                  <MonacoEditor
                    height="380px"
                    defaultLanguage="yaml"
                    value={rule.rule_yaml}
                    theme="deptex-rule-detail"
                    beforeMount={beforeMount}
                    options={{
                      readOnly: true,
                      minimap: { enabled: false },
                      fontSize: 12,
                      wordWrap: 'on',
                      scrollBeyondLastLine: false,
                      lineNumbers: 'on',
                      renderLineHighlight: 'none',
                      padding: { top: 12, bottom: 12 },
                    }}
                  />
                </div>
              )}

              {tab === 'fixtures' && (
                <div className="p-6 grid gap-6">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-semibold text-foreground">Vulnerable fixture</h4>
                      <span className="text-xs text-foreground-secondary">Must be matched by the rule.</span>
                    </div>
                    <MonacoEditor
                      height="180px"
                      defaultLanguage="plaintext"
                      value={rule.vulnerable_fixture}
                      theme="deptex-rule-detail"
                      beforeMount={beforeMount}
                      options={{
                        readOnly: true,
                        minimap: { enabled: false },
                        fontSize: 12,
                        wordWrap: 'on',
                        scrollBeyondLastLine: false,
                        lineNumbers: 'on',
                        renderLineHighlight: 'none',
                        padding: { top: 12, bottom: 12 },
                      }}
                    />
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-semibold text-foreground">Safe fixture</h4>
                      <span className="text-xs text-foreground-secondary">Must not be matched by the rule.</span>
                    </div>
                    <MonacoEditor
                      height="180px"
                      defaultLanguage="plaintext"
                      value={rule.safe_fixture}
                      theme="deptex-rule-detail"
                      beforeMount={beforeMount}
                      options={{
                        readOnly: true,
                        minimap: { enabled: false },
                        fontSize: 12,
                        wordWrap: 'on',
                        scrollBeyondLastLine: false,
                        lineNumbers: 'on',
                        renderLineHighlight: 'none',
                        padding: { top: 12, bottom: 12 },
                      }}
                    />
                  </div>
                </div>
              )}

              {tab === 'validation' && (
                <div className="p-6">
                  {!validationLogPretty ? (
                    <div className="text-center py-12">
                      <Clock className="h-10 w-10 text-foreground-secondary mx-auto mb-3" />
                      <p className="text-sm text-foreground">No validation log yet</p>
                      <p className="text-xs text-foreground-secondary mt-1">
                        The pipeline records its decisions here after the next scan.
                      </p>
                    </div>
                  ) : (
                    <pre className="text-xs font-mono bg-background-card border border-border rounded-md p-4 whitespace-pre-wrap break-words text-foreground/90 overflow-x-auto">
                      {validationLogPretty}
                    </pre>
                  )}
                </div>
              )}

              {tab === 'history' && (
                <div className="p-6">
                  {previousVersions.length === 0 ? (
                    <div className="text-center py-12">
                      <History className="h-10 w-10 text-foreground-secondary mx-auto mb-3" />
                      <p className="text-sm text-foreground">No previous versions</p>
                      <p className="text-xs text-foreground-secondary mt-1">
                        Earlier rule versions appear here after a regeneration.
                      </p>
                    </div>
                  ) : (
                    <ul className="space-y-2">
                      {previousVersions.map((v, idx) => (
                        <PreviousVersionRow
                          key={`${v.replaced_at}-${idx}`}
                          version={v}
                          expanded={expandedVersionIdx === idx}
                          onToggle={() => setExpandedVersionIdx((cur) => (cur === idx ? null : idx))}
                        />
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        {rule && (
          <div className="px-6 py-4 border-t border-border bg-background flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="flex items-center gap-2 flex-wrap">
              {rule.validation_status === 'failed_validation' && canManage && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleManualOverride}
                  disabled={overrideBusy}
                  className="text-xs gap-1.5"
                >
                  {overrideBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                  Force enable (manual override)
                </Button>
              )}
            </div>
            {canManage && (
              <div className="flex items-center gap-2 flex-wrap">
                <Select value={regenProvider} onValueChange={(v) => {
                  const p = v as 'anthropic' | 'openai' | 'google';
                  setRegenProvider(p);
                  setRegenModel(PROVIDER_MODELS[p][0]?.value ?? '');
                }}>
                  <SelectTrigger className="h-8 text-xs w-[120px]">
                    <SelectValue placeholder="Provider" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="anthropic">Anthropic</SelectItem>
                    <SelectItem value="openai">OpenAI</SelectItem>
                    <SelectItem value="google">Google</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={regenModel} onValueChange={setRegenModel}>
                  <SelectTrigger className="h-8 text-xs w-[200px]">
                    <SelectValue placeholder="Model" />
                  </SelectTrigger>
                  <SelectContent>
                    {PROVIDER_MODELS[regenProvider].map((m) => (
                      <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  size="sm"
                  onClick={handleRegenerate}
                  disabled={regenBusy || !regenModel.trim()}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 text-xs gap-1.5"
                >
                  {regenBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                  Regenerate
                </Button>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

interface PreviousVersionRowProps {
  version: GeneratedRulePreviousVersion;
  expanded: boolean;
  onToggle: () => void;
}

function PreviousVersionRow({ version, expanded, onToggle }: PreviousVersionRowProps) {
  return (
    <li className="rounded-md border border-border bg-background-card overflow-hidden">
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-background-subtle/40 transition-colors"
      >
        <ChevronRight
          className={cn(
            'h-3.5 w-3.5 text-foreground-secondary shrink-0 transition-transform',
            expanded && 'rotate-90',
          )}
        />
        <div className="flex-1 min-w-0 grid sm:grid-cols-3 gap-3 items-center">
          <span className="text-sm text-foreground tabular-nums">{formatDate(version.replaced_at)}</span>
          <span className="text-xs text-foreground-secondary truncate">
            {version.generated_with_provider} / {version.generated_with_model}
          </span>
          <span className="text-xs flex items-center gap-1.5">
            {version.validation_status === 'validated' ? (
              <CheckCircle2 className="h-3 w-3 text-green-500" />
            ) : version.validation_status === 'failed_validation' ? (
              <AlertCircle className="h-3 w-3 text-destructive" />
            ) : (
              <Clock className="h-3 w-3 text-foreground-secondary" />
            )}
            <span className="text-foreground-secondary">{statusLabel(version.validation_status)}</span>
          </span>
        </div>
      </button>
      {expanded && (
        <div className="border-t border-border p-4 grid gap-3 bg-background">
          <div>
            <p className="text-xs font-medium text-foreground-secondary mb-1.5">Rule YAML</p>
            <pre className="text-xs font-mono bg-background-card border border-border rounded p-3 whitespace-pre-wrap break-words text-foreground/90 overflow-x-auto max-h-48 overflow-y-auto custom-scrollbar">
              {version.rule_yaml}
            </pre>
          </div>
          <div className="grid gap-1 text-xs text-foreground-secondary">
            <span>Generation cost: <span className="text-foreground tabular-nums">${version.generation_cost_usd.toFixed(4)}</span></span>
            <span>Originally generated: <span className="text-foreground">{formatDate(version.generated_at)}</span></span>
          </div>
        </div>
      )}
    </li>
  );
}
