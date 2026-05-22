import { useEffect, useMemo, useRef, useState } from 'react';
import {
  api,
  type AIModelMetadata,
  type AIModelsResponse,
} from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';
import { AIProviderIcon, brandForModel } from '../ai-provider-icon';
import { Button } from '../ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '../ui/tooltip';

interface AISectionProps {
  organizationId: string;
  canManageSettings: boolean;
  // Retained for API compatibility with the parent; spending UI lives in the
  // Usage settings tab now.
  canViewSpending?: boolean;
}

// Bucket models into 4 cost tiers based on output price per 1M (output
// dominates spend for chat/agent use). Visualised as $/$$/$$$/$$$$ in the
// table so users compare cheap-vs-expensive at a glance instead of doing
// mental math on per-million pricing.
function costTier(outputPricePer1M: number): 1 | 2 | 3 | 4 {
  if (outputPricePer1M < 1.5) return 1;
  if (outputPricePer1M < 8) return 2;
  if (outputPricePer1M < 25) return 3;
  return 4;
}

export default function AISection({ organizationId, canManageSettings }: AISectionProps) {
  const { toast } = useToast();
  const [modelsState, setModelsState] = useState<AIModelsResponse | null>(null);
  const [modelsLoading, setModelsLoading] = useState(true);
  // Bumped on each PATCH so out-of-order responses can't clobber the latest
  // optimistic state.
  const requestSeq = useRef(0);

  useEffect(() => {
    let cancelled = false;
    setModelsLoading(true);
    api
      .getAIModels(organizationId)
      .then((data) => { if (!cancelled) setModelsState(data); })
      .catch((err: any) => {
        if (!cancelled) {
          toast({ title: 'Could not load AI models', description: err.message ?? 'Unknown error', variant: 'destructive' });
        }
      })
      .finally(() => { if (!cancelled) setModelsLoading(false); });
    return () => { cancelled = true; };
  }, [organizationId, toast]);

  const requireManage = () => {
    if (!canManageSettings) {
      toast({
        title: 'Permission required',
        description: 'You need permission to change AI model settings.',
        variant: 'destructive',
      });
      return false;
    }
    return true;
  };

  // Apply the local change instantly, then sync to the backend in the
  // background. On failure, revert and toast. requestSeq guards against
  // out-of-order responses overwriting a newer optimistic state.
  const patchModels = (
    optimistic: AIModelsResponse,
    patch: { defaultModel?: string; enabledModels?: string[] },
  ) => {
    const prev = modelsState;
    const seq = ++requestSeq.current;
    setModelsState(optimistic);
    api
      .updateAIModels(organizationId, patch)
      .then((next) => {
        if (requestSeq.current === seq) setModelsState(next);
      })
      .catch((err: any) => {
        if (requestSeq.current === seq) {
          if (prev) setModelsState(prev);
          toast({ title: 'Could not update model', description: err.message ?? 'Unknown error', variant: 'destructive' });
        }
      });
  };

  const handleSetDefault = (modelId: string) => {
    if (!modelsState || !requireManage()) return;
    if (modelsState.defaultModel === modelId) return;
    const willEnable = !modelsState.enabledModels.includes(modelId);
    const enabledModels = willEnable ? [...modelsState.enabledModels, modelId] : modelsState.enabledModels;
    patchModels(
      { ...modelsState, defaultModel: modelId, enabledModels },
      { defaultModel: modelId, ...(willEnable ? { enabledModels } : {}) },
    );
  };

  const handleToggle = (modelId: string, nextEnabled: boolean) => {
    if (!modelsState || !requireManage()) return;
    const isEnabled = modelsState.enabledModels.includes(modelId);
    if (isEnabled === nextEnabled) return;

    if (nextEnabled) {
      const enabledModels = [...modelsState.enabledModels, modelId];
      patchModels({ ...modelsState, enabledModels }, { enabledModels });
      return;
    }

    if (modelsState.enabledModels.length === 1) {
      toast({ title: 'At least one model must remain enabled', variant: 'destructive' });
      return;
    }

    const enabledModels = modelsState.enabledModels.filter((id) => id !== modelId);
    // If disabling the current default, auto-pick a new one (same provider preferred).
    let nextDefault = modelsState.defaultModel;
    if (modelsState.defaultModel === modelId) {
      const meta = modelsState.models.find((m) => m.id === modelId);
      const sameProviderEnabled = enabledModels.find((id) => modelsState.models.find((m) => m.id === id)?.provider === meta?.provider);
      nextDefault = sameProviderEnabled ?? enabledModels[0];
    }
    patchModels(
      { ...modelsState, enabledModels, defaultModel: nextDefault },
      { enabledModels, ...(nextDefault !== modelsState.defaultModel ? { defaultModel: nextDefault } : {}) },
    );
  };

  // Sort models newest-first by release date.
  const sortedModels = useMemo<AIModelMetadata[]>(() => {
    if (!modelsState) return [];
    return [...modelsState.models].sort((a, b) => b.releasedAt.localeCompare(a.releasedAt));
  }, [modelsState]);

  return (
    <TooltipProvider delayDuration={150}>
      <div className="space-y-8">
        <section className="space-y-3">
          <div>
            <h3 className="text-base font-semibold text-foreground">AI Models</h3>
            <p className="mt-0.5 text-xs text-foreground-secondary">Toggle which models Aegis can pick from.</p>
          </div>
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            {modelsLoading || !modelsState ? (
              <table className="w-full">
                <thead className="bg-background-card-header border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Model</th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-36">SWE-Bench</th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-24">Cost</th>
                    <th className="text-center px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-32">Enabled</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border" data-testid="ai-models-skeleton">
                  {[0, 1, 2, 3, 4].map((i) => (
                    <tr key={i}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="h-[18px] w-[18px] rounded-sm bg-muted animate-pulse shrink-0" />
                          <div className="min-w-0 space-y-1.5">
                            <div className="h-3.5 w-32 bg-muted animate-pulse rounded" />
                            <div className="h-3 w-48 bg-muted animate-pulse rounded opacity-60" />
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3"><div className="h-3.5 w-10 bg-muted animate-pulse rounded ml-auto" /></td>
                      <td className="px-4 py-3"><div className="h-3.5 w-12 bg-muted animate-pulse rounded ml-auto" /></td>
                      <td className="px-4 py-3"><div className="h-7 w-[68px] bg-muted animate-pulse rounded-md mx-auto" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <table className="w-full">
                <thead className="bg-background-card-header border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Model</th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-36">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="cursor-help underline decoration-dotted underline-offset-2 decoration-foreground-secondary/40">SWE-Bench</span>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="max-w-xs">
                          <div className="text-xs">
                            <p className="font-semibold mb-1">SWE-Bench Verified</p>
                            <p className="text-foreground-secondary">Industry benchmark measuring how often a model can resolve real GitHub issues end-to-end. Higher is better.</p>
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    </th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-24">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="cursor-help underline decoration-dotted underline-offset-2 decoration-foreground-secondary/40">Cost</span>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="max-w-xs">
                          <div className="text-xs">
                            <p className="font-semibold mb-1">Relative cost tier</p>
                            <p className="text-foreground-secondary">Hover a row's $ symbols for the exact input + output price per 1M tokens. Output dominates for chat &amp; agent workloads.</p>
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    </th>
                    <th className="text-center px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-32">Enabled</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {sortedModels.map((m) => (
                    <ModelRow
                      key={m.id}
                      model={m}
                      enabled={modelsState.enabledModels.includes(m.id)}
                      isDefault={modelsState.defaultModel === m.id}
                      canEdit={canManageSettings}
                      onSetDefault={handleSetDefault}
                      onToggle={handleToggle}
                    />
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </div>
    </TooltipProvider>
  );
}

function CostTier({ tier, inputPricePer1M, outputPricePer1M }: { tier: 1 | 2 | 3 | 4; inputPricePer1M: number; outputPricePer1M: number }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-baseline font-mono text-sm tabular-nums cursor-help">
          {[1, 2, 3, 4].map((i) => (
            <span key={i} className={cn(i <= tier ? 'text-foreground' : 'text-foreground/20')}>$</span>
          ))}
        </span>
      </TooltipTrigger>
      <TooltipContent side="left" className="max-w-xs">
        <div className="text-xs space-y-1">
          <div className="flex items-center justify-between gap-4">
            <span className="text-foreground-secondary">Input</span>
            <span className="font-mono text-foreground">${inputPricePer1M.toFixed(2)} / 1M</span>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-foreground-secondary">Output</span>
            <span className="font-mono text-foreground">${outputPricePer1M.toFixed(2)} / 1M</span>
          </div>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

interface ModelRowProps {
  model: AIModelMetadata;
  enabled: boolean;
  isDefault: boolean;
  canEdit: boolean;
  onSetDefault: (id: string) => void;
  onToggle: (id: string, enabled: boolean) => void;
}

function ModelRow({
  model: m,
  enabled,
  isDefault,
  canEdit,
  onSetDefault,
  onToggle,
}: ModelRowProps) {
  return (
    <tr className="group transition-colors hover:bg-table-hover">
      <td className="px-4 py-3">
        <div className="flex items-center gap-3">
          <AIProviderIcon brand={brandForModel(m)} size={18} className="shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <p className="text-sm font-semibold text-foreground truncate">{m.label}</p>
              {isDefault && (
                <span className="inline-flex items-center gap-1 rounded-full border border-border bg-background-subtle px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-foreground" />
                  Default
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <p className="text-xs text-foreground-secondary truncate">{m.description}</p>
              {!isDefault && enabled && canEdit && (
                <button
                  type="button"
                  onClick={() => onSetDefault(m.id)}
                  className="shrink-0 text-[11px] text-foreground-secondary underline-offset-2 opacity-0 transition-opacity hover:text-foreground hover:underline group-hover:opacity-100 focus:opacity-100"
                >
                  Set as default
                </button>
              )}
            </div>
          </div>
        </div>
      </td>
      <td className="px-4 py-3 text-right text-sm text-foreground tabular-nums">
        {m.sweBenchVerified != null ? `${m.sweBenchVerified.toFixed(1)}%` : <span className="text-foreground-secondary">—</span>}
      </td>
      <td className="px-4 py-3 text-right">
        <CostTier tier={costTier(m.outputPricePer1M)} inputPricePer1M={m.inputPricePer1M} outputPricePer1M={m.outputPricePer1M} />
      </td>
      <td className="px-4 py-3 text-center">
        <Button
          type="button"
          variant={enabled ? 'green' : 'outline'}
          disabled={!canEdit}
          onClick={() => onToggle(m.id, !enabled)}
          aria-pressed={enabled}
          className="!h-7 !px-2.5 !rounded-md text-xs"
        >
          {enabled ? 'Enabled' : 'Disabled'}
        </Button>
      </td>
    </tr>
  );
}
