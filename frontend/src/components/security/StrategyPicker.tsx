import React, { useState, useEffect } from 'react';
import { ChevronDown, ChevronUp, Sparkles, Clock, DollarSign, AlertTriangle } from 'lucide-react';
import { api, StrategyRecommendation } from '../../lib/api';

interface StrategyPickerProps {
  orgId: string;
  ecosystem: string;
  vulnerabilityType?: string;
  isDirect?: boolean;
  fixType: 'vulnerability' | 'semgrep' | 'secret';
  onSelectStrategy: (strategy: string) => void;
  onCancel: () => void;
}

export function StrategyPicker({
  orgId,
  ecosystem,
  vulnerabilityType,
  isDirect,
  fixType,
  onSelectStrategy,
  onCancel,
}: StrategyPickerProps) {
  const [recommendations, setRecommendations] = useState<StrategyRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [showReasoning, setShowReasoning] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    api.getStrategyRecommendations(orgId, { ecosystem, vulnerabilityType, isDirect, fixType })
      .then(({ recommendations: recs }) => {
        if (mounted) {
          setRecommendations(recs);
          if (recs.length > 0) setSelected(recs[0].strategy);
        }
      })
      .catch(() => {
        if (mounted) setRecommendations([]);
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => { mounted = false; };
  }, [orgId, ecosystem, vulnerabilityType, isDirect, fixType]);

  if (loading) {
    return (
      <div className="rounded-lg border border-[#27272a] bg-[#18181b] p-4">
        <div className="flex items-center gap-2 text-sm text-zinc-400">
          <Sparkles className="h-4 w-4 text-green-500 animate-pulse" />
          Loading strategy recommendations...
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-[#27272a] bg-[#18181b] p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-white">Choose Fix Strategy</h4>
        <button
          onClick={onCancel}
          className="text-xs text-zinc-500 hover:text-zinc-400 transition-colors"
        >
          Cancel
        </button>
      </div>

      <div className="space-y-1.5">
        {recommendations.map((rec, idx) => {
          const isTop = idx === 0;
          const isSelected = selected === rec.strategy;
          const pct = Math.round(rec.predictedSuccessRate * 100);

          return (
            <div key={rec.strategy}>
              <button
                onClick={() => setSelected(rec.strategy)}
                className={`w-full text-left rounded-lg border p-3 transition-all ${
                  isSelected
                    ? 'border-green-500/40 bg-green-500/5'
                    : isTop
                    ? 'border-green-500/20 bg-green-500/[0.02] hover:border-green-500/30'
                    : 'border-[#27272a] hover:border-[#3f3f46]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-white">{rec.displayName}</span>
                    {rec.isGlobalDefault ? (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-500">
                        Platform average
                      </span>
                    ) : (
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                        rec.confidence === 'high' ? 'bg-green-500/10 text-green-400' :
                        rec.confidence === 'medium' ? 'bg-amber-500/10 text-amber-400' :
                        'bg-zinc-800 text-zinc-500'
                      }`}>
                        {rec.confidence === 'high' ? 'High' : rec.confidence === 'medium' ? 'Medium' : 'Low'} confidence
                      </span>
                    )}
                  </div>
                  <span className="text-sm font-mono text-white">{pct}%</span>
                </div>

                <div className="mt-1.5 flex items-center gap-3">
                  <div className="flex-1 h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-green-500 transition-all"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-zinc-500 shrink-0">
                    <span className="flex items-center gap-0.5">
                      <Clock className="h-3 w-3" />
                      {Math.round(rec.avgDuration / 60)}m
                    </span>
                    <span className="flex items-center gap-0.5">
                      <DollarSign className="h-3 w-3" />
                      ${rec.avgCost.toFixed(2)}
                    </span>
                    {rec.basedOnSamples > 0 && (
                      <span>{rec.basedOnSamples} samples</span>
                    )}
                  </div>
                </div>

                {rec.warnings && rec.warnings.length > 0 && (
                  <div className="mt-1.5 space-y-0.5">
                    {rec.warnings.map((w, i) => (
                      <div key={i} className="flex items-center gap-1 text-[10px] text-amber-400">
                        <AlertTriangle className="h-3 w-3 shrink-0" />
                        {w}
                      </div>
                    ))}
                  </div>
                )}
              </button>

              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setShowReasoning(showReasoning === rec.strategy ? null : rec.strategy);
                }}
                className="flex items-center gap-1 px-3 py-1 text-[10px] text-zinc-500 hover:text-zinc-400 transition-colors"
              >
                {showReasoning === rec.strategy ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                Why this ranking?
              </button>

              {showReasoning === rec.strategy && (
                <div className="mx-3 mb-2 p-2 rounded bg-zinc-900 text-[11px] text-zinc-400 leading-relaxed">
                  {rec.reasoning}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {recommendations.length > 0 && recommendations[0].isGlobalDefault && (
        <p className="text-[10px] text-zinc-600 text-center">
          Aegis will learn your organization's patterns as more fixes are completed.
        </p>
      )}

      <button
        onClick={() => selected && onSelectStrategy(selected)}
        disabled={!selected}
        className="w-full py-2 rounded-lg text-sm font-medium bg-green-600 hover:bg-green-500 text-white flex items-center justify-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <Sparkles className="h-4 w-4" />
        Start Fix{selected ? ` with ${recommendations.find(r => r.strategy === selected)?.displayName}` : ''}
      </button>
    </div>
  );
}
