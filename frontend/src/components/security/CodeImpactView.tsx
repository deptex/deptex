import { useState, useCallback } from 'react';
import { ChevronDown, ChevronRight, ArrowDown, Code2, Shield, ExternalLink, Sparkles, AlertTriangle } from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { api, type ReachableFlow, type ReachableFlowNode, type CodeContext } from '../../lib/api';

interface CodeImpactViewProps {
  flows: ReachableFlow[];
  organizationId: string;
  projectId: string;
  onExplainWithAegis?: (flow: ReachableFlow) => void;
}

function FlowNodeSnippet({
  node,
  index,
  isFirst,
  isLast,
  expanded,
  onToggle,
  codeContext,
  loading,
  onLoadContext,
}: {
  node: ReachableFlowNode;
  index: number;
  isFirst: boolean;
  isLast: boolean;
  expanded: boolean;
  onToggle: () => void;
  codeContext: CodeContext | null;
  loading: boolean;
  onLoadContext: () => void;
}) {
  const isExternal = node.isExternal ?? false;
  const fileName = node.parentFileName ?? 'unknown';
  const lineNum = node.lineNumber ?? 0;
  const methodName = node.parentMethodName ?? node.name ?? '';
  const codeLine = node.code ?? '';

  return (
    <div className="group">
      <div
        className={`border rounded-lg overflow-hidden ${
          isExternal
            ? 'border-red-500/20 bg-red-950/20'
            : 'border-zinc-800 bg-zinc-900/50'
        }`}
      >
        <div
          className="flex items-center gap-2 px-3 py-1.5 text-xs cursor-pointer hover:bg-zinc-800/50 transition-colors"
          onClick={onToggle}
        >
          {expanded ? (
            <ChevronDown className="h-3 w-3 text-zinc-500 shrink-0" />
          ) : (
            <ChevronRight className="h-3 w-3 text-zinc-500 shrink-0" />
          )}

          {isExternal ? (
            <ExternalLink className="h-3 w-3 text-red-400 shrink-0" />
          ) : (
            <Code2 className="h-3 w-3 text-zinc-400 shrink-0" />
          )}

          <span className="text-zinc-400 font-mono truncate">
            {fileName}
            {lineNum > 0 && <span className="text-zinc-600">:{lineNum}</span>}
          </span>

          {methodName && (
            <span className="text-zinc-300 font-mono text-[11px]">
              {methodName}()
            </span>
          )}

          {isFirst && node.tags && (
            <Badge variant="outline" className="text-[9px] h-4 px-1 border-amber-500/30 text-amber-400 bg-amber-950/30">
              {node.tags}
            </Badge>
          )}

          {isExternal && (
            <Badge variant="outline" className="text-[9px] h-4 px-1 border-red-500/30 text-red-400 bg-red-950/30">
              vulnerable dep
            </Badge>
          )}
        </div>

        {codeLine && (
          <div className="px-3 py-1.5 border-t border-zinc-800/50 bg-zinc-950/50">
            <pre className="text-[11px] font-mono text-zinc-300 overflow-x-auto whitespace-pre">
              {lineNum > 0 && (
                <span className="text-zinc-600 select-none mr-3">{lineNum}</span>
              )}
              {codeLine}
            </pre>
          </div>
        )}

        {expanded && codeContext && (
          <div className="border-t border-zinc-800/50 bg-zinc-950/70 px-3 py-2">
            <pre className="text-[11px] font-mono text-zinc-400 overflow-x-auto whitespace-pre">
              {codeContext.code.split('\n').map((line, i) => {
                const lineNo = codeContext.startLine + i;
                const isCallSite = lineNo === lineNum;
                return (
                  <div
                    key={i}
                    className={isCallSite ? 'bg-amber-500/10 text-zinc-200 -mx-3 px-3' : ''}
                  >
                    <span className="text-zinc-600 select-none inline-block w-8 text-right mr-3">
                      {lineNo}
                    </span>
                    {line}
                  </div>
                );
              })}
            </pre>
          </div>
        )}

        {expanded && !codeContext && (
          <div className="border-t border-zinc-800/50 px-3 py-2">
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-zinc-500 h-6"
              onClick={(e) => {
                e.stopPropagation();
                onLoadContext();
              }}
              disabled={loading}
            >
              {loading ? 'Loading...' : 'Show expanded context'}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

export function CodeImpactView({ flows, organizationId, projectId, onExplainWithAegis }: CodeImpactViewProps) {
  const [expandedFlowIdx, setExpandedFlowIdx] = useState<number>(0);
  const [expandedSteps, setExpandedSteps] = useState<Record<string, boolean>>({});
  const [codeContexts, setCodeContexts] = useState<Record<string, CodeContext | null>>({});
  const [loadingContexts, setLoadingContexts] = useState<Record<string, boolean>>({});
  const [collapsedMiddle, setCollapsedMiddle] = useState<Record<number, boolean>>({});

  const toggleStep = useCallback((flowIdx: number, stepIdx: number) => {
    const key = `${flowIdx}-${stepIdx}`;
    setExpandedSteps(prev => ({ ...prev, [key]: !prev[key] }));
  }, []);

  const loadCodeContext = useCallback(async (flowIdx: number, stepIdx: number, flowId: string) => {
    const key = `${flowIdx}-${stepIdx}`;
    if (codeContexts[key] || loadingContexts[key]) return;

    setLoadingContexts(prev => ({ ...prev, [key]: true }));
    try {
      const ctx = await api.getFlowCodeContext(organizationId, projectId, flowId, stepIdx);
      setCodeContexts(prev => ({ ...prev, [key]: ctx }));
    } catch {
      setCodeContexts(prev => ({ ...prev, [key]: null }));
    }
    setLoadingContexts(prev => ({ ...prev, [key]: false }));
  }, [organizationId, projectId, codeContexts, loadingContexts]);

  if (flows.length === 0) return null;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Shield className="h-3.5 w-3.5 text-orange-400" />
        <span className="text-xs font-medium text-zinc-300">
          Affected Code
        </span>
        <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-orange-500/30 text-orange-400 bg-orange-950/30">
          DATA FLOW TRACED
        </Badge>
      </div>

      {flows.map((flow, flowIdx) => {
        const nodes = flow.flow_nodes ?? [];
        const isExpanded = expandedFlowIdx === flowIdx;
        const showMiddle = !collapsedMiddle[flowIdx];
        const middleNodes = nodes.slice(1, -1);
        const hasMiddle = middleNodes.length > 0;
        const collapseMiddle = middleNodes.length > 3;

        return (
          <div key={flow.id} className="space-y-0">
            {flows.length > 1 && (
              <button
                className={`w-full text-left text-xs px-2 py-1 rounded mb-1 transition-colors ${
                  isExpanded ? 'text-zinc-300 bg-zinc-800/50' : 'text-zinc-500 hover:text-zinc-400 hover:bg-zinc-800/30'
                }`}
                onClick={() => setExpandedFlowIdx(isExpanded ? -1 : flowIdx)}
              >
                Flow {flowIdx + 1}: {flow.entry_point_file?.split('/').pop()}:{flow.entry_point_line}
                {' → '}
                {flow.sink_method ?? 'unknown'}
                <span className="text-zinc-600 ml-2">({nodes.length} steps)</span>
              </button>
            )}

            {(isExpanded || flows.length === 1) && (
              <div className="space-y-1.5 pl-1">
                {/* Entry point */}
                {nodes.length > 0 && (
                  <FlowNodeSnippet
                    node={nodes[0]}
                    index={0}
                    isFirst={true}
                    isLast={nodes.length === 1}
                    expanded={!!expandedSteps[`${flowIdx}-0`]}
                    onToggle={() => toggleStep(flowIdx, 0)}
                    codeContext={codeContexts[`${flowIdx}-0`] ?? null}
                    loading={!!loadingContexts[`${flowIdx}-0`]}
                    onLoadContext={() => loadCodeContext(flowIdx, 0, flow.id)}
                  />
                )}

                {/* Middle nodes (collapsible if > 3) */}
                {hasMiddle && (
                  <>
                    <div className="flex justify-center py-0.5">
                      <ArrowDown className="h-3 w-3 text-zinc-600" />
                    </div>

                    {collapseMiddle && !showMiddle ? (
                      <button
                        className="w-full text-center text-[10px] text-zinc-500 hover:text-zinc-400 py-1 transition-colors"
                        onClick={() => setCollapsedMiddle(prev => ({ ...prev, [flowIdx]: false }))}
                      >
                        {middleNodes.length} intermediate steps (click to expand)
                      </button>
                    ) : (
                      <>
                        {middleNodes.map((node, mi) => {
                          const stepIdx = mi + 1;
                          return (
                            <div key={stepIdx}>
                              <FlowNodeSnippet
                                node={node}
                                index={stepIdx}
                                isFirst={false}
                                isLast={false}
                                expanded={!!expandedSteps[`${flowIdx}-${stepIdx}`]}
                                onToggle={() => toggleStep(flowIdx, stepIdx)}
                                codeContext={codeContexts[`${flowIdx}-${stepIdx}`] ?? null}
                                loading={!!loadingContexts[`${flowIdx}-${stepIdx}`]}
                                onLoadContext={() => loadCodeContext(flowIdx, stepIdx, flow.id)}
                              />
                              {mi < middleNodes.length - 1 && (
                                <div className="flex justify-center py-0.5">
                                  <ArrowDown className="h-3 w-3 text-zinc-600" />
                                </div>
                              )}
                            </div>
                          );
                        })}
                        {collapseMiddle && showMiddle && (
                          <button
                            className="w-full text-center text-[10px] text-zinc-500 hover:text-zinc-400 py-0.5 transition-colors"
                            onClick={() => setCollapsedMiddle(prev => ({ ...prev, [flowIdx]: true }))}
                          >
                            Collapse intermediate steps
                          </button>
                        )}
                      </>
                    )}
                  </>
                )}

                {/* Sink node */}
                {nodes.length > 1 && (
                  <>
                    <div className="flex justify-center py-0.5">
                      <ArrowDown className="h-3 w-3 text-zinc-600" />
                    </div>
                    <FlowNodeSnippet
                      node={nodes[nodes.length - 1]}
                      index={nodes.length - 1}
                      isFirst={false}
                      isLast={true}
                      expanded={!!expandedSteps[`${flowIdx}-${nodes.length - 1}`]}
                      onToggle={() => toggleStep(flowIdx, nodes.length - 1)}
                      codeContext={codeContexts[`${flowIdx}-${nodes.length - 1}`] ?? null}
                      loading={!!loadingContexts[`${flowIdx}-${nodes.length - 1}`]}
                      onLoadContext={() => loadCodeContext(flowIdx, nodes.length - 1, flow.id)}
                    />
                  </>
                )}

                {/* Actions */}
                <div className="flex items-center gap-2 pt-1">
                  {onExplainWithAegis && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-xs h-7 text-zinc-400 hover:text-zinc-200"
                      onClick={() => onExplainWithAegis(flow)}
                    >
                      <Sparkles className="h-3 w-3 mr-1" />
                      Explain with Aegis
                    </Button>
                  )}
                </div>
              </div>
            )}
          </div>
        );
      })}

      <p className="text-[10px] text-zinc-600 flex items-center gap-1">
        <AlertTriangle className="h-2.5 w-2.5" />
        Analysis may vary between runs. Data flow reaches the package but may not target the specific vulnerable function.
      </p>
    </div>
  );
}
