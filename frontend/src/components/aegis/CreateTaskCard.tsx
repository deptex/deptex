import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ListTodo, Check, X, Loader2, ArrowRight, AlertCircle } from 'lucide-react';
import { aegisApi } from '../../lib/aegis-api';

interface CreateTaskCardTarget {
  findingType: string;
  label: string;
}

interface CreateTaskCardProps {
  taskId: string;
  description?: string;
  targets?: CreateTaskCardTarget[];
  organizationId?: string;
}

type CardState = 'idle' | 'accepting' | 'accepted' | 'declining' | 'declined' | 'error';

const TYPE_LABEL: Record<string, string> = {
  vulnerability: 'Vuln',
  semgrep: 'Semgrep',
  secret: 'Secret',
};

/**
 * In-chat Create-Task card (the chat door). Accepting authorizes the whole job
 * — fixes auto-approve and the worker opens draft PRs; the merge is the human
 * gate. Accept navigates into the spawned task-chat ("watch it work").
 */
export function CreateTaskCard({ taskId, description, targets = [], organizationId }: CreateTaskCardProps) {
  const navigate = useNavigate();
  const [state, setState] = useState<CardState>('idle');
  const [error, setError] = useState<string | null>(null);
  const fixCount = targets.length;

  const handleAccept = async () => {
    if (!organizationId) return;
    setState('accepting');
    setError(null);
    try {
      const { threadId } = await aegisApi.acceptTask(taskId, organizationId);
      setState('accepted');
      window.dispatchEvent(new CustomEvent('aegis:taskListChanged'));
      window.dispatchEvent(new CustomEvent('aegis:threadListChanged'));
      if (threadId) navigate(`/organizations/${organizationId}/aegis/${threadId}`);
    } catch (e: any) {
      setState('error');
      setError(e?.message ?? 'Failed to accept task');
    }
  };

  const handleDecline = async () => {
    if (!organizationId) return;
    setState('declining');
    setError(null);
    try {
      await aegisApi.declineTask(taskId, organizationId);
      setState('declined');
      window.dispatchEvent(new CustomEvent('aegis:taskListChanged'));
    } catch (e: any) {
      setState('error');
      setError(e?.message ?? 'Failed to decline task');
    }
  };

  const terminal = state === 'accepted' || state === 'declined';

  return (
    <div className="my-2 w-full rounded-lg border border-border bg-background-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 pt-3 pb-2 border-b border-border/60">
        <ListTodo className="h-4 w-4 text-foreground-secondary shrink-0" />
        <span className="text-sm font-medium text-foreground">Create task</span>
        {fixCount > 0 && (
          <span className="ml-auto text-[11px] font-medium text-foreground-secondary">
            {fixCount} {fixCount === 1 ? 'finding' : 'findings'}
          </span>
        )}
      </div>

      <div className="px-4 py-3 space-y-2.5">
        {description && <p className="text-sm text-foreground/90 leading-relaxed">{description}</p>}

        {targets.length > 0 && (
          <ul className="space-y-1.5">
            {targets.map((t, i) => (
              <li key={i} className="flex items-center gap-2 text-sm text-foreground/80 min-w-0">
                <span className="shrink-0 rounded-sm border border-border bg-background-subtle px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-foreground-secondary">
                  {TYPE_LABEL[t.findingType] ?? t.findingType}
                </span>
                <span className="truncate">{t.label}</span>
              </li>
            ))}
          </ul>
        )}

        {fixCount > 0 && (
          <p className="text-xs text-foreground-secondary">
            Aegis will open {fixCount} draft {fixCount === 1 ? 'PR' : 'PRs'} — the merge stays your call.
          </p>
        )}

        {state === 'error' && error && (
          <div className="flex items-start gap-2 rounded-md border border-error/30 bg-error/[0.06] px-2.5 py-2 text-xs text-foreground/90">
            <AlertCircle className="h-3.5 w-3.5 shrink-0 text-error/80 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {!terminal ? (
        <div className="flex items-center gap-2 px-4 pb-3">
          <button
            type="button"
            onClick={handleAccept}
            disabled={state === 'accepting' || state === 'declining' || !organizationId}
            className="inline-flex items-center gap-1.5 rounded-md bg-foreground px-3 py-1.5 text-xs font-medium text-background hover:bg-foreground/90 transition-colors disabled:opacity-60"
          >
            {state === 'accepting' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            {state === 'accepting' ? 'Accepting' : 'Accept'}
          </button>
          <button
            type="button"
            onClick={handleDecline}
            disabled={state === 'accepting' || state === 'declining' || !organizationId}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-transparent px-3 py-1.5 text-xs font-medium text-foreground-secondary hover:bg-foreground/[0.05] transition-colors disabled:opacity-60"
          >
            {state === 'declining' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <X className="h-3.5 w-3.5" />}
            Decline
          </button>
        </div>
      ) : (
        <div className="px-4 pb-3">
          {state === 'accepted' ? (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-foreground-secondary">
              <Check className="h-3.5 w-3.5 text-emerald-500" /> Accepted
              <ArrowRight className="h-3 w-3" />
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-foreground-secondary">
              <X className="h-3.5 w-3.5" /> Declined
            </span>
          )}
        </div>
      )}
    </div>
  );
}
