import { useState, useEffect, useCallback } from 'react';
import { Loader2, FileText, ClipboardEdit, Ban } from 'lucide-react';
import { cn } from '../lib/utils';
import { Button } from './ui/button';
import { PolicyDiffViewer } from './PolicyDiffViewer';
import { Avatar, AvatarFallback, AvatarImage } from './ui/avatar';
import { RoleBadge } from './RoleBadge';

interface RequesterInfo {
  email: string;
  full_name: string | null;
  avatar_url?: string | null;
  role?: string;
  role_display_name?: string | null;
  role_color?: string | null;
}

interface ApplyModeProps {
  mode: 'apply';
  baseCode: string;
  requestedCode: string;
  onApply: (reason: string) => Promise<void>;
  onClose: () => void;
}

interface ReviewModeProps {
  mode: 'review';
  baseCode: string;
  requestedCode: string;
  projectName?: string;
  requester?: RequesterInfo;
  reason?: string;
  onAccept: () => Promise<void>;
  onReject: () => Promise<void>;
  onClose: () => void;
}

interface ViewModeProps {
  mode: 'view';
  baseCode: string;
  requestedCode: string;
  projectName?: string;
  requester?: RequesterInfo;
  reason?: string;
  status?: 'pending' | 'accepted' | 'rejected' | 'revoked';
  onRevoke?: () => Promise<void>;
  onClose: () => void;
}

type PolicyExceptionSidebarProps = ApplyModeProps | ReviewModeProps | ViewModeProps;

export function PolicyExceptionSidebar(props: PolicyExceptionSidebarProps) {
  const { mode, baseCode, requestedCode, onClose } = props;

  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [actionType, setActionType] = useState<'apply' | 'accept' | 'reject' | 'revoke' | null>(null);
  const [panelVisible, setPanelVisible] = useState(false);

  useEffect(() => {
    setPanelVisible(false);
    const raf = requestAnimationFrame(() => {
      requestAnimationFrame(() => setPanelVisible(true));
    });
    return () => cancelAnimationFrame(raf);
  }, []);

  const handleClose = useCallback(() => {
    setPanelVisible(false);
    setTimeout(onClose, 150);
  }, [onClose]);

  const handleApply = async () => {
    if (mode !== 'apply' || !reason.trim()) return;
    setSubmitting(true);
    setActionType('apply');
    try {
      await props.onApply(reason.trim());
    } catch {
      setSubmitting(false);
      setActionType(null);
    }
  };

  const handleAccept = async () => {
    if (mode !== 'review') return;
    setSubmitting(true);
    setActionType('accept');
    try {
      await props.onAccept();
    } catch {
      setSubmitting(false);
      setActionType(null);
    }
  };

  const handleReject = async () => {
    if (mode !== 'review') return;
    setSubmitting(true);
    setActionType('reject');
    try {
      await props.onReject();
    } catch {
      setSubmitting(false);
      setActionType(null);
    }
  };

  const handleRevoke = async () => {
    if (mode !== 'view' || !(props as ViewModeProps).onRevoke) return;
    setSubmitting(true);
    setActionType('revoke');
    try {
      await (props as ViewModeProps).onRevoke!();
    } catch {
      setSubmitting(false);
      setActionType(null);
    }
  };

  const showRevokeFooter = mode === 'view' && (props as ViewModeProps).status === 'accepted' && (props as ViewModeProps).onRevoke;

  return (
    <div className="fixed inset-0 z-50">
      <div
        className={cn(
          'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
          panelVisible ? 'opacity-100' : 'opacity-0'
        )}
        onClick={handleClose}
      />

      <div
        className={cn(
          'fixed right-4 top-4 bottom-4 w-full max-w-[720px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
          panelVisible ? 'translate-x-0' : 'translate-x-full'
        )}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 pt-5 pb-3 flex-shrink-0">
          <h2 className="text-xl font-bold text-foreground">
            {mode === 'apply' ? 'Apply for Exception' : mode === 'view' ? 'Exception Details' : 'Review Exception'}
          </h2>
          <p className="text-sm text-foreground-secondary mt-2">
            {mode === 'apply'
              ? 'Submit a request to use a different policy for this project.'
              : (
                <span className="flex items-center gap-2 flex-wrap">
                  {(props as ReviewModeProps & ViewModeProps).projectName && (
                    <span>{(props as ReviewModeProps & ViewModeProps).projectName}</span>
                  )}
                  {(props as ReviewModeProps & ViewModeProps).projectName && (props as ReviewModeProps & ViewModeProps).requester && (
                    <span> — </span>
                  )}
                  {(props as ReviewModeProps & ViewModeProps).requester && (() => {
                    const r = (props as ReviewModeProps & ViewModeProps).requester!;
                    const name = r.full_name || r.email || 'Unknown';
                    return (
                      <span className="inline-flex items-center gap-2">
                          <Avatar className="h-5 w-5">
                            <AvatarImage src={r.avatar_url ?? undefined} alt="" />
                            <AvatarFallback className="text-[10px] bg-background-subtle">
                              {name.charAt(0).toUpperCase()}
                            </AvatarFallback>
                          </Avatar>
                          <span>{name}</span>
                          {r.role && (
                            <RoleBadge
                              role={r.role}
                              roleDisplayName={r.role_display_name}
                              roleColor={r.role_color}
                            />
                          )}
                      </span>
                    );
                  })()}
                </span>
              )
            }
          </p>
        </div>

        <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
          <div className="space-y-6">
            {mode === 'apply' ? (
              <div className="space-y-3">
                <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                  <FileText className="h-5 w-5 text-foreground-secondary" />
                  Reason
                </label>
                <textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Explain why this project needs a different policy..."
                  rows={3}
                  className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all resize-none"
                  autoFocus
                  disabled={submitting}
                />
              </div>
            ) : ((props as ReviewModeProps & ViewModeProps).reason) ? (
                <div className="space-y-3">
                  <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                    <FileText className="h-5 w-5 text-foreground-secondary" />
                    Reason
                  </label>
                  <div className="px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground-secondary">
                    {(props as ReviewModeProps & ViewModeProps).reason}
                  </div>
                </div>
              ) : null}

            <div className="border-t border-border" />

            <div className="space-y-3">
              <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                Requested policy changes
              </label>
              <div className="rounded-lg overflow-hidden border border-border">
                <PolicyDiffViewer
                  baseCode={baseCode}
                  requestedCode={requestedCode}
                  minHeight="320px"
                />
              </div>
            </div>
          </div>
        </div>

        {(mode !== 'view' || showRevokeFooter) && (
          <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
            {mode === 'apply' ? (
              <>
                <Button
                  variant="outline"
                  onClick={handleClose}
                  disabled={submitting}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleApply}
                  disabled={submitting || !reason.trim()}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {submitting && actionType === 'apply' ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <ClipboardEdit className="h-4 w-4 mr-2" />
                  )}
                  Apply for Exception
                </Button>
              </>
            ) : mode === 'review' ? (
              <>
                <Button
                  variant="outline"
                  onClick={handleReject}
                  disabled={submitting}
                >
                  {submitting && actionType === 'reject' ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : null}
                  Reject
                </Button>
                <Button
                  onClick={handleAccept}
                  disabled={submitting}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {submitting && actionType === 'accept' ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : null}
                  Accept
                </Button>
              </>
            ) : showRevokeFooter ? (
              <Button
                variant="outline"
                onClick={handleRevoke}
                disabled={submitting}
                className="border-destructive/30 bg-destructive/10 text-destructive hover:bg-destructive/20 hover:border-destructive/50 hover:text-destructive shadow-sm"
              >
                {submitting && actionType === 'revoke' ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Ban className="h-4 w-4 mr-2" />
                )}
                Revoke Exception
              </Button>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}
