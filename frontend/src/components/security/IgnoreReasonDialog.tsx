import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '../ui/dialog';

export type IgnoreReason = 'false_positive' | 'wont_fix' | 'accepted_risk';

const REASONS: { value: IgnoreReason; label: string; desc: string }[] = [
  { value: 'false_positive', label: 'False positive', desc: 'Not a real issue in this codebase.' },
  { value: 'wont_fix', label: "Won't fix", desc: 'A real issue, but not one we plan to address.' },
  { value: 'accepted_risk', label: 'Accepted risk', desc: 'Understood and consciously accepted.' },
];

export interface IgnoreReasonDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Short label of the finding being ignored, shown in the prompt. */
  findingLabel: string;
  onConfirm: (reason: IgnoreReason, note: string) => Promise<void>;
}

/**
 * Ignore-a-finding dialog: pick a reason (false positive / won't fix / accepted
 * risk), add an optional note, confirm. Follows the house dialog pattern
 * (3-section flex, footer on a card header, green confirm = spinner-only while
 * submitting, outline Cancel on the left). Closes optimistically once onConfirm
 * resolves.
 */
export function IgnoreReasonDialog({ open, onOpenChange, findingLabel, onConfirm }: IgnoreReasonDialogProps) {
  const [reason, setReason] = useState<IgnoreReason>('false_positive');
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const reset = () => {
    setReason('false_positive');
    setNote('');
  };

  const handleOpenChange = (next: boolean) => {
    if (!next && !submitting) reset();
    onOpenChange(next);
  };

  const handleConfirm = async () => {
    setSubmitting(true);
    try {
      await onConfirm(reason, note.trim());
      reset();
      onOpenChange(false);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent hideClose className="sm:max-w-[480px] bg-background p-0 gap-0 max-h-[90vh] flex flex-col">
        <div className="px-6 pt-6 pb-4 flex-shrink-0">
          <DialogTitle>Ignore finding</DialogTitle>
          <DialogDescription className="mt-1">
            Hide <span className="text-foreground font-medium">{findingLabel}</span> from the open findings. It stays
            visible under All and survives rescans until you un-ignore it.
          </DialogDescription>
        </div>

        <div className="px-6 py-4 grid gap-4 overflow-y-auto flex-1 min-h-0">
          <div className="grid gap-2">
            <label className="text-sm font-medium text-foreground">Reason</label>
            <div className="grid gap-2">
              {REASONS.map((r) => {
                const active = reason === r.value;
                return (
                  <button
                    key={r.value}
                    type="button"
                    onClick={() => setReason(r.value)}
                    className={`flex flex-col items-start gap-0.5 rounded-lg border px-3 py-2.5 text-left transition-colors ${
                      active
                        ? 'border-emerald-500/40 bg-emerald-500/5'
                        : 'border-border bg-background-card hover:bg-table-hover'
                    }`}
                  >
                    <span className="text-sm font-medium text-foreground">{r.label}</span>
                    <span className="text-xs text-foreground-secondary">{r.desc}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid gap-2">
            <label htmlFor="ignore-note" className="text-sm font-medium text-foreground">
              Note <span className="font-normal text-foreground-secondary">(optional)</span>
            </label>
            <textarea
              id="ignore-note"
              rows={3}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Add context for your team…"
              className="w-full resize-none rounded-md border border-border bg-background-card px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary focus:border-foreground-secondary/50 focus:outline-none focus:ring-1 focus:ring-foreground-secondary/20"
            />
          </div>
        </div>

        <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:justify-between sm:rounded-b-lg">
          <Button
            variant="outline"
            className="h-8 rounded-lg px-3"
            disabled={submitting}
            onClick={() => handleOpenChange(false)}
          >
            Cancel
          </Button>
          <Button onClick={handleConfirm} variant="green" disabled={submitting} className="relative">
            <span className={submitting ? 'invisible' : undefined}>Ignore finding</span>
            {submitting && (
              <span className="absolute inset-0 flex items-center justify-center">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              </span>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
