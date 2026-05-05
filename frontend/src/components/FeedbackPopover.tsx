import { useState } from 'react';
import { AlertTriangle, Lightbulb, HelpCircle } from 'lucide-react';
import { Popover, PopoverTrigger, PopoverContent } from './ui/popover';
import { Dialog, DialogContent, DialogTitle } from './ui/dialog';
import { Button } from './ui/button';
import { useToast } from '../hooks/use-toast';
import { useAuth } from '../contexts/AuthContext';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

type FeedbackType = 'issue' | 'idea' | null;

interface FeedbackPopoverProps {
  /** Optional controlled open state. When provided alongside onOpenChange, the component is fully controlled. */
  open?: boolean;
  onOpenChange?: (next: boolean) => void;
  /**
   * When true, the component renders as a centered Dialog with no built-in trigger button.
   * Use this when invoking from a parent dropdown / menu where Popover anchoring would be awkward.
   */
  hideTrigger?: boolean;
}

export default function FeedbackPopover({ open: controlledOpen, onOpenChange, hideTrigger = false }: FeedbackPopoverProps = {}) {
  const { session } = useAuth();
  const isControlled = controlledOpen !== undefined && onOpenChange !== undefined;
  const [internalOpen, setInternalOpen] = useState(false);
  const open = isControlled ? !!controlledOpen : internalOpen;
  const [step, setStep] = useState<'choose' | 'form'>('choose');
  const [type, setType] = useState<FeedbackType>(null);
  const [body, setBody] = useState('');
  const [sending, setSending] = useState(false);
  const { toast } = useToast();

  const handleChoose = (t: 'issue' | 'idea') => {
    setType(t);
    setStep('form');
    setBody('');
  };

  const handleOpenChange = (next: boolean) => {
    if (isControlled) onOpenChange?.(next);
    else setInternalOpen(next);
    if (!next) {
      setStep('choose');
      setType(null);
      setBody('');
    }
  };

  const handleSend = async () => {
    const text = body.trim();
    if (!type || !text) return;
    setSending(true);
    try {
      const headers: HeadersInit = { 'Content-Type': 'application/json' };
      if (session?.access_token) headers['Authorization'] = `Bearer ${session.access_token}`;

      const res = await fetch(`${API_BASE_URL}/api/feedback`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ type, body: text }),
      });
      if (!res.ok) throw new Error(res.statusText || 'Failed to send');
      toast({ title: 'Thanks!', description: 'Your feedback has been sent.' });
      handleOpenChange(false);
    } catch {
      toast({ title: 'Could not send feedback', description: 'Please try again or contact support.', variant: 'destructive' });
    } finally {
      setSending(false);
    }
  };

  const newOrgButtonClass =
    'bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40';

  const formContent = step === 'choose' ? (
    <>
      <div className="px-4 pt-4 pb-2">
        <h3 className="text-sm font-medium text-foreground">What would you like to share?</h3>
      </div>
      <div className="grid grid-cols-2 gap-2 p-4 pt-2">
        <button
          type="button"
          onClick={() => handleChoose('issue')}
          className="flex flex-col items-center gap-2 rounded-lg border border-border bg-background p-4 text-center hover:bg-background-subtle hover:border-foreground-secondary/50 transition-colors"
        >
          <AlertTriangle className="h-8 w-8 text-amber-500" />
          <div>
            <span className="text-sm font-medium text-foreground block">Issue</span>
            <span className="text-xs text-foreground-secondary">with my project</span>
          </div>
        </button>
        <button
          type="button"
          onClick={() => handleChoose('idea')}
          className="flex flex-col items-center gap-2 rounded-lg border border-border bg-background p-4 text-center hover:bg-background-subtle hover:border-foreground-secondary/50 transition-colors"
        >
          <Lightbulb className="h-8 w-8 text-amber-400" />
          <div>
            <span className="text-sm font-medium text-foreground block">Idea</span>
            <span className="text-xs text-foreground-secondary">to improve Deptex</span>
          </div>
        </button>
      </div>
    </>
  ) : (
    <>
      <div className="border-b border-border px-4 py-3">
        <h3 className="text-sm font-medium text-foreground">
          {type === 'issue' ? 'Describe the issue' : 'Share your idea'}
        </h3>
      </div>
      <div className="p-4 space-y-3">
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder={type === 'issue' ? 'What went wrong?' : 'My idea for improving Deptex is...'}
          rows={4}
          className="demo-page-input w-full rounded-md px-3 py-2.5 text-sm text-foreground shadow-sm transition-colors focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary resize-none min-h-[100px]"
        />
        <div className="flex items-center justify-between gap-2">
          <a
            href="/docs/help"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs text-foreground-secondary hover:text-foreground"
          >
            <HelpCircle className="h-3.5 w-3.5" />
            Get help instead
          </a>
          <Button
            size="sm"
            onClick={handleSend}
            disabled={!body.trim() || sending}
            className={`h-8 px-3.5 py-2 ${newOrgButtonClass}`}
          >
            {sending ? (
              <span className="inline-flex items-center gap-2">
                <span className="h-3 w-3 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                Send
              </span>
            ) : (
              'Send'
            )}
          </Button>
        </div>
      </div>
    </>
  );

  if (hideTrigger) {
    return (
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent hideClose className="sm:max-w-[420px] p-0 gap-0 overflow-hidden bg-background">
          <DialogTitle className="sr-only">Feedback</DialogTitle>
          {formContent}
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="rounded-md px-2 py-1.5 text-sm text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
        >
          Feedback
        </button>
      </PopoverTrigger>

      <PopoverContent align="end" className="w-[380px] p-0">
        {formContent}
      </PopoverContent>
    </Popover>
  );
}
