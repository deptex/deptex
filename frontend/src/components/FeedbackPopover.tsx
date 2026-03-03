import { useState } from 'react';
import { MessageSquarePlus, AlertTriangle, Lightbulb, Send, HelpCircle } from 'lucide-react';
import { Popover, PopoverTrigger, PopoverContent } from './ui/popover';
import { Button } from './ui/button';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';
import { useToast } from '../hooks/use-toast';
import { useAuth } from '../contexts/AuthContext';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

type FeedbackType = 'issue' | 'idea' | null;

export default function FeedbackPopover() {
  const { session } = useAuth();
  const [open, setOpen] = useState(false);
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

  const handleBack = () => {
    setStep('choose');
    setType(null);
    setBody('');
  };

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
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

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <Tooltip>
        <TooltipTrigger asChild>
          <PopoverTrigger asChild>
            <button
              type="button"
              className="flex items-center justify-center rounded-md p-2 text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
            >
              <MessageSquarePlus className="h-5 w-5" />
            </button>
          </PopoverTrigger>
        </TooltipTrigger>
        <TooltipContent side="bottom">Feedback</TooltipContent>
      </Tooltip>

      <PopoverContent align="end" className="w-[380px] p-0">
        {step === 'choose' ? (
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
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <h3 className="text-sm font-medium text-foreground">
                {type === 'issue' ? 'Describe the issue' : 'Share your idea'}
              </h3>
              <button
                type="button"
                onClick={handleBack}
                className="text-xs text-foreground-secondary hover:text-foreground"
              >
                Back
              </button>
            </div>
            <div className="p-4 space-y-3">
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder={type === 'issue' ? 'What went wrong?' : 'My idea for improving Deptex is...'}
                rows={4}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
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
                >
                  {sending ? (
                    <span className="inline-flex items-center gap-2">
                      <span className="h-3 w-3 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                      Sending...
                    </span>
                  ) : (
                    <>
                      <Send className="h-3.5 w-3.5 mr-1.5" />
                      Send
                    </>
                  )}
                </Button>
              </div>
            </div>
          </>
        )}
      </PopoverContent>
    </Popover>
  );
}
