import { useRef, useState, type KeyboardEvent, type FormEvent } from 'react';
import { Mic } from 'lucide-react';
import { cn } from '../../lib/utils';

interface ChatInputProps {
  onSubmit: (message: string) => void;
  onChange?: () => void;
  disabled?: boolean;
  placeholder?: string;
  autoFocus?: boolean;
}

function ArrowUpIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round" xmlns="http://www.w3.org/2000/svg" className={className}>
      <path d="M12 19V5M5 12l7-7 7 7" />
    </svg>
  );
}

export function ChatInput({ onSubmit, onChange, disabled, placeholder = 'Ask Aegis anything', autoFocus }: ChatInputProps) {
  const [value, setValue] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const resize = () => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 200) + 'px';
  };

  const submit = () => {
    const text = value.trim();
    if (!text || disabled) return;
    onSubmit(text);
    setValue('');
    requestAnimationFrame(resize);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    // Enter alone sends; Shift/Ctrl/Cmd+Enter inserts a newline.
    if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      submit();
    }
  };

  const onFormSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit();
  };

  const canSend = value.trim().length > 0 && !disabled;

  return (
    <form onSubmit={onFormSubmit} className="px-2 py-2.5 outline-none">
      <div className="mx-auto max-w-3xl">
        <div className="relative flex items-end">
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => { setValue(e.target.value); resize(); onChange?.(); }}
            onKeyDown={onKeyDown}
            placeholder={placeholder}
            disabled={disabled}
            autoFocus={autoFocus}
            rows={1}
            className="flex-1 resize-none bg-transparent border-0 px-3 py-2 pr-12 text-[0.9375rem] leading-relaxed text-foreground placeholder:text-foreground/50 outline-none focus:outline-none focus:ring-0 disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={!canSend}
            aria-label={canSend ? 'Send message' : 'Voice input'}
            className={cn(
              'absolute right-2.5 bottom-2 flex items-center justify-center h-7 w-7 rounded-full transition-all',
              canSend
                ? 'bg-foreground text-background hover:bg-foreground/85 cursor-pointer'
                : 'bg-foreground text-background cursor-not-allowed',
            )}
          >
            {canSend ? <ArrowUpIcon className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
          </button>
        </div>
      </div>
    </form>
  );
}
