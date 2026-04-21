import { useRef, useState, type KeyboardEvent, type FormEvent } from 'react';
import { cn } from '../../lib/utils';

interface ChatInputProps {
  onSubmit: (message: string) => void;
  onChange?: () => void;
  disabled?: boolean;
  placeholder?: string;
  autoFocus?: boolean;
}

// Solid filled send arrow (Material Design "send" path) — not available as a filled Lucide icon.
function SendIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" className={className}>
      <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
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
    <form onSubmit={onFormSubmit} className="px-4 py-3 outline-none">
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
            className="flex-1 resize-none bg-transparent border-0 px-3 py-2 pr-10 text-sm text-foreground placeholder:text-foreground/50 outline-none focus:outline-none focus:ring-0 disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={!canSend}
            aria-label="Send message"
            className={cn(
              'absolute right-3 bottom-2.5 flex items-center justify-center transition-colors',
              canSend
                ? 'text-foreground hover:text-foreground/80 cursor-pointer'
                : 'text-foreground/25 cursor-not-allowed',
            )}
          >
            <SendIcon className="h-5 w-5" />
          </button>
        </div>
      </div>
    </form>
  );
}
