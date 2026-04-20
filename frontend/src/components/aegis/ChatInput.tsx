import { useRef, useState, type KeyboardEvent, type FormEvent } from 'react';
import { ArrowUp } from 'lucide-react';
import { cn } from '../../lib/utils';

interface ChatInputProps {
  onSubmit: (message: string) => void;
  disabled?: boolean;
  placeholder?: string;
  autoFocus?: boolean;
}

export function ChatInput({ onSubmit, disabled, placeholder = 'Ask Aegis anything…', autoFocus }: ChatInputProps) {
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
    if (e.key === 'Enter' && !e.shiftKey) {
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
    <form onSubmit={onFormSubmit} className="px-4 pb-4 pt-2">
      <div className="mx-auto max-w-3xl">
        <div className="relative flex items-end rounded-2xl border border-border bg-background-card focus-within:border-foreground/30 transition-colors">
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => { setValue(e.target.value); resize(); }}
            onKeyDown={onKeyDown}
            placeholder={placeholder}
            disabled={disabled}
            autoFocus={autoFocus}
            rows={1}
            className="flex-1 resize-none bg-transparent px-4 py-3 pr-12 text-sm text-foreground placeholder:text-foreground/50 outline-none disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={!canSend}
            aria-label="Send message"
            className={cn(
              'absolute right-2 bottom-2 flex h-8 w-8 items-center justify-center rounded-lg transition-colors',
              canSend
                ? 'bg-foreground text-background hover:bg-foreground/90'
                : 'bg-background-subtle text-foreground/40 cursor-not-allowed',
            )}
          >
            <ArrowUp className="h-4 w-4" />
          </button>
        </div>
      </div>
    </form>
  );
}
