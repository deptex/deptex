import { useRef, useState, type KeyboardEvent, type FormEvent } from 'react';
import { SendHorizontal } from 'lucide-react';
import { cn } from '../../lib/utils';

interface ChatInputProps {
  onSubmit: (message: string) => void;
  onChange?: () => void;
  disabled?: boolean;
  placeholder?: string;
  autoFocus?: boolean;
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
    <form onSubmit={onFormSubmit} className="px-4 pb-4 pt-2 outline-none">
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
            className="flex-1 resize-none bg-transparent border-0 px-5 py-4 pr-12 text-sm text-foreground placeholder:text-foreground/50 outline-none focus:outline-none focus:ring-0 disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={!canSend}
            aria-label="Send message"
            className={cn(
              'absolute right-3 bottom-3 flex items-center justify-center transition-colors',
              canSend
                ? 'text-foreground hover:text-foreground/80 cursor-pointer'
                : 'text-foreground/25 cursor-not-allowed',
            )}
          >
            <SendHorizontal className="h-5 w-5" />
          </button>
        </div>
      </div>
    </form>
  );
}
