import { useRef, useState, type KeyboardEvent, type FormEvent } from 'react';
import { Mic, Square } from 'lucide-react';
import type { AIModelMetadata } from '../../lib/api';
import { cn } from '../../lib/utils';
import { useSpeechRecognition } from '../../hooks/useSpeechRecognition';
import { useToast } from '../../hooks/use-toast';
import { ModelPicker } from './ModelPicker';

interface ChatInputProps {
  onSubmit: (message: string) => void;
  onChange?: () => void;
  disabled?: boolean;
  placeholder?: string;
  autoFocus?: boolean;
  // Model picker. When omitted, the picker is hidden — the backend falls back
  // to the org default. While `modelsLoading` is true, we render a skeleton in
  // the picker slot so the toolbar doesn't pop on first load.
  models?: AIModelMetadata[];
  selectedModelId?: string | null;
  onSelectModel?: (modelId: string) => void;
  modelsLoading?: boolean;
  // When the assistant is mid-stream, the action button morphs into a stop
  // control — but only when the textarea is empty. Once the user starts
  // typing a follow-up, the send arrow returns and queues the message.
  isStreaming?: boolean;
  onStop?: () => void;
}

function ArrowUpIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" xmlns="http://www.w3.org/2000/svg" className={className}>
      <path d="M12 19V5M5 12l7-7 7 7" />
    </svg>
  );
}

export function ChatInput({
  onSubmit,
  onChange,
  disabled,
  placeholder = 'Ask Aegis anything',
  autoFocus,
  models,
  selectedModelId,
  onSelectModel,
  modelsLoading,
  isStreaming,
  onStop,
}: ChatInputProps) {
  const [value, setValue] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const { toast } = useToast();

  const resize = () => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 200) + 'px';
  };

  const { supported: speechSupported, listening, interim, toggle: toggleSpeech, stop: stopSpeech } =
    useSpeechRecognition({
      onAppend: (chunk) => {
        if (!chunk) return;
        setValue((prev) => (prev ? prev.trimEnd() + ' ' + chunk : chunk));
        requestAnimationFrame(resize);
      },
      onError: (code) => {
        if (code === 'not-allowed' || code === 'service-not-allowed') {
          toast({
            title: 'Microphone blocked',
            description: 'Allow microphone access in your browser to use voice input.',
            variant: 'destructive',
          });
        } else if (code !== 'no-speech' && code !== 'aborted') {
          toast({ title: 'Voice input failed', description: code, variant: 'destructive' });
        }
      },
    });

  const submit = () => {
    const text = value.trim();
    if (!text || disabled) return;
    if (listening) stopSpeech();
    onSubmit(text);
    setValue('');
    requestAnimationFrame(resize);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
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
  const showModelPicker = !!(models && models.length > 0 && onSelectModel);

  return (
    <form onSubmit={onFormSubmit} className="outline-none">
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(e) => { setValue(e.target.value); resize(); onChange?.(); }}
        onKeyDown={onKeyDown}
        placeholder={placeholder}
        disabled={disabled}
        autoFocus={autoFocus}
        rows={1}
        className="w-full resize-none bg-transparent border-0 px-4 pt-3 pb-1 text-[0.9375rem] leading-relaxed text-foreground placeholder:text-foreground/50 outline-none focus:outline-none focus:ring-0 disabled:opacity-60"
      />
      <div className="flex items-center justify-between px-2 pb-2">
        <div className="flex items-center gap-1">
          {modelsLoading ? (
            <ModelPickerSkeleton />
          ) : (
            showModelPicker && (
              <ModelPicker
                models={models!}
                selectedModelId={selectedModelId ?? null}
                onSelect={onSelectModel!}
              />
            )
          )}
        </div>
        {listening ? (
          <button
            type="button"
            onClick={() => stopSpeech()}
            aria-label="Stop recording"
            className="relative flex items-center justify-center h-8 w-8 rounded-full transition-colors shadow-sm ring-1 ring-inset bg-destructive/15 text-destructive ring-destructive/30 hover:bg-destructive/25 cursor-pointer"
          >
            <span className="absolute inset-0 rounded-full ring-2 ring-destructive/40 animate-ping" />
            <Square className="h-3 w-3 fill-current" />
          </button>
        ) : canSend ? (
          <button
            type="submit"
            aria-label="Send message"
            className="flex items-center justify-center h-8 w-8 rounded-full transition-colors shadow-sm ring-1 ring-inset bg-foreground text-background ring-foreground/10 hover:bg-foreground/90 cursor-pointer"
          >
            <ArrowUpIcon className="h-4 w-4" />
          </button>
        ) : isStreaming && onStop ? (
          <button
            type="button"
            onClick={() => onStop()}
            aria-label="Stop generating"
            className="flex items-center justify-center h-8 w-8 rounded-full transition-colors shadow-sm ring-1 ring-inset bg-foreground text-background ring-foreground/10 hover:bg-foreground/90 cursor-pointer"
          >
            <Square className="h-3 w-3 fill-current" />
          </button>
        ) : (
          <button
            type="button"
            onClick={() => toggleSpeech()}
            disabled={!speechSupported || disabled}
            aria-label={speechSupported ? 'Start voice input' : 'Voice input not supported'}
            className={cn(
              'flex items-center justify-center h-8 w-8 rounded-full transition-colors shadow-sm ring-1 ring-inset',
              'bg-background-subtle text-foreground/60 ring-border',
              speechSupported && !disabled && 'hover:bg-background-subtle/70 hover:text-foreground/80 cursor-pointer',
              (!speechSupported || disabled) && 'opacity-60 cursor-not-allowed',
            )}
          >
            <Mic className="h-4 w-4" />
          </button>
        )}
      </div>
    </form>
  );
}

function ModelPickerSkeleton() {
  return (
    <div className="inline-flex h-8 items-center gap-2 rounded-md px-2">
      <div className="h-3.5 w-3.5 rounded-full bg-foreground/10 animate-pulse" />
      <div className="h-3 w-24 rounded bg-foreground/10 animate-pulse" />
      <div className="h-3 w-3 rounded bg-foreground/10 animate-pulse" />
    </div>
  );
}

