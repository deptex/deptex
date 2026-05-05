import { useState } from 'react';
import { Check, ChevronDown } from 'lucide-react';
import type { AIModelMetadata } from '../../lib/api';
import { cn } from '../../lib/utils';
import { Popover, PopoverContent, PopoverTrigger } from '../ui/popover';
import { AIProviderIcon, brandForModel } from '../ai-provider-icon';

interface ModelPickerProps {
  models: AIModelMetadata[];
  selectedModelId: string | null;
  onSelect: (id: string) => void;
}

export function ModelPicker({ models, selectedModelId, onSelect }: ModelPickerProps) {
  const [open, setOpen] = useState(false);
  const selected = models.find((m) => m.id === selectedModelId) ?? models[0];
  if (!selected) return null;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="inline-flex h-8 items-center gap-2 rounded-md px-2 text-sm font-medium text-foreground/80 hover:bg-background-subtle hover:text-foreground transition-colors"
        >
          <AIProviderIcon brand={brandForModel(selected)} size={14} className="shrink-0" />
          <span className="truncate max-w-[160px]">{selected.label}</span>
          <ChevronDown className="h-3.5 w-3.5 text-foreground/60" />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" sideOffset={8} className="w-[320px] p-1">
        <div className="max-h-80 overflow-y-auto">
          {models.map((m) => {
            const isSelected = m.id === selected.id;
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => {
                  onSelect(m.id);
                  setOpen(false);
                }}
                className={cn(
                  'w-full flex items-start gap-2.5 rounded-md px-2 py-2 text-left transition-colors',
                  'hover:bg-background-subtle',
                  isSelected && 'bg-background-subtle',
                )}
              >
                <AIProviderIcon brand={brandForModel(m)} size={16} className="mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground truncate">{m.label}</span>
                  </div>
                  <p className="text-xs text-foreground-secondary line-clamp-1">{m.description}</p>
                </div>
                {isSelected && <Check className="h-4 w-4 text-foreground mt-0.5 shrink-0" />}
              </button>
            );
          })}
        </div>
      </PopoverContent>
    </Popover>
  );
}
