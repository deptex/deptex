import { Sparkles } from 'lucide-react';
import { PromptChips } from './PromptChips';

interface EmptyStateProps {
  onSelectPrompt: (prompt: string) => void;
  disabled?: boolean;
}

export function EmptyState({ onSelectPrompt, disabled }: EmptyStateProps) {
  return (
    <div className="flex h-full items-center justify-center px-6">
      <div className="max-w-xl w-full text-center">
        <div className="mx-auto mb-4 flex h-10 w-10 items-center justify-center rounded-full border border-border bg-background-card">
          <Sparkles className="h-5 w-5 text-foreground/80" aria-hidden />
        </div>
        <h1 className="text-lg font-semibold text-foreground mb-1">
          Aegis, your AI security agent
        </h1>
        <p className="text-sm text-foreground/80 leading-relaxed mb-6">
          Ask me anything about your org&rsquo;s security posture. I have access to your projects,
          dependencies, vulnerabilities, and policies.
        </p>
        <PromptChips onSelect={onSelectPrompt} disabled={disabled} />
      </div>
    </div>
  );
}
