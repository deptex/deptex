export const DEFAULT_PROMPTS = [
  'Security posture',
  'Reachable vulnerabilities',
  'Riskiest projects',
];

interface PromptChipsProps {
  prompts?: string[];
  onSelect: (prompt: string) => void;
  disabled?: boolean;
}

export function PromptChips({ prompts = DEFAULT_PROMPTS, onSelect, disabled }: PromptChipsProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
      {prompts.map((p) => (
        <button
          key={p}
          type="button"
          onClick={() => onSelect(p)}
          disabled={disabled}
          className="rounded-lg border border-border bg-background-card px-4 py-3 text-left text-sm text-foreground/90 hover:bg-background-subtle hover:text-foreground transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {p}
        </button>
      ))}
    </div>
  );
}
