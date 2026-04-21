import { ChatInput } from './ChatInput';
import { DEFAULT_PROMPTS } from './PromptChips';

interface LandingHeroProps {
  name: string;
  onSubmit: (message: string) => void;
  onSelectPrompt: (prompt: string) => void;
}

export function LandingHero({ name, onSubmit, onSelectPrompt }: LandingHeroProps) {
  return (
    <div className="flex h-full flex-col items-center justify-center px-6">
      <div className="w-full max-w-2xl -mt-12">
        <div className="mb-8">
          <div className="text-base text-foreground/60 mb-1">Hi {name}</div>
          <h1 className="text-3xl font-semibold text-foreground tracking-tight">
            What can I help you secure?
          </h1>
        </div>

        <div className="rounded-2xl bg-background-card border border-border/30">
          <ChatInput onSubmit={onSubmit} autoFocus />
        </div>

        <div className="flex flex-wrap justify-center gap-2 mt-4 px-4">
          {DEFAULT_PROMPTS.map((prompt) => (
            <button
              key={prompt}
              type="button"
              onClick={() => onSelectPrompt(prompt)}
              className="rounded-full bg-background-subtle/60 hover:bg-background-subtle px-4 py-2 text-xs text-foreground/80 hover:text-foreground transition-colors"
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
