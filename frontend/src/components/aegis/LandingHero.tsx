import { useEffect, useState } from 'react';
import { ChatInput } from './ChatInput';

const AEGIS_PROMPTS = [
  "What's my security posture?",
  'How many reachable vulnerabilities does my org have?',
  'Which projects are at highest risk?',
  'Are any of my secrets exposed?',
  'Which dependencies should I update first?',
  'Show me my critical CVEs',
];

const TYPE_MS = 55;
const BACKSPACE_MS = 30;
const HOLD_MS = 2400;

function useTypewriterPlaceholder(phrases: string[]) {
  const [index, setIndex] = useState(0);
  const [visible, setVisible] = useState(0);
  const [phase, setPhase] = useState<'typing' | 'hold' | 'backspacing'>('typing');
  const phrase = phrases[index];

  useEffect(() => {
    if (phase === 'hold') {
      const t = setTimeout(() => setPhase('backspacing'), HOLD_MS);
      return () => clearTimeout(t);
    }
    if (phase === 'typing') {
      if (visible >= phrase.length) { setPhase('hold'); return; }
      const t = setTimeout(() => setVisible((v) => v + 1), TYPE_MS);
      return () => clearTimeout(t);
    }
    // backspacing
    if (visible <= 0) {
      setIndex((i) => (i + 1) % phrases.length);
      setPhase('typing');
      return;
    }
    const t = setTimeout(() => setVisible((v) => v - 1), BACKSPACE_MS);
    return () => clearTimeout(t);
  }, [phase, visible, phrase.length, phrases.length]);

  return phrase.slice(0, visible);
}

interface LandingHeroProps {
  name: string;
  onSubmit: (message: string) => void;
}

export function LandingHero({ name, onSubmit }: LandingHeroProps) {
  const placeholder = useTypewriterPlaceholder(AEGIS_PROMPTS);

  return (
    <div className="flex h-full flex-col items-center justify-center px-6">
      <div className="w-full max-w-2xl -mt-12">
        <div className="mb-8">
          <div className="text-base text-foreground/60 mb-1">Hi {name}</div>
          <h1 className="text-3xl font-semibold text-foreground tracking-tight">
            What can I help you secure?
          </h1>
        </div>

        <div className="rounded-2xl bg-background-card border border-border">
          <ChatInput onSubmit={onSubmit} placeholder={placeholder} autoFocus />
        </div>
      </div>
    </div>
  );
}
