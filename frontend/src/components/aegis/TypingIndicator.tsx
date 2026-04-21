interface TypingIndicatorProps {
  users: Array<{ userId: string; displayName: string }>;
}

export function TypingIndicator({ users }: TypingIndicatorProps) {
  if (users.length === 0) return null;
  const names = users.map((u) => u.displayName || 'Someone');
  let text: string;
  if (names.length === 1) text = `${names[0]} is typing…`;
  else if (names.length === 2) text = `${names[0]} and ${names[1]} are typing…`;
  else text = `${names[0]} and ${names.length - 1} others are typing…`;

  return (
    <div className="px-4 py-2">
      <div className="mx-auto max-w-3xl flex items-center gap-2 text-xs text-foreground/50 italic">
        <span className="inline-flex gap-0.5">
          <span className="h-1 w-1 rounded-full bg-foreground/40 animate-pulse" />
          <span className="h-1 w-1 rounded-full bg-foreground/40 animate-pulse [animation-delay:150ms]" />
          <span className="h-1 w-1 rounded-full bg-foreground/40 animate-pulse [animation-delay:300ms]" />
        </span>
        {text}
      </div>
    </div>
  );
}
