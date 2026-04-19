import { Users } from 'lucide-react';

/** Same team icon used on the org overview team card (VulnProjectNode) and org sidebar team list. One source of truth. */
export function TeamIcon({ className = '' }: { className?: string }) {
  return (
    <div
      className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 bg-[#1a1c1e] text-muted-foreground ${className}`.trim()}
    >
      <Users className="w-4 h-4" />
    </div>
  );
}
