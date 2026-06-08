/** Display helpers shared by the org-overview sidebar and team-sidebar projects tables. */

/** "DD Mon YY" — e.g. "08 Jun 26". */
export const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  const day = date.getDate().toString().padStart(2, '0');
  const month = date.toLocaleDateString('en-US', { month: 'short' });
  const year = date.getFullYear().toString().slice(-2);
  return `${day} ${month} ${year}`;
};

/** "Last scan"-style relative time: just now / 5m / 3h / 2d, falling back to a date past ~7 days. */
export const formatRelativeTime = (dateString: string | null | undefined): string => {
  if (!dateString) return 'Never';
  const then = new Date(dateString).getTime();
  if (Number.isNaN(then)) return 'Never';
  const diffMs = Date.now() - then;
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return formatDate(dateString);
};

/** Prettify a framework id for the Type column ("spring-boot" → "Spring Boot", "express" → "Express"). */
export const prettyFramework = (framework: string | null | undefined): string => {
  if (!framework) return 'Unknown';
  return framework
    .split(/[-_]/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
};

export const PROVIDER_LOGOS: Record<string, string> = {
  github: '/images/integrations/github.png',
  gitlab: '/images/integrations/gitlab.png',
  bitbucket: '/images/integrations/bitbucket.png',
};
