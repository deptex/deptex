import { useNavigate } from 'react-router-dom';
import { usePlan, TIER_DISPLAY } from '../contexts/PlanContext';
import { AlertTriangle, X } from 'lucide-react';
import { useState } from 'react';

interface PlanLimitBannerProps {
  organizationId: string;
}

export default function PlanLimitBanner({ organizationId }: PlanLimitBannerProps) {
  const { plan, highestUsagePercent } = usePlan();
  const navigate = useNavigate();
  const [dismissed, setDismissed] = useState(false);

  if (!plan || dismissed || highestUsagePercent < 90) return null;

  const isAtLimit = highestUsagePercent >= 100;
  const isCritical = plan.status === 'past_due';

  const bgColor = isCritical
    ? 'bg-red-500/10 border-red-500/30'
    : isAtLimit
      ? 'bg-red-500/10 border-red-500/20'
      : 'bg-yellow-500/10 border-yellow-500/20';

  const textColor = isCritical || isAtLimit ? 'text-red-400' : 'text-yellow-400';
  const iconColor = isCritical || isAtLimit ? 'text-red-400' : 'text-yellow-400';

  let message = '';
  if (isCritical) {
    message = 'Payment failed. Please update your payment method to avoid service interruption.';
  } else if (isAtLimit) {
    const limited = findLimitedResources(plan);
    message = `You've reached your ${limited} limit. Upgrade for more.`;
  } else {
    message = `You're approaching your plan limits (${highestUsagePercent}% used). Consider upgrading.`;
  }

  return (
    <div className={`flex items-center gap-3 px-4 py-2 border-b ${bgColor} text-sm`}>
      <AlertTriangle className={`h-4 w-4 shrink-0 ${iconColor}`} />
      <span className={`flex-1 ${textColor}`}>{message}</span>
      <button
        onClick={() => navigate(`/organizations/${organizationId}/settings/plan`)}
        className="text-xs font-medium px-3 py-1 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
      >
        {isCritical ? 'Update Payment' : 'Upgrade'}
      </button>
      {!isCritical && (
        <button onClick={() => setDismissed(true)} className="text-foreground-secondary hover:text-foreground">
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
}

function findLimitedResources(plan: any): string {
  const names: Record<string, string> = {
    projects: 'project', members: 'member', syncs: 'sync', watchtower: 'watched package', teams: 'team',
  };
  for (const [key, label] of Object.entries(names)) {
    const limit = plan.limits[key];
    if (limit !== -1 && plan.usage[key] >= limit) return label;
  }
  return 'resource';
}
