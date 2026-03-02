import { Lock } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { usePlanGate, usePlanLimit, type GatableFeature, type LimitableResource, TIER_DISPLAY } from '../contexts/PlanContext';
import { Button } from './ui/button';

interface FeatureGateProps {
  feature: GatableFeature;
  organizationId: string;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export function FeatureGate({ feature, organizationId, children, fallback }: FeatureGateProps) {
  const gate = usePlanGate(feature);

  if (gate.allowed) return <>{children}</>;

  if (fallback) return <>{fallback}</>;

  return (
    <div className="flex flex-col items-center justify-center py-8 gap-3 text-center">
      <Lock className="h-5 w-5 text-foreground-tertiary" />
      <p className="text-sm text-foreground-secondary">
        This feature requires the {TIER_DISPLAY[gate.requiredTier]} plan.
      </p>
      <Button variant="outline" size="sm" asChild>
        <a href={`/organizations/${organizationId}/settings/plan`}>Upgrade</a>
      </Button>
    </div>
  );
}

interface LimitGateProps {
  resource: LimitableResource;
  organizationId: string;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export function LimitGate({ resource, organizationId, children, fallback }: LimitGateProps) {
  const limit = usePlanLimit(resource);

  if (limit.allowed) return <>{children}</>;

  if (fallback) return <>{fallback}</>;

  return (
    <div className="flex flex-col items-center justify-center py-8 gap-3 text-center">
      <Lock className="h-5 w-5 text-foreground-tertiary" />
      <p className="text-sm text-foreground-secondary">
        You've reached your {resource.replace(/_/g, ' ')} limit ({limit.current}/{limit.limit}).
      </p>
      <Button variant="outline" size="sm" asChild>
        <a href={`/organizations/${organizationId}/settings/plan`}>Upgrade</a>
      </Button>
    </div>
  );
}
