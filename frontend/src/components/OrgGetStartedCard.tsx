import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronRight, Rocket } from 'lucide-react';
import { Button } from './ui/button';
import { Organization, OrganizationIntegration, OrganizationPolicies, Project, api } from '../lib/api';
import { useToast } from '../hooks/use-toast';

interface OrgGetStartedCardProps {
  organization: Organization;
  integrations: OrganizationIntegration[];
  projects: Project[];
  policies: OrganizationPolicies | null;
  onDismissed: () => void;
  onCreateProject?: () => void;
}

interface StepConfig {
  id: string;
  completed: boolean;
  onCta: () => void;
}

export default function OrgGetStartedCard({
  organization,
  integrations,
  projects,
  policies,
  onDismissed,
  onCreateProject,
}: OrgGetStartedCardProps) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [dismissing, setDismissing] = useState(false);

  const orgId = organization.id;

  const hasIntegration =
    !!organization.github_installation_id ||
    integrations.some((i) => i.status === 'connected');
  const hasMembers = (organization.member_count ?? 1) > 1;
  const hasProject = projects.length > 0;
  const hasPolicy =
    (!!policies?.policy_code && policies.policy_code.trim().length > 0) ||
    !!(policies as any)?.package_policy_code?.trim() ||
    !!(policies as any)?.project_status_code?.trim() ||
    !!(policies as any)?.pr_check_code?.trim();

  const steps: StepConfig[] = [
    {
      id: 'integration',
      completed: hasIntegration,
      onCta: () => navigate(`/organizations/${orgId}/settings/integrations`),
    },
    {
      id: 'members',
      completed: hasMembers,
      onCta: () => navigate(`/organizations/${orgId}/settings/members`),
    },
    {
      id: 'project',
      completed: hasProject,
      onCta: () => {
        if (onCreateProject) onCreateProject();
        else navigate(`/organizations/${orgId}/projects`);
      },
    },
    {
      id: 'policy',
      completed: hasPolicy,
      onCta: () => navigate(`/organizations/${orgId}/settings/policies`),
    },
  ];

  const completedCount = steps.filter((s) => s.completed).length;
  const totalSteps = steps.length;
  const allDone = completedCount === totalSteps;
  const nextStep = steps.find((s) => !s.completed);

  const handleDismiss = async () => {
    setDismissing(true);
    try {
      await api.dismissGetStarted(orgId);
      onDismissed();
    } catch {
      toast({
        title: 'Something went wrong',
        description: 'Could not dismiss the card. Please try again.',
        variant: 'destructive',
      });
      setDismissing(false);
    }
  };

  const progressPercent = (completedCount / totalSteps) * 100;

  return (
    <div className="rounded-lg border border-border bg-background-content overflow-hidden flex flex-col">
      <div className="px-5 py-4 flex items-center gap-4">
        <div className="flex-shrink-0 flex items-center justify-center w-9 h-9 rounded-lg bg-white/5">
          <Rocket className="h-5 w-5 text-foreground" strokeWidth={1.5} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm text-foreground-muted tabular-nums">
            {completedCount} out of {totalSteps} steps
          </p>
        </div>
        <div className="flex-shrink-0">
          {allDone ? (
            <Button
              variant="outline"
              size="sm"
              onClick={handleDismiss}
              disabled={dismissing}
              className="h-8"
            >
              {dismissing ? 'Saving…' : 'Done'}
            </Button>
          ) : (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => nextStep?.onCta()}
              className="h-8 text-foreground-secondary hover:text-foreground gap-1.5"
            >
              Resume
              <ChevronRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
      <div className="h-1 w-full bg-border overflow-hidden rounded-b-lg">
        <div
          className="h-full bg-primary transition-all duration-300 rounded-b-lg"
          style={{ width: `${progressPercent}%` }}
        />
      </div>
    </div>
  );
}
