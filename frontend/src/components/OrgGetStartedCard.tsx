import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Github,
  Users,
  FolderKanban,
  Shield,
  CheckCircle2,
  ArrowRight,
  ChevronRight,
  Sparkles,
  X,
} from 'lucide-react';
import { Progress } from './ui/progress';
import { Button } from './ui/button';
import { Organization, OrganizationIntegration, OrganizationPolicies, Project, api } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import { cn } from '../lib/utils';

interface OrgGetStartedCardProps {
  organization: Organization;
  integrations: OrganizationIntegration[];
  projects: Project[];
  policies: OrganizationPolicies | null;
  onDismissed: () => void;
  onCreateProject?: () => void;
}

interface Step {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  iconBg: string;
  completed: boolean;
  ctaLabel: string;
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

  // Determine completion of each step
  const hasIntegration =
    !!organization.github_installation_id ||
    integrations.some((i) => i.status === 'connected');

  const hasMembers = (organization.member_count ?? 1) > 1;

  const hasProject = projects.length > 0;

  const hasPolicy =
    !!policies?.policy_code && policies.policy_code.trim().length > 0;

  const steps: Step[] = [
    {
      id: 'integration',
      title: 'Connect a VCS integration',
      description:
        'Install the GitHub App (or GitLab / Bitbucket) so Deptex can scan your repositories and analyse dependencies automatically.',
      icon: <Github className="h-5 w-5" />,
      iconBg: 'bg-[#24292e]',
      completed: hasIntegration,
      ctaLabel: 'Go to Integrations',
      onCta: () => navigate(`/organizations/${orgId}/settings/integrations`),
    },
    {
      id: 'members',
      title: 'Invite team members',
      description:
        'Add your colleagues so they can collaborate on projects, review vulnerabilities, and manage compliance together.',
      icon: <Users className="h-5 w-5" />,
      iconBg: 'bg-blue-500/20',
      completed: hasMembers,
      ctaLabel: 'Invite Members',
      onCta: () => navigate(`/organizations/${orgId}/settings/members`),
    },
    {
      id: 'project',
      title: 'Create your first project',
      description:
          "Link a repository to a Deptex project. We'll extract your dependency tree, check for vulnerabilities, and keep you up to date.",
      icon: <FolderKanban className="h-5 w-5" />,
      iconBg: 'bg-violet-500/20',
      completed: hasProject,
      ctaLabel: 'Create Project',
      onCta: () => {
        if (onCreateProject) {
          onCreateProject();
        } else {
          navigate(`/organizations/${orgId}/projects`);
        }
      },
    },
    {
      id: 'policy',
      title: 'Define your organization policy',
      description:
        'Write policy-as-code to enforce license rules, vulnerability thresholds, and supply-chain requirements across all your projects.',
      icon: <Shield className="h-5 w-5" />,
      iconBg: 'bg-amber-500/20',
      completed: hasPolicy,
      ctaLabel: 'Set Up Policy',
      onCta: () => navigate(`/organizations/${orgId}/settings/policies`),
    },
  ];

  const completedCount = steps.filter((s) => s.completed).length;
  const progressPercent = Math.round((completedCount / steps.length) * 100);
  const allDone = completedCount === steps.length;

  // The first incomplete step is the "active" one
  const activeStepIndex = steps.findIndex((s) => !s.completed);

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

  return (
    <div className="relative rounded-xl border border-border bg-background-card overflow-hidden">
      {/* Top accent gradient strip */}
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/60 to-transparent" />

      {/* Header */}
      <div className="px-6 pt-6 pb-5 border-b border-border">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary/30 bg-primary/10">
              <Sparkles className="h-4.5 w-4.5 text-primary" style={{ height: '18px', width: '18px' }} />
            </div>
            <div>
              <h2 className="text-base font-semibold text-foreground leading-tight">
                Get started with Deptex
              </h2>
              <p className="text-xs text-foreground-secondary mt-0.5">
                Complete a few quick steps to get the most out of your organization
              </p>
            </div>
          </div>
          <button
            onClick={handleDismiss}
            disabled={dismissing}
            className="flex-shrink-0 p-1.5 rounded-md text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
            aria-label="Dismiss"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Progress bar row */}
        <div className="mt-4 flex items-center gap-3">
          <Progress value={progressPercent} className="flex-1 h-1.5" />
          <span className="text-xs font-medium tabular-nums text-foreground-secondary whitespace-nowrap">
            {completedCount} / {steps.length} steps
          </span>
        </div>
      </div>

      {/* Steps */}
      <div className="divide-y divide-border">
        {steps.map((step, index) => {
          const isActive = !step.completed && index === activeStepIndex;
          const isPending = !step.completed && index > activeStepIndex;

          return (
            <div
              key={step.id}
              className={cn(
                'flex items-start gap-4 px-6 py-4 transition-colors',
                isActive && 'bg-primary/[0.03]',
                isPending && 'opacity-50',
                step.completed && 'opacity-60'
              )}
            >
              {/* Step icon / check */}
              <div className="flex-shrink-0 mt-0.5">
                {step.completed ? (
                  <div className="flex h-9 w-9 items-center justify-center rounded-full bg-green-500/10 border border-green-500/20">
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                  </div>
                ) : (
                  <div
                    className={cn(
                      'flex h-9 w-9 items-center justify-center rounded-full border',
                      isActive
                        ? 'border-primary/40 text-primary bg-primary/10'
                        : 'border-border text-foreground-secondary bg-background-subtle/50'
                    )}
                  >
                    <span className={cn('text-inherit', step.iconBg === 'bg-[#24292e]' ? '' : '')}>{step.icon}</span>
                  </div>
                )}
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span
                    className={cn(
                      'text-xs font-semibold uppercase tracking-wider',
                      isActive ? 'text-primary' : 'text-foreground-secondary'
                    )}
                  >
                    Step {index + 1}
                  </span>
                  {step.completed && (
                    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-green-500/10 text-green-500 border border-green-500/20">
                      Completed
                    </span>
                  )}
                  {isActive && (
                    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-primary/10 text-primary border border-primary/20">
                      Up next
                    </span>
                  )}
                </div>
                <p
                  className={cn(
                    'text-sm font-medium leading-tight',
                    step.completed ? 'text-foreground-secondary line-through decoration-foreground-secondary/40' : 'text-foreground'
                  )}
                >
                  {step.title}
                </p>
                {!step.completed && (
                  <p className="text-xs text-foreground-secondary mt-1 leading-relaxed">
                    {step.description}
                  </p>
                )}
              </div>

              {/* CTA */}
              {!step.completed && (
                <div className="flex-shrink-0 mt-0.5">
                  {isActive ? (
                    <Button
                      size="sm"
                      onClick={step.onCta}
                      className="h-8 text-xs px-3 gap-1.5"
                    >
                      {step.ctaLabel}
                      <ArrowRight className="h-3.5 w-3.5" />
                    </Button>
                  ) : (
                    <button
                      onClick={step.onCta}
                      className="flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground transition-colors"
                    >
                      {step.ctaLabel}
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <div className="px-6 py-4 bg-black/20 border-t border-border flex items-center justify-between gap-4">
        {allDone ? (
          <>
            <div className="flex items-center gap-2 text-sm text-green-500 font-medium">
              <CheckCircle2 className="h-4 w-4" />
              You're all set — great work!
            </div>
            <div className="flex items-center gap-3">
              <a
                href="https://docs.deptex.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-foreground-secondary hover:text-foreground transition-colors underline underline-offset-2"
              >
                How to get the most out of Deptex →
              </a>
              <Button
                size="sm"
                onClick={handleDismiss}
                disabled={dismissing}
                className="h-8 text-xs px-3"
              >
                {dismissing ? 'Saving…' : 'Done'}
              </Button>
            </div>
          </>
        ) : (
          <>
            <p className="text-xs text-foreground-secondary">
              {steps.length - completedCount} step{steps.length - completedCount !== 1 ? 's' : ''} remaining
            </p>
            <button
              onClick={handleDismiss}
              disabled={dismissing}
              className="text-xs text-foreground-secondary hover:text-foreground transition-colors"
            >
              {dismissing ? 'Saving…' : "I'll set this up later"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
