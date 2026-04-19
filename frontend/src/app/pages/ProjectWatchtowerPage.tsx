import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  TowerControl,
  Loader2,
  BookOpen,
  Lock,
  Fingerprint,
  FileCode,
  GitCommit,
  Info,
} from 'lucide-react';
import { useRealtimeStatus } from '../../hooks/useRealtimeStatus';
import { isExtractionOngoing as checkExtractionOngoing } from '../../lib/extractionStatus';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { cn } from '../../lib/utils';

/** Simple skeleton matching the landing layout: title, buttons, feature cards. */
function WatchtowerLandingSkeleton() {
  const pulse = 'bg-muted animate-pulse rounded';
  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <div className="max-w-2xl mx-auto text-center space-y-6">
        <div>
          <div className={cn('h-8 w-96 mx-auto', pulse)} />
          <div className={cn('h-4 w-80 mx-auto mt-2', pulse)} />
        </div>
        <div className="flex items-center justify-center gap-3">
          <div className={cn('h-9 w-36', pulse)} />
          <div className={cn('h-9 w-20', pulse)} />
        </div>
        <div className="grid grid-cols-2 gap-4 mt-8 max-w-lg mx-auto text-left">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="p-4 rounded-lg border border-border bg-background-card">
              <div className={cn('h-5 w-5 mb-2', pulse)} />
              <div className={cn('h-4 w-24', pulse)} />
              <div className={cn('h-3 w-full mt-1', pulse)} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function ProjectWatchtowerPage() {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  const [showUpgradeCard, setShowUpgradeCard] = useState(false);
  const navigate = useNavigate();
  const realtime = useRealtimeStatus(orgId, projectId);
  const isExtractionOngoing = checkExtractionOngoing(realtime.status, realtime.extractionStep);
  const { toast } = useToast();

  const handleEnableClick = () => {
    setShowUpgradeCard(true);
    toast({
      title: 'Watchtower is a Pro feature',
      description: 'Upgrade to Pro to unlock supply chain monitoring, commit forensics, and anomaly detection.',
    });
  };

  // Show skeleton until extraction status is known (avoids flash of content)
  if (realtime.isLoading) {
    return <WatchtowerLandingSkeleton />;
  }

  if (isExtractionOngoing) {
    return (
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="max-w-2xl mx-auto">
          <div className="rounded-lg border border-border bg-background-card p-6">
            <div className="flex items-center gap-4">
              <div className="flex-1 space-y-2 min-w-0">
                <h3 className="text-sm font-semibold text-foreground">Project extraction still in progress</h3>
                <p className="text-sm text-foreground-secondary">
                  Watchtower will be available once extraction completes. You can enable supply chain monitoring from this tab then.
                </p>
              </div>
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" aria-hidden />
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <div className="max-w-2xl mx-auto text-center space-y-6">
        <div>
          <h2 className="text-2xl font-semibold text-foreground">Watchtower Supply Chain Monitoring</h2>
          <p className="mt-2 text-foreground-secondary max-w-md mx-auto">
            Enable Watchtower on this project to receive advanced security intelligence.
          </p>
        </div>

        {showUpgradeCard && orgId && (
          <div className="rounded-lg border border-border bg-background-card p-6 text-left max-w-2xl mx-auto">
            <div className="flex gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                <Info className="h-4 w-4 text-foreground-secondary" />
              </div>
              <div className="flex-1 space-y-2">
                <h3 className="text-sm font-semibold text-foreground">Upgrade to Pro to unlock Watchtower</h3>
                <p className="text-sm text-foreground-secondary">
                  Supply chain forensics, commit anomaly detection, and registry integrity checks are available on the Pro plan.
                </p>
                <Button
                  onClick={() => navigate(`/organizations/${orgId}/settings/plan`)}
                  className="mt-4 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm px-4"
                >
                  Upgrade to Pro
                </Button>
              </div>
            </div>
          </div>
        )}

        <div className="flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={handleEnableClick}
            className="inline-flex items-center gap-2 h-9 px-5 py-2.5 rounded-lg text-sm font-semibold bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 focus:outline-none focus:ring-2 focus:ring-primary/50 focus:ring-offset-2"
          >
            <TowerControl className="h-4 w-4" />
            Enable Watchtower
          </button>
          <a
            href="/docs/watchtower"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 h-9 px-5 py-2.5 rounded-lg text-sm font-medium border border-border bg-background-card text-foreground hover:bg-background-subtle"
          >
            <BookOpen className="h-4 w-4" />
            Docs
          </a>
        </div>

        <div className="grid grid-cols-2 gap-4 mt-8 max-w-lg mx-auto text-left">
          {[
            { icon: Lock, title: 'Registry Integrity', desc: 'Detects tampered publishes where code differs between registry and source' },
            { icon: FileCode, title: 'Install Script Analysis', desc: 'Scans for dangerous preinstall/postinstall hooks' },
            { icon: Fingerprint, title: 'Entropy Analysis', desc: 'Identifies obfuscated or encoded malicious payloads' },
            { icon: GitCommit, title: 'Commit Anomaly Detection', desc: 'Flags unusual contributor activity patterns' },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} className="p-4 rounded-lg border border-border bg-background-card">
              <Icon className="h-5 w-5 text-foreground-secondary mb-2" />
              <h3 className="text-sm font-medium text-foreground">{title}</h3>
              <p className="text-xs text-foreground-secondary mt-1">{desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
