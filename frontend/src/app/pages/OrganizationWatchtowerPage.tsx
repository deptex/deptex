import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  TowerControl,
  BookOpen,
  Lock,
  Fingerprint,
  FileCode,
  GitCommit,
  Info,
} from 'lucide-react';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';

export default function OrganizationWatchtowerPage() {
  const { id: orgId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [showUpgradeCard, setShowUpgradeCard] = useState(false);
  const { toast } = useToast();

  const handleEnableClick = () => {
    setShowUpgradeCard(true);
    toast({
      title: 'Watchtower is a Pro feature',
      description: 'Upgrade to Pro to unlock supply chain monitoring, commit forensics, and anomaly detection.',
    });
  };

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <div className="max-w-2xl mx-auto text-center space-y-6">
        <div>
          <h2 className="text-2xl font-semibold text-foreground">Watchtower Supply Chain Monitoring</h2>
          <p className="mt-2 text-foreground-secondary max-w-md mx-auto">
            Enable Watchtower on your projects to receive advanced security intelligence across your organization.
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
