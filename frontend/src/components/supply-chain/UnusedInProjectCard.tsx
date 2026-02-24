import { memo } from 'react';
import { Loader2, GitPullRequest } from 'lucide-react';
import { Card, CardHeader } from '../ui/card';
import { Button } from '../ui/button';

interface UnusedInProjectCardProps {
  removePrUrl: string | null;
  removePrNumber?: number | null;
  onRemove: () => void;
  removing: boolean;
}

function UnusedInProjectCardComponent({
  removePrUrl,
  removePrNumber,
  onRemove,
  removing,
}: UnusedInProjectCardProps) {
  return (
    <Card className="w-fit min-w-[200px] shadow-md transition-[width] duration-200 ease-in-out">
      <CardHeader className="p-3 pb-2">
        <div className="flex items-center gap-4">
          <div className="min-w-0">
            <p className="text-xs font-medium text-foreground leading-tight">Status</p>
            <p className="text-sm text-foreground-secondary mt-0.5">Unused in Project</p>
          </div>
          <div className="shrink-0">
            {removePrUrl ? (
              <Button variant="outline" size="sm" asChild>
                <a
                  href={removePrUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {removePrNumber != null ? `View PR #${removePrNumber}` : 'View PR'}
                </a>
              </Button>
            ) : (
              <Button
                variant="outline"
                size="sm"
                onClick={onRemove}
                disabled={removing}
                className="bg-destructive/10 border-destructive/20 text-destructive hover:bg-destructive/20 hover:border-destructive/30"
              >
                {removing ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <GitPullRequest className="h-3 w-3" />
                )}
                Remove
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
    </Card>
  );
}

export const UnusedInProjectCard = memo(UnusedInProjectCardComponent);
