import { Zap, Clock4, Plus } from 'lucide-react';
import { Button } from '../ui/button';

export function RoutinesPanel() {
  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <div className="mx-auto w-full max-w-4xl px-6 pt-8 pb-12">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-foreground/80" aria-hidden />
              <h1 className="text-base font-semibold text-foreground">Routines</h1>
            </div>
            <p className="mt-1 text-sm text-foreground/60">
              Run Aegis on a schedule.
            </p>
          </div>
          <Button variant="outline" size="sm" disabled className="shrink-0">
            <Plus className="h-4 w-4 mr-1.5" />
            New routine
          </Button>
        </div>

        <div className="mt-16 flex flex-col items-center text-center">
          <Clock4 className="h-5 w-5 text-foreground/40 mb-2" aria-hidden />
          <p className="text-sm text-foreground/60">No routines yet.</p>
        </div>
      </div>
    </div>
  );
}
