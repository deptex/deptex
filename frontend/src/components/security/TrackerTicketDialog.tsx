import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '../ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { api, type TrackerProvider, type TrackerDestination, type TrackerFindingType, type FindingTrackerLink } from '../../lib/api';

const PROVIDER_LABEL: Record<TrackerProvider, string> = { jira: 'Jira', linear: 'Linear', github: 'GitHub' };
const DESTINATION_LABEL: Record<TrackerProvider, string> = { jira: 'Project', linear: 'Team', github: 'Repository' };

export interface TrackerTicketDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  provider: TrackerProvider;
  organizationId: string;
  projectId: string;
  findingType: TrackerFindingType;
  findingKey: string;
  defaultTitle: string;
  defaultDescription: string;
  onCreated: (link: FindingTrackerLink) => void;
}

/**
 * File an external ticket (Jira / Linear / GitHub) for a finding. Jira/Linear
 * need a destination (project / team) which is fetched on open because the
 * connect flow doesn't capture it; GitHub files to the project's connected repo.
 * Follows the house dialog pattern (green confirm = spinner-only while filing).
 */
export function TrackerTicketDialog({
  open, onOpenChange, provider, organizationId, projectId, findingType, findingKey,
  defaultTitle, defaultDescription, onCreated,
}: TrackerTicketDialogProps) {
  const [title, setTitle] = useState(defaultTitle);
  const [description, setDescription] = useState(defaultDescription);
  const [destinations, setDestinations] = useState<TrackerDestination[] | null>(null);
  const [destination, setDestination] = useState<string>('');
  const [loadingDest, setLoadingDest] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const needsDestination = provider === 'jira' || provider === 'linear';

  useEffect(() => {
    if (!open) return;
    setTitle(defaultTitle);
    setDescription(defaultDescription);
    setError(null);
    setDestination('');
    setDestinations(null);
    if (!needsDestination) return;
    let cancelled = false;
    setLoadingDest(true);
    api
      .getTrackerDestinations(organizationId, projectId, provider)
      .then((r) => {
        if (cancelled) return;
        setDestinations(r.destinations);
        if (r.destinations.length === 1) setDestination(r.destinations[0].id);
      })
      .catch((e: any) => { if (!cancelled) setError(e?.message ?? `Could not load ${PROVIDER_LABEL[provider]} destinations.`); })
      .finally(() => { if (!cancelled) setLoadingDest(false); });
    return () => { cancelled = true; };
  }, [open, provider, organizationId, projectId, defaultTitle, defaultDescription, needsDestination]);

  const handleConfirm = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const { link } = await api.createFindingTicket(organizationId, projectId, findingType, findingKey, {
        provider,
        title: title.trim(),
        description: description.trim(),
        projectKey: provider === 'jira' ? destination : undefined,
        teamId: provider === 'linear' ? destination : undefined,
      });
      onCreated(link);
      onOpenChange(false);
    } catch (e: any) {
      setError(e?.message ?? 'Could not create the ticket.');
    } finally {
      setSubmitting(false);
    }
  };

  const canSubmit = !submitting && title.trim().length > 0 && (!needsDestination || !!destination);

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!submitting) onOpenChange(next); }}>
      <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 max-h-[90vh] flex flex-col">
        <div className="px-6 pt-6 pb-4 flex-shrink-0">
          <DialogTitle>Create {PROVIDER_LABEL[provider]} ticket</DialogTitle>
          <DialogDescription className="mt-1">
            Files a {PROVIDER_LABEL[provider]} ticket for this finding and links it here. The link is a reference — closing
            the ticket won't change the finding's status.
          </DialogDescription>
        </div>

        <div className="px-6 py-4 grid gap-4 overflow-y-auto flex-1 min-h-0">
          {needsDestination && (
            <div className="grid gap-2">
              <label className="text-sm font-medium text-foreground">{DESTINATION_LABEL[provider]}</label>
              {loadingDest ? (
                <div className="flex items-center gap-2 text-sm text-foreground-secondary">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading {PROVIDER_LABEL[provider]} {DESTINATION_LABEL[provider].toLowerCase()}s…
                </div>
              ) : destinations && destinations.length > 0 ? (
                <Select value={destination} onValueChange={setDestination}>
                  <SelectTrigger className="h-9">
                    <SelectValue placeholder={`Select a ${DESTINATION_LABEL[provider].toLowerCase()}`} />
                  </SelectTrigger>
                  <SelectContent>
                    {destinations.map((d) => (
                      <SelectItem key={d.id} value={d.id}>{d.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <p className="text-sm text-foreground-secondary">
                  No {PROVIDER_LABEL[provider]} {DESTINATION_LABEL[provider].toLowerCase()}s available.
                </p>
              )}
            </div>
          )}

          <div className="grid gap-2">
            <label htmlFor="ticket-title" className="text-sm font-medium text-foreground">Title</label>
            <input
              id="ticket-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full rounded-md border border-border bg-background-card px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary focus:border-foreground-secondary/50 focus:outline-none focus:ring-1 focus:ring-foreground-secondary/20"
            />
          </div>

          <div className="grid gap-2">
            <label htmlFor="ticket-desc" className="text-sm font-medium text-foreground">Description</label>
            <textarea
              id="ticket-desc"
              rows={6}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full resize-none rounded-md border border-border bg-background-card px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary focus:border-foreground-secondary/50 focus:outline-none focus:ring-1 focus:ring-foreground-secondary/20"
            />
          </div>

          {error && <p className="text-sm text-red-400">{error}</p>}
        </div>

        <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:justify-between sm:rounded-b-lg">
          <Button variant="outline" className="h-8 rounded-lg px-3" disabled={submitting} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleConfirm} variant="green" disabled={!canSubmit} className="relative">
            <span className={submitting ? 'invisible' : undefined}>Create ticket</span>
            {submitting && (
              <span className="absolute inset-0 flex items-center justify-center">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              </span>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
