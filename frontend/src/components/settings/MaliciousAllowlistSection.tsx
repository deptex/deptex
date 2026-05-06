/**
 * Org Settings → Security → Malicious Allowlist.
 *
 * Lists active allowlist entries and lets users with `manage_organization_settings`
 * add or revoke them. Allowlisted (package, version, ecosystem) tuples auto-
 * suppress matching malicious findings on the next extraction run.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Plus, Loader2, ShieldCheck, Trash2 } from 'lucide-react';
import {
  api,
  MALICIOUS_ECOSYSTEMS,
  type MaliciousAllowlistEntry,
  type MaliciousEcosystem,
} from '../../lib/api';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';

interface MaliciousAllowlistSectionProps {
  organizationId: string;
  canManage: boolean;
}

const MIN_REASON_LEN = 10;
const RANGE_OPERATOR_RE = /[\^~<>=*]|(\s+-\s+)/;

function ecosystemLabel(eco: string): string {
  switch (eco) {
    case 'npm': return 'npm';
    case 'pypi': return 'PyPI';
    case 'maven': return 'Maven';
    case 'golang': return 'Go';
    case 'rubygems': return 'RubyGems';
    case 'composer': return 'Composer (PHP)';
    case 'cargo': return 'Cargo (Rust)';
    case 'nuget': return 'NuGet (C#)';
    case 'github-actions': return 'GitHub Actions';
    case 'vscode': return 'VS Code';
    default: return eco;
  }
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return iso;
  }
}

export default function MaliciousAllowlistSection({
  organizationId,
  canManage,
}: MaliciousAllowlistSectionProps) {
  const { toast } = useToast();
  const [entries, setEntries] = useState<MaliciousAllowlistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<MaliciousAllowlistEntry | null>(null);
  const [revoking, setRevoking] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.maliciousAllowlist.list(organizationId);
      setEntries(res.data);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load allowlist');
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => { refresh(); }, [refresh]);

  const handleAdded = useCallback((entry: MaliciousAllowlistEntry) => {
    setEntries((prev) => [entry, ...prev]);
    setAddOpen(false);
    toast({ title: 'Allowlist entry added', description: `${entry.package_name}${entry.version ? `@${entry.version}` : ''} (${ecosystemLabel(entry.ecosystem)})` });
  }, [toast]);

  const handleRevoke = useCallback(async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    try {
      await api.maliciousAllowlist.revoke(organizationId, revokeTarget.id);
      setEntries((prev) => prev.filter((e) => e.id !== revokeTarget.id));
      toast({ title: 'Allowlist entry revoked', description: `${revokeTarget.package_name} is no longer suppressed.` });
      setRevokeTarget(null);
    } catch (e: any) {
      toast({ title: 'Failed to revoke', description: e?.message ?? 'Try again.', variant: 'destructive' });
    } finally {
      setRevoking(false);
    }
  }, [organizationId, revokeTarget, toast]);

  return (
    <div className="space-y-6 pt-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Malicious Package Allowlist</h2>
          <p className="mt-1.5 text-sm text-foreground-secondary max-w-2xl">
            Pre-approved (package, version, ecosystem) tuples auto-suppress matching malicious findings across every project in this organization. Each entry requires a reason and is recorded in the audit trail.
          </p>
        </div>
        {canManage && (
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4 mr-1.5" />
            Add entry
          </Button>
        )}
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center px-6 py-12 text-sm text-foreground-secondary">
            <Loader2 className="h-4 w-4 mr-2 animate-spin" /> Loading allowlist…
          </div>
        ) : error ? (
          <div className="px-6 py-12 text-center text-sm text-destructive">{error}</div>
        ) : entries.length === 0 ? (
          <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
            <ShieldCheck className="h-8 w-8 text-foreground-muted mb-3" strokeWidth={1.5} />
            <h3 className="text-sm font-semibold text-foreground">No allowlisted packages yet</h3>
            <p className="mt-1.5 text-xs text-foreground-secondary max-w-sm">
              Allowlisting a package suppresses matching malicious findings across all projects in this organization.
            </p>
            {canManage && (
              <Button size="sm" variant="outline" className="mt-4" onClick={() => setAddOpen(true)}>
                <Plus className="h-4 w-4 mr-1.5" />
                Add your first entry
              </Button>
            )}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Package</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Version</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Ecosystem</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Reason</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Added by</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Added</th>
                {canManage && <th className="px-4 py-3" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {entries.map((entry) => (
                <tr key={entry.id} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-2.5 font-medium text-foreground">{entry.package_name}</td>
                  <td className="px-4 py-2.5 text-foreground-secondary">
                    {entry.version ?? <span className="italic text-foreground-muted">all versions</span>}
                  </td>
                  <td className="px-4 py-2.5 text-foreground-secondary">{ecosystemLabel(entry.ecosystem)}</td>
                  <td className="px-4 py-2.5 text-foreground-secondary max-w-md truncate" title={entry.reason}>
                    {entry.reason}
                  </td>
                  <td className="px-4 py-2.5 text-foreground-secondary">{entry.added_by_email}</td>
                  <td className="px-4 py-2.5 text-foreground-secondary">{formatDate(entry.added_at)}</td>
                  {canManage && (
                    <td className="px-4 py-2.5 text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs text-foreground-secondary hover:text-destructive"
                        onClick={() => setRevokeTarget(entry)}
                      >
                        <Trash2 className="h-3.5 w-3.5 mr-1" />
                        Revoke
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {addOpen && (
        <AddEntryDialog
          organizationId={organizationId}
          existingEntries={entries}
          onClose={() => setAddOpen(false)}
          onAdded={handleAdded}
        />
      )}

      <Dialog open={!!revokeTarget} onOpenChange={(open) => !open && !revoking && setRevokeTarget(null)}>
        <DialogContent hideClose className="p-0 gap-0 overflow-hidden bg-background-card-header">
          <div className="p-6">
            <DialogHeader>
              <DialogTitle>Revoke allowlist entry?</DialogTitle>
              <DialogDescription>
                {revokeTarget && (
                  <>Findings for <span className="font-mono text-foreground">{revokeTarget.package_name}{revokeTarget.version ? `@${revokeTarget.version}` : ''}</span> will stop being auto-suppressed on the next extraction run.</>
                )}
              </DialogDescription>
            </DialogHeader>
          </div>
          <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-background">
            <Button variant="outline" onClick={() => setRevokeTarget(null)} disabled={revoking}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRevoke}
              disabled={revoking}
              className={cn(revoking && 'disabled:opacity-100 disabled:bg-background-subtle disabled:text-foreground/70')}
            >
              {revoking ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Revoke</> : 'Revoke'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Add dialog ────────────────────────────────────────────────────────────

interface AddEntryDialogProps {
  organizationId: string;
  existingEntries: MaliciousAllowlistEntry[];
  onClose: () => void;
  onAdded: (entry: MaliciousAllowlistEntry) => void;
}

function AddEntryDialog({ organizationId, existingEntries, onClose, onAdded }: AddEntryDialogProps) {
  const { toast } = useToast();
  const [pkg, setPkg] = useState('');
  const [version, setVersion] = useState('');
  const [ecosystem, setEcosystem] = useState<MaliciousEcosystem>('npm');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const versionTrimmed = version.trim();
  const reasonTrimmed = reason.trim();
  const pkgTrimmed = pkg.trim();

  const versionError = useMemo(() => {
    if (!versionTrimmed) return null;
    if (RANGE_OPERATOR_RE.test(versionTrimmed)) {
      return 'Exact version only — semver ranges (^, ~, <, >, =, *) are not supported in v2.';
    }
    return null;
  }, [versionTrimmed]);

  const duplicate = useMemo(() => {
    return existingEntries.some(
      (e) =>
        e.package_name === pkgTrimmed &&
        e.ecosystem === ecosystem &&
        ((e.version ?? null) === (versionTrimmed || null)),
    );
  }, [existingEntries, pkgTrimmed, ecosystem, versionTrimmed]);

  const reasonTooShort = reasonTrimmed.length > 0 && reasonTrimmed.length < MIN_REASON_LEN;
  const canSubmit =
    pkgTrimmed.length > 0 &&
    reasonTrimmed.length >= MIN_REASON_LEN &&
    !versionError &&
    !duplicate &&
    !submitting;

  async function handleSubmit() {
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      const entry = await api.maliciousAllowlist.add(organizationId, {
        package_name: pkgTrimmed,
        version: versionTrimmed || null,
        ecosystem,
        reason: reasonTrimmed,
      });
      onAdded(entry);
    } catch (e: any) {
      toast({
        title: 'Failed to add entry',
        description: e?.message ?? 'Try again.',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !submitting && onClose()}>
      <DialogContent className="bg-background-card-header max-w-lg">
        <DialogHeader>
          <DialogTitle>Add allowlist entry</DialogTitle>
          <DialogDescription>
            This entry suppresses matching malicious findings across every project in your organization.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 pt-2">
          <div className="space-y-1.5">
            <Label htmlFor="al-pkg">Package name</Label>
            <Input
              id="al-pkg"
              value={pkg}
              onChange={(e) => setPkg(e.target.value)}
              placeholder="e.g. lodash"
              autoFocus
              disabled={submitting}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="al-version">Version <span className="text-foreground-muted text-xs">(optional)</span></Label>
              <Input
                id="al-version"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder="exact, e.g. 4.17.20"
                disabled={submitting}
                aria-invalid={Boolean(versionError)}
              />
              {versionError && <p className="text-xs text-destructive">{versionError}</p>}
              {!versionError && !versionTrimmed && (
                <p className="text-xs text-foreground-muted">Leave blank to allowlist every version.</p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="al-ecosystem">Ecosystem</Label>
              <Select value={ecosystem} onValueChange={(v) => setEcosystem(v as MaliciousEcosystem)} disabled={submitting}>
                <SelectTrigger id="al-ecosystem"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {MALICIOUS_ECOSYSTEMS.map((e) => (
                    <SelectItem key={e} value={e}>{ecosystemLabel(e)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="al-reason">Reason</Label>
            <textarea
              id="al-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. used in test fixtures only — vetted by security 2026-04-15"
              disabled={submitting}
              rows={3}
              className={cn(
                'w-full px-3 py-2 bg-background-card border border-border rounded-md',
                'text-sm text-foreground placeholder:text-foreground-secondary',
                'focus:ring-2 focus:ring-primary/50 focus:border-primary focus:outline-none',
                'resize-none',
                reasonTooShort && 'border-destructive/50',
              )}
            />
            <div className="flex items-center justify-between">
              <p className={cn('text-xs', reasonTooShort ? 'text-destructive' : 'text-foreground-muted')}>
                {reasonTooShort
                  ? `Reason must be at least ${MIN_REASON_LEN} characters (${reasonTrimmed.length}/${MIN_REASON_LEN}).`
                  : `Captured in the audit trail. Min ${MIN_REASON_LEN} chars.`}
              </p>
              <p className="text-xs text-foreground-muted">{reasonTrimmed.length}/2000</p>
            </div>
          </div>

          {duplicate && (
            <p className="text-xs text-warning">An entry for this package + version already exists.</p>
          )}
        </div>

        <div className="flex items-center justify-between pt-4 border-t border-border -mx-6 px-6">
          <Button variant="outline" onClick={onClose} disabled={submitting}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={!canSubmit}>
            {submitting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Adding…</> : 'Add entry'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
