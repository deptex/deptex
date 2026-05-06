import { useEffect, useState, useCallback } from 'react';
import { Loader2, Plus, Trash2, CheckCircle2, XCircle } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';
import { api, type RegistryCredential, type RegistryType, type CredentialShape } from '../../lib/api';
import AddRegistryCredentialDialog from './AddRegistryCredentialDialog';

const REGISTRY_TYPE_LABELS: Record<RegistryType, string> = {
  ghcr: 'GHCR',
  ecr: 'ECR',
  gcr: 'GCR',
  acr: 'ACR',
  dockerhub: 'Docker Hub',
  quay: 'Quay',
  harbor: 'Harbor',
  jfrog: 'JFrog',
  custom: 'Custom',
};

const SHAPE_LABELS: Record<CredentialShape, string> = {
  username_password: 'username + password',
  aws_keys: 'AWS keys',
  gcp_service_account_key: 'GCP service account',
  azure_service_principal: 'Azure SP',
  token: 'token',
};

interface Props {
  organizationId: string;
  canManage: boolean;
}

type TestState =
  | { status: 'idle' }
  | { status: 'pending' }
  | { status: 'ok' }
  | { status: 'error'; errorClass: 'decrypt_failed' | 'shape_invalid' };

export default function RegistryCredentialsSection({ organizationId, canManage }: Props) {
  const [creds, setCreds] = useState<RegistryCredential[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<RegistryCredential | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [testStateById, setTestStateById] = useState<Record<string, TestState>>({});

  const reload = useCallback(async () => {
    setError(null);
    try {
      const list = await api.listRegistryCredentials(organizationId);
      setCreds(list);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load registry credentials');
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    setLoading(true);
    reload();
  }, [reload]);

  const handleCreated = (c: RegistryCredential) => {
    setCreds((prev) => (prev ? [c, ...prev] : [c]));
  };

  const handleTest = async (cred: RegistryCredential) => {
    setTestStateById((s) => ({ ...s, [cred.id]: { status: 'pending' } }));
    try {
      const result = await api.testRegistryCredential(organizationId, cred.id);
      if (result.ok) {
        setTestStateById((s) => ({ ...s, [cred.id]: { status: 'ok' } }));
      } else {
        setTestStateById((s) => ({
          ...s,
          [cred.id]: { status: 'error', errorClass: result.error_class },
        }));
      }
    } catch {
      setTestStateById((s) => ({ ...s, [cred.id]: { status: 'error', errorClass: 'decrypt_failed' } }));
    }
  };

  const handleConfirmDelete = async () => {
    if (!confirmDelete) return;
    setDeleting(true);
    try {
      await api.deleteRegistryCredential(organizationId, confirmDelete.id);
      setCreds((prev) => (prev ?? []).filter((c) => c.id !== confirmDelete.id));
      setConfirmDelete(null);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to delete credential');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="rounded-lg border border-border bg-background-card overflow-hidden">
      <div className="flex items-center justify-between p-6 pb-4">
        <div>
          <h3 className="text-base font-semibold text-foreground">Registry credentials</h3>
          <p className="text-sm text-foreground-secondary mt-1">
            Encrypted credentials shared across this organization. Used by container scans to pull
            private images. The plaintext is never returned to the browser after submit.
          </p>
        </div>
        {canManage && (
          <Button variant="outline" size="sm" onClick={() => setShowAdd(true)}>
            <Plus className="h-3.5 w-3.5 mr-1.5" />
            Add credential
          </Button>
        )}
      </div>

      <div className="border-t border-border">
        {loading ? (
          <div className="divide-y divide-border">
            {[0, 1].map((i) => (
              <div key={i} className="px-6 py-4">
                <div className="h-4 w-40 bg-foreground/5 rounded mb-2 animate-pulse" />
                <div className="h-3 w-24 bg-foreground/5 rounded animate-pulse" />
              </div>
            ))}
          </div>
        ) : error ? (
          <div className="px-6 py-6 text-sm text-destructive">{error}</div>
        ) : !creds || creds.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <div className="text-sm text-foreground-secondary">No registry credentials yet.</div>
            {canManage && (
              <div className="text-xs text-foreground-muted mt-1">
                Add one to scan images from a private registry.
              </div>
            )}
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {creds.map((cred) => {
              const test = testStateById[cred.id] ?? { status: 'idle' };
              return (
                <li key={cred.id} className="px-6 py-4 flex items-center justify-between gap-4">
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-foreground truncate">
                      {cred.display_name}
                    </div>
                    <div className="text-xs text-foreground-secondary mt-0.5">
                      {REGISTRY_TYPE_LABELS[cred.registry_type]} · {SHAPE_LABELS[cred.credential_shape]}
                      {cred.registry_url ? ` · ${cred.registry_url}` : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <TestBadge state={test} />
                    {canManage && (
                      <>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleTest(cred)}
                          disabled={test.status === 'pending'}
                        >
                          {test.status === 'pending' ? (
                            <><Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />Testing</>
                          ) : (
                            'Test'
                          )}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setConfirmDelete(cred)}
                          aria-label={`Delete ${cred.display_name}`}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {showAdd && (
        <AddRegistryCredentialDialog
          open={showAdd}
          organizationId={organizationId}
          onClose={() => setShowAdd(false)}
          onCreated={handleCreated}
        />
      )}

      <Dialog open={!!confirmDelete} onOpenChange={(o) => !o && !deleting && setConfirmDelete(null)}>
        <DialogContent hideClose className="p-0 gap-0 overflow-hidden bg-background-card-header">
          <div className="p-6">
            <DialogHeader>
              <DialogTitle>Delete credential?</DialogTitle>
              <DialogDescription>
                Removing &ldquo;{confirmDelete?.display_name}&rdquo; will detach it from any
                configured images that reference it across this organization. Future scans of those
                images will skip pull. This cannot be undone.
              </DialogDescription>
            </DialogHeader>
          </div>
          <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-background">
            <Button variant="outline" onClick={() => setConfirmDelete(null)} disabled={deleting}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleConfirmDelete}
              disabled={deleting}
              className={cn(
                deleting && 'disabled:opacity-100 disabled:bg-background-subtle disabled:text-foreground/70',
              )}
            >
              {deleting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Delete</> : 'Delete'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function TestBadge({ state }: { state: TestState }) {
  if (state.status === 'ok') {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-green-400">
        <CheckCircle2 className="h-3.5 w-3.5" />
        OK
      </span>
    );
  }
  if (state.status === 'error') {
    const label = state.errorClass === 'decrypt_failed' ? 'Decrypt failed' : 'Shape invalid';
    return (
      <span className="inline-flex items-center gap-1 text-xs text-destructive">
        <XCircle className="h-3.5 w-3.5" />
        {label}
      </span>
    );
  }
  return null;
}
