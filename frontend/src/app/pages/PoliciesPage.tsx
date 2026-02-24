import { useState, useEffect, useCallback } from 'react';
import { useParams, useOutletContext } from 'react-router-dom';
import { Save, Undo2, Check, X, Clock, FileText } from 'lucide-react';
import { api, Organization, OrganizationPolicies, RolePermissions, ProjectPolicyException } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { PolicyCodeEditor } from '../../components/PolicyCodeEditor';
import { PolicyDiffViewer } from '../../components/PolicyDiffViewer';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Toaster } from '../../components/ui/toaster';

/** Default policy template shown when org has no policy code yet. */
export const DEFAULT_POLICY_TEMPLATE = `// Policy-as-code: define rules for PR/merge. Evaluator receives each dependency with:
//   name, version, license
//   vulnerabilities: [{ severity, osv_id, aliases, fixed_versions, published_at }] (current + past versions)
//   slsaLevel: 1-4 or null (when you have provenance/attestation data)
// Optional context you can use when evaluator supports it: score, weekly_downloads, last_published_at, releases_last_12_months

const orgPolicy = {
  // License: allow list, or use bannedLicenses to block specific ones
  allowedLicenses: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"],
  bannedLicenses: ["AGPL-1.0", "AGPL-3.0", "GPL-3.0"],
  // SLSA: minimum level required (1-4), or null for no requirement
  minSlsaLevel: null,
  // Vulnerabilities: block PR if any dependency has vuln meeting these rules
  blockCritical: true,
  blockHigh: false,
  allowOnlyIfFixed: false  // if true, block when vuln has no fix in a released version
};

function evaluateDependencySet(dependencies, policy) {
  for (const pkg of dependencies) {
    const license = pkg.license || "UNKNOWN";
    if (policy.bannedLicenses && policy.bannedLicenses.some(b => license.includes(b))) {
      return { passed: false, reason: \`Banned license: \${license} (\${pkg.name}@\${pkg.version})\` };
    }
    if (policy.allowedLicenses && policy.allowedLicenses.length > 0) {
      const allowed = policy.allowedLicenses.some(a => license.includes(a));
      if (!allowed && license !== "UNKNOWN") {
        return { passed: false, reason: \`License not allowed: \${license} (\${pkg.name})\` };
      }
    }
    if (policy.minSlsaLevel != null && (pkg.slsaLevel == null || pkg.slsaLevel < policy.minSlsaLevel)) {
      return { passed: false, reason: \`SLSA level required: \${policy.minSlsaLevel} (\${pkg.name} has \${pkg.slsaLevel ?? "none"})\` };
    }
    const vulns = pkg.vulnerabilities || [];
    for (const v of vulns) {
      if (policy.blockCritical && (v.severity === "critical" || v.severity === "CRITICAL")) {
        return { passed: false, reason: \`Critical vulnerability: \${v.osv_id || v.aliases?.[0]} in \${pkg.name}@\${pkg.version}\` };
      }
      if (policy.blockHigh && (v.severity === "high" || v.severity === "HIGH")) {
        return { passed: false, reason: \`High vulnerability: \${v.osv_id || v.aliases?.[0]} in \${pkg.name}@\${pkg.version}\` };
      }
      if (policy.allowOnlyIfFixed && (!v.fixed_versions || v.fixed_versions.length === 0)) {
        return { passed: false, reason: \`Unfixed vulnerability: \${v.osv_id || v.aliases?.[0]} in \${pkg.name}@\${pkg.version}\` };
      }
    }
  }
  return { passed: true };
}
`;

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

interface PoliciesPageProps {
  isSettingsSubpage?: boolean;
}

export default function PoliciesPage({ isSettingsSubpage = false }: PoliciesPageProps) {
  const { id } = useParams<{ id: string }>();
  const { organization } = useOutletContext<OrganizationContextType>();
  const { toast } = useToast();

  const [policies, setPolicies] = useState<OrganizationPolicies | null>(null);
  const [loading, setLoading] = useState(true);
  const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(null);
  const [permissionsLoaded, setPermissionsLoaded] = useState(false);

  const [savedCode, setSavedCode] = useState('');
  const [editorCode, setEditorCode] = useState('');
  const [saving, setSaving] = useState(false);
  const [hasSyncedFromPolicies, setHasSyncedFromPolicies] = useState(false);

  const [activeTab, setActiveTab] = useState<'policies' | 'exceptions'>('policies');
  const [exceptions, setExceptions] = useState<ProjectPolicyException[]>([]);
  const [exceptionsLoading, setExceptionsLoading] = useState(false);
  const [reviewingExceptionId, setReviewingExceptionId] = useState<string | null>(null);
  const [reviewingStatus, setReviewingStatus] = useState<'idle' | 'accepting' | 'rejecting'>('idle');

  const loadExceptions = useCallback(async () => {
    if (!id) return;
    try {
      setExceptionsLoading(true);
      const list = await api.getOrganizationPolicyExceptions(id);
      setExceptions(list);
    } catch (e: any) {
      toast({ title: 'Error', description: e.message || 'Failed to load exception applications', variant: 'destructive' });
    } finally {
      setExceptionsLoading(false);
    }
  }, [id, toast]);

  useEffect(() => {
    if (id && activeTab === 'exceptions') {
      loadExceptions();
    }
  }, [id, activeTab, loadExceptions]);

  const getCachedPermissions = (): RolePermissions | null => {
    if (organization?.permissions) return organization.permissions;
    if (id) {
      const cachedStr = localStorage.getItem(`org_permissions_${id}`);
      if (cachedStr) {
        try { return JSON.parse(cachedStr); } catch { return null; }
      }
    }
    return null;
  };

  useEffect(() => {
    const loadPermissions = async () => {
      if (!id || !organization?.role) {
        setPermissionsLoaded(true);
        return;
      }
      const cachedPerms = getCachedPermissions();
      if (cachedPerms) setUserPermissions(cachedPerms);
      try {
        const roles = await api.getOrganizationRoles(id);
        const userRole = roles.find(r => r.name === organization.role);
        if (userRole?.permissions) {
          setUserPermissions(userRole.permissions);
          localStorage.setItem(`org_permissions_${id}`, JSON.stringify(userRole.permissions));
        }
      } catch (error) {
        console.error('Failed to load permissions:', error);
      } finally {
        setPermissionsLoaded(true);
      }
    };
    loadPermissions();
  }, [id, organization?.role]);

  useEffect(() => {
    if (id && permissionsLoaded) loadPolicies();
  }, [id, permissionsLoaded]);

  // Sync editor from server when policies load or after save
  useEffect(() => {
    if (!policies) return;
    const code = (policies.policy_code ?? '').trim() || DEFAULT_POLICY_TEMPLATE;
    setSavedCode(code);
    setEditorCode(code);
    setHasSyncedFromPolicies(true);
  }, [policies?.policy_code]);

  const loadPolicies = async () => {
    if (!id) return;
    try {
      setLoading(true);
      const policiesData = await api.getOrganizationPolicies(id);
      setPolicies(policiesData);
    } catch (error: any) {
      console.error('Failed to load policies:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to load policies',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const isDirty = hasSyncedFromPolicies && editorCode !== savedCode;

  const handleSave = async () => {
    if (!id) return;
    try {
      setSaving(true);
      const updated = await api.updateOrganizationPolicies(id, { policy_code: editorCode });
      setPolicies(updated);
      setSavedCode(updated.policy_code ?? editorCode);
      setEditorCode(updated.policy_code ?? editorCode);
      toast({
        title: 'Policy saved',
        description: 'Your organization policy has been updated successfully.',
      });
    } catch (error: any) {
      console.error('Failed to save policy:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to save policy',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDiscard = () => {
    setEditorCode(savedCode);
  };

  const canEdit = userPermissions?.edit_policies ?? false;

  if (!organization) {
    return (
      <main className={isSettingsSubpage ? '' : 'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8'}>
        <div className="animate-pulse">
          <div className="h-8 bg-background-subtle rounded w-1/4 mb-4" />
          <div className="h-4 bg-background-subtle rounded w-1/2" />
        </div>
      </main>
    );
  }

  if (loading || !permissionsLoaded) {
    return (
      <main className={isSettingsSubpage ? '' : 'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8'}>
        <div className="mb-8 flex items-center justify-between">
          <div>
            {isSettingsSubpage ? (
              <>
                <h2 className="text-2xl font-bold text-foreground">Policies</h2>
                <p className="text-foreground-secondary mt-1">Define your organization&apos;s policy as code.</p>
              </>
            ) : (
              <>
                <h1 className="text-3xl font-bold text-foreground mb-2">Policies</h1>
                <p className="text-foreground-secondary">Define your organization&apos;s policy as code.</p>
              </>
            )}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-[#1d1f21] overflow-hidden p-4" style={{ minHeight: '360px' }}>
          <div className="space-y-3 animate-pulse">
            <div className="h-3.5 bg-white/10 rounded w-full max-w-[85%]" />
            <div className="h-3.5 bg-white/10 rounded w-full max-w-[70%]" />
            <div className="h-3.5 bg-white/10 rounded w-full max-w-[60%]" />
            <div className="h-3.5 bg-white/10 rounded w-12" />
            <div className="h-3.5 bg-white/10 rounded w-full max-w-[80%]" />
          </div>
        </div>
      </main>
    );
  }

  const reviewingException = reviewingExceptionId ? exceptions.find((e) => e.id === reviewingExceptionId) : null;
  const canReviewExceptions = userPermissions?.edit_policies ?? false;

  return (
    <>
      <main className={isSettingsSubpage ? '' : 'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8'}>
        <div className="mb-6 flex items-center justify-between border-b border-border">
          <div className="flex items-center gap-6">
            <button
              type="button"
              onClick={() => setActiveTab('policies')}
              className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === 'policies' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
              }`}
            >
              Policies
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('exceptions')}
              className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === 'exceptions' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
              }`}
            >
              Exception applications
            </button>
          </div>
        </div>

        {activeTab === 'policies' && (
          <>
            <div className="mb-6">
              {isSettingsSubpage ? (
                <>
                  <h2 className="text-2xl font-bold text-foreground">Policies</h2>
                  <p className="text-foreground-secondary mt-1">Define your organization&apos;s policy as code.</p>
                </>
              ) : (
                <>
                  <h1 className="text-3xl font-bold text-foreground mb-2">Policies</h1>
                  <p className="text-foreground-secondary">Define your organization&apos;s policy as code.</p>
                </>
              )}
            </div>
            <div className="relative">
              <PolicyCodeEditor
                value={editorCode}
                onChange={setEditorCode}
                readOnly={!canEdit}
                minHeight="360px"
              />
              {canEdit && isDirty && (
                <div className="absolute top-3 right-3 flex flex-row gap-2 z-10">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleDiscard}
                    disabled={saving}
                    className="rounded-lg border border-border bg-background-subtle hover:bg-table-hover text-foreground text-xs font-medium transition-colors"
                  >
                    <Undo2 className="h-4 w-4 mr-1.5" />
                    Discard
                  </Button>
                  <Button size="sm" onClick={handleSave} disabled={saving} className="shadow-sm">
                    {saving ? (
                      <span className="h-4 w-4 mr-1.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
                    ) : (
                      <Save className="h-4 w-4 mr-1.5" />
                    )}
                    Save
                  </Button>
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === 'exceptions' && (
          <div className="space-y-6">
            <div>
              <h2 className="text-2xl font-bold text-foreground">Exception applications</h2>
              <p className="text-foreground-secondary mt-1">Review and accept or reject policy exception requests from projects.</p>
            </div>
            {reviewingException && reviewingException.status === 'pending' && (
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <div className="p-4 border-b border-border flex items-center justify-between">
                  <div>
                    <span className="font-medium text-foreground">{reviewingException.project_name ?? 'Project'}</span>
                    <span className="text-foreground-secondary text-sm ml-2">
                      requested by {reviewingException.requester?.full_name || reviewingException.requester?.email || 'Unknown'}
                    </span>
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => setReviewingExceptionId(null)}>Close</Button>
                </div>
                {reviewingException.reason && (
                  <div className="px-4 py-2 bg-background-subtle/50 border-b border-border">
                    <p className="text-sm text-foreground-secondary"><FileText className="h-4 w-4 inline mr-1.5" />Reason: {reviewingException.reason}</p>
                  </div>
                )}
                <div className="p-4">
                  <PolicyDiffViewer
                    baseCode={reviewingException.base_policy_code ?? ''}
                    requestedCode={reviewingException.requested_policy_code ?? ''}
                    minHeight="320px"
                  />
                </div>
                <div className="p-4 border-t border-border flex gap-2 justify-end">
                  <Button
                    variant="outline"
                    disabled={reviewingStatus !== 'idle'}
                    onClick={async () => {
                      if (!id || !reviewingException.id) return;
                      setReviewingStatus('rejecting');
                      try {
                        await api.reviewPolicyException(id, reviewingException.id, 'rejected');
                        toast({ title: 'Exception rejected' });
                        setReviewingExceptionId(null);
                        await loadExceptions();
                      } catch (e: any) {
                        toast({ title: 'Error', description: e.message || 'Failed to reject', variant: 'destructive' });
                      } finally {
                        setReviewingStatus('idle');
                      }
                    }}
                  >
                    <X className="h-4 w-4 mr-1.5" />
                    Reject
                  </Button>
                  <Button
                    disabled={reviewingStatus !== 'idle'}
                    onClick={async () => {
                      if (!id || !reviewingException.id) return;
                      setReviewingStatus('accepting');
                      try {
                        await api.reviewPolicyException(id, reviewingException.id, 'accepted');
                        toast({ title: 'Exception accepted' });
                        setReviewingExceptionId(null);
                        await loadExceptions();
                      } catch (e: any) {
                        toast({ title: 'Error', description: e.message || 'Failed to accept', variant: 'destructive' });
                      } finally {
                        setReviewingStatus('idle');
                      }
                    }}
                  >
                    <Check className="h-4 w-4 mr-1.5" />
                    Accept
                  </Button>
                </div>
              </div>
            )}
            {exceptionsLoading ? (
              <div className="rounded-lg border border-border p-8 text-center text-foreground-secondary text-sm">Loading…</div>
            ) : exceptions.length === 0 ? (
              <div className="rounded-lg border border-border bg-background-card p-12 text-center">
                <FileText className="h-10 w-10 text-foreground-secondary/40 mx-auto mb-3" />
                <p className="text-sm text-foreground-secondary">No exception applications</p>
              </div>
            ) : (
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full">
                  <thead className="bg-[#141618] border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Requester</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Date</th>
                      {canReviewExceptions && (
                        <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Actions</th>
                      )}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {exceptions.map((ex) => (
                      <tr key={ex.id} className="hover:bg-table-hover transition-colors">
                        <td className="px-4 py-3 text-sm text-foreground">{ex.project_name ?? '—'}</td>
                        <td className="px-4 py-3 text-sm text-foreground-secondary">{ex.requester?.full_name || ex.requester?.email || '—'}</td>
                        <td className="px-4 py-3">
                          {ex.status === 'pending' && (
                            <Badge variant="warning" className="gap-1"><Clock className="h-3 w-3" /> Pending</Badge>
                          )}
                          {ex.status === 'accepted' && (
                            <Badge variant="success" className="gap-1"><Check className="h-3 w-3" /> Accepted</Badge>
                          )}
                          {ex.status === 'rejected' && (
                            <Badge variant="destructive" className="gap-1"><X className="h-3 w-3" /> Rejected</Badge>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sm text-foreground-secondary">{new Date(ex.created_at).toLocaleDateString()}</td>
                        {canReviewExceptions && (
                          <td className="px-4 py-3 text-right">
                            {ex.status === 'pending' && (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setReviewingExceptionId(ex.id)}
                              >
                                Review
                              </Button>
                            )}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </main>

      <Toaster position="bottom-right" />
    </>
  );
}
