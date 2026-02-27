import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useParams, useOutletContext, useNavigate, Link } from 'react-router-dom';
import { cn } from '../../lib/utils';
import { Check, X, Clock, BookOpen, Sparkles, Eye, Ban, FileQuestion } from 'lucide-react';
import { api, Organization, OrganizationPolicies, RolePermissions, ProjectPolicyException } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { PolicyCodeEditor } from '../../components/PolicyCodeEditor';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '../../components/ui/avatar';
import { Toaster } from '../../components/ui/toaster';
import { PolicyAIAssistant } from '../../components/PolicyAIAssistant';
import { PolicyExceptionSidebar } from '../../components/PolicyExceptionSidebar';
import { FrameworkIcon } from '../../components/framework-icon';
import { RoleBadge } from '../../components/RoleBadge';

/** Minimal default: both return pass/compliant. */
const DEFAULT_PULL_REQUEST_BODY = 'return { passed: true };';
const DEFAULT_COMPLIANCE_BODY = 'return { compliant: true };';

/** Assemble full policy code from two function bodies. */
function assemblePolicyCode(pullRequestBody: string, complianceBody: string): string {
  const prLines = pullRequestBody.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
  const compLines = complianceBody.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
  return `function pullRequestCheck(context) {\n${prLines.join('\n')}\n}\n\nfunction projectCompliance(context) {\n${compLines.join('\n')}\n}`;
}

/** Extract the body of a named function from full policy code. */
function extractFunctionBody(code: string, fnName: string): string | null {
  const regex = new RegExp(`function\\s+${fnName}\\s*\\([^)]*\\)\\s*\\{`, 'g');
  const match = regex.exec(code);
  if (!match) return null;
  const startIdx = match.index + match[0].length;
  let depth = 1;
  let i = startIdx;
  while (i < code.length && depth > 0) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') depth--;
    i++;
  }
  return code.slice(startIdx, i - 1).trim();
}

/** Parse full policy code into pullRequestCheck and projectCompliance bodies. */
function parsePolicyCode(code: string): { pullRequestBody: string; complianceBody: string } {
  const prBody = extractFunctionBody(code, 'pullRequestCheck');
  const compBody = extractFunctionBody(code, 'projectCompliance');
  return {
    pullRequestBody: prBody ?? DEFAULT_PULL_REQUEST_BODY,
    complianceBody: compBody ?? DEFAULT_COMPLIANCE_BODY,
  };
}

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

interface PoliciesPageProps {
  isSettingsSubpage?: boolean;
}

export default function PoliciesPage({ isSettingsSubpage = false }: PoliciesPageProps) {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { organization } = useOutletContext<OrganizationContextType>();
  const { toast } = useToast();

  const [policies, setPolicies] = useState<OrganizationPolicies | null>(null);
  const [loading, setLoading] = useState(true);
  const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(null);
  const [permissionsLoaded, setPermissionsLoaded] = useState(false);

  const [savedPullRequestBody, setSavedPullRequestBody] = useState('');
  const [savedComplianceBody, setSavedComplianceBody] = useState('');
  const [pullRequestBody, setPullRequestBody] = useState('');
  const [complianceBody, setComplianceBody] = useState('');
  const [saving, setSaving] = useState(false);
  const [hasSyncedFromPolicies, setHasSyncedFromPolicies] = useState(false);

  const [showAI, setShowAI] = useState(false);
  const [aiPanelVisible, setAiPanelVisible] = useState(false);
  const aiCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [activeTab, setActiveTab] = useState<'policies' | 'exceptions'>('policies');
  const [exceptions, setExceptions] = useState<ProjectPolicyException[]>([]);
  const [exceptionsLoading, setExceptionsLoading] = useState(false);
  const [reviewingExceptionId, setReviewingExceptionId] = useState<string | null>(null);
  const [viewingExceptionId, setViewingExceptionId] = useState<string | null>(null);

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
    if (id) loadExceptions();
  }, [id, loadExceptions]);

  const loadPolicies = useCallback(async () => {
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
  }, [id, toast]);

  // AI sidebar: animate in on open, animate out before unmount
  useEffect(() => {
    if (showAI) {
      setAiPanelVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setAiPanelVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setAiPanelVisible(false);
    }
  }, [showAI]);

  useEffect(() => () => {
    if (aiCloseTimeoutRef.current) clearTimeout(aiCloseTimeoutRef.current);
  }, []);

  const closeAIPanel = useCallback(() => {
    setAiPanelVisible(false);
    if (aiCloseTimeoutRef.current) clearTimeout(aiCloseTimeoutRef.current);
    aiCloseTimeoutRef.current = setTimeout(() => {
      aiCloseTimeoutRef.current = null;
      setShowAI(false);
    }, 150);
  }, []);

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
      if (cachedPerms) {
        setUserPermissions(cachedPerms);
        setPermissionsLoaded(true);
      }
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
    if (id) loadPolicies();
  }, [id, loadPolicies]);

  // Sync editors from server when policies load or after save
  useEffect(() => {
    if (!policies) return;
    const code = (policies.policy_code ?? '').trim();
    const { pullRequestBody: pr, complianceBody: comp } = code
      ? parsePolicyCode(code)
      : { pullRequestBody: DEFAULT_PULL_REQUEST_BODY, complianceBody: DEFAULT_COMPLIANCE_BODY };
    setSavedPullRequestBody(pr);
    setSavedComplianceBody(comp);
    setPullRequestBody(pr);
    setComplianceBody(comp);
    setHasSyncedFromPolicies(true);
  }, [policies?.policy_code]);

  const complianceDirty =
    hasSyncedFromPolicies && complianceBody !== savedComplianceBody;
  const pullRequestDirty =
    hasSyncedFromPolicies && pullRequestBody !== savedPullRequestBody;

  const handleSave = async () => {
    if (!id) return;
    try {
      setSaving(true);
      const codeToSave = assemblePolicyCode(pullRequestBody, complianceBody);
      const updated = await api.updateOrganizationPolicies(id, { policy_code: codeToSave });
      setPolicies(updated);
      const { pullRequestBody: pr, complianceBody: comp } = parsePolicyCode(updated.policy_code ?? codeToSave);
      setSavedPullRequestBody(pr);
      setSavedComplianceBody(comp);
      setPullRequestBody(pr);
      setComplianceBody(comp);
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

  const handleDiscardCompliance = () => setComplianceBody(savedComplianceBody);
  const handleDiscardPullRequest = () => setPullRequestBody(savedPullRequestBody);

  const hasManageCompliance =
    userPermissions?.manage_compliance === true ||
    organization?.role === 'owner' ||
    organization?.role === 'admin';
  const canEdit = hasManageCompliance;

  if (!organization) {
    return (
      <main className={`${isSettingsSubpage ? '' : 'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8'} py-8`}>
        <div className="animate-pulse">
          <div className="h-8 bg-background-subtle rounded w-1/4 mb-4" />
          <div className="h-4 bg-background-subtle rounded w-1/2" />
        </div>
      </main>
    );
  }

  if (permissionsLoaded && !hasManageCompliance) {
    if (id) navigate(`/organizations/${id}`, { replace: true });
    return null;
  }

  if (loading) {
    return (
      <main className={`${isSettingsSubpage ? '' : 'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8'} py-8`}>
        <div className="sticky top-0 z-10 bg-background pb-2">
          <div className="mb-6 flex items-start justify-between">
            <div>
              {isSettingsSubpage ? (
                <h2 className="text-2xl font-bold text-foreground">Policies</h2>
              ) : (
                <h1 className="text-3xl font-bold text-foreground">Policies</h1>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="text-xs" disabled>
                <Sparkles className="h-3.5 w-3.5 mr-1.5" />
                AI Assistant
              </Button>
              <Button variant="outline" size="sm" className="text-xs" disabled>
                <BookOpen className="h-3.5 w-3.5 mr-1.5" />
                Docs
              </Button>
            </div>
          </div>
          <div className="flex items-center border-b border-border pb-px">
            <div className="flex items-center gap-6">
              <span className="pb-3 text-sm font-medium text-foreground border-b-2 border-foreground -mb-px">Policy</span>
              <span className="pb-3 text-sm font-medium text-foreground-secondary border-b-2 border-transparent -mb-px">Exception applications</span>
            </div>
          </div>
        </div>
        <div className="space-y-6 pt-2">
          {[0, 1].map((i) => (
            <div key={i} className="rounded-lg border border-border bg-background-card overflow-hidden">
              <div className="px-4 py-2.5 bg-background-card-header border-b border-border">
                <div className="h-3.5 bg-muted rounded w-32 animate-pulse" />
              </div>
              <div className="bg-[#1d1f21] px-4 py-3 font-mono text-[13px] leading-6" style={{ minHeight: '180px' }}>
                <div className="space-y-1.5 animate-pulse">
                  <div className="h-3 bg-white/[0.06] rounded w-[70%]" />
                  <div className="h-3 bg-white/[0.06] rounded w-[55%] ml-4" />
                  <div className="h-3 bg-white/[0.06] rounded w-[80%] ml-4" />
                  <div className="h-3 bg-white/[0.06] rounded w-[40%] ml-8" />
                  <div className="h-3 bg-white/[0.06] rounded w-[60%] ml-4" />
                  <div className="h-3 bg-white/[0.06] rounded w-[30%]" />
                  <div className="h-3" />
                  <div className="h-3 bg-white/[0.06] rounded w-[50%] ml-4" />
                  <div className="h-3 bg-white/[0.06] rounded w-[45%] ml-4" />
                </div>
              </div>
            </div>
          ))}
        </div>
      </main>
    );
  }

  const reviewingException = reviewingExceptionId ? exceptions.find((e) => e.id === reviewingExceptionId) : null;
  const canReviewExceptions = hasManageCompliance;

  return (
    <>
      <div className="w-full">
        <main className={`${isSettingsSubpage ? '' : 'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8'} py-8`}>
        {/* Sticky header so title and tabs stay visible when scrolling */}
        <div className="sticky top-0 z-10 bg-background pb-2">
        <div className="mb-6 flex items-start justify-between">
          <div>
            {isSettingsSubpage ? (
              <h2 className="text-2xl font-bold text-foreground">Policies</h2>
            ) : (
              <h1 className="text-3xl font-bold text-foreground">Policies</h1>
            )}
          </div>
          <div className="flex items-center gap-2">
            {canEdit && (
              <Button variant="outline" size="sm" className="text-xs" onClick={() => setShowAI(true)}>
                <Sparkles className="h-3.5 w-3.5 mr-1.5" />
                AI Assistant
              </Button>
            )}
            <Link to="/docs/policies" target="_blank">
              <Button variant="outline" size="sm" className="text-xs">
                <BookOpen className="h-3.5 w-3.5 mr-1.5" />
                Docs
              </Button>
            </Link>
          </div>
        </div>

        <div className="flex items-center justify-between border-b border-border pb-px">
          <div className="flex items-center gap-6">
            <button
              type="button"
              onClick={() => setActiveTab('policies')}
              className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === 'policies' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
              }`}
            >
              Policy
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
        </div>

        {activeTab === 'policies' && (
          <div className="space-y-6 pt-2 pb-8">
            <div className="rounded-lg border border-border bg-background-card overflow-hidden">
              <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
                <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project Compliance</span>
                {canEdit && complianceDirty && (
                  <div className="flex items-center gap-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleDiscardCompliance}
                      disabled={saving}
                      className="h-5 min-h-5 px-1.5 py-0 text-[11px] leading-none"
                    >
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      onClick={handleSave}
                      disabled={saving}
                      className="h-5 min-h-5 px-1.5 py-0 text-[11px] leading-none shadow-sm gap-1"
                    >
                      {saving && (
                        <span className="h-2.5 w-2.5 animate-spin rounded-full border-2 border-current border-t-transparent shrink-0" />
                      )}
                      Save
                    </Button>
                  </div>
                )}
              </div>
              <div className="bg-background-card">
                <PolicyCodeEditor
                  value={complianceBody}
                  onChange={setComplianceBody}
                  readOnly={!canEdit}
                  fitContent
                />
              </div>
            </div>

            <div className="rounded-lg border border-border bg-background-card overflow-hidden">
              <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
                <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Pull Request Check</span>
                {canEdit && pullRequestDirty && (
                  <div className="flex items-center gap-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleDiscardPullRequest}
                      disabled={saving}
                      className="h-5 min-h-5 px-1.5 py-0 text-[11px] leading-none"
                    >
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      onClick={handleSave}
                      disabled={saving}
                      className="h-5 min-h-5 px-1.5 py-0 text-[11px] leading-none shadow-sm gap-1"
                    >
                      {saving && (
                        <span className="h-2.5 w-2.5 animate-spin rounded-full border-2 border-current border-t-transparent shrink-0" />
                      )}
                      Save
                    </Button>
                  </div>
                )}
              </div>
              <div className="bg-background-card">
                <PolicyCodeEditor
                  value={pullRequestBody}
                  onChange={setPullRequestBody}
                  readOnly={!canEdit}
                  fitContent
                />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'exceptions' && (
          <div className="space-y-6 pt-2 pb-8">
            {exceptionsLoading ? (
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full table-fixed">
                  <colgroup>
                    <col className="w-[200px]" />
                    <col className="w-[180px]" />
                    <col className="w-[120px]" />
                    <col className="w-[120px]" />
                    <col className="w-[120px]" />
                  </colgroup>
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Requester</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Type</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                      <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {[0, 1, 2].map((i) => (
                      <tr key={i} className="animate-pulse">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-5 w-5 rounded bg-muted flex-shrink-0" />
                            <div className="h-4 bg-muted rounded w-24" />
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-5 w-5 rounded-full bg-muted flex-shrink-0" />
                            <div className="h-4 bg-muted rounded w-24" />
                          </div>
                        </td>
                        <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-20" /></td>
                        <td className="px-4 py-3"><div className="h-5 bg-muted rounded w-16" /></td>
                        <td className="px-4 py-3 text-right"><div className="h-7 bg-muted rounded w-16 ml-auto" /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full table-fixed">
                  <colgroup>
                    <col className="w-[200px]" />
                    <col className="w-[180px]" />
                    <col className="w-[120px]" />
                    <col className="w-[120px]" />
                    <col className="w-[120px]" />
                  </colgroup>
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Requester</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Type</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                      <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {exceptions.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-12">
                          <div className="flex flex-col items-center justify-center gap-3 text-center">
                            <FileQuestion className="h-10 w-10 text-foreground-muted" />
                            <div>
                              <p className="text-sm font-medium text-foreground">No exception applications</p>
                              <p className="text-sm text-foreground-secondary mt-1 max-w-sm">
                                Projects can request policy exceptions when they need different rules. Requests will appear here for review.
                              </p>
                            </div>
                          </div>
                        </td>
                      </tr>
                    ) : (
                      exceptions.map((ex) => (
                        <tr key={ex.id} className="group hover:bg-table-hover transition-colors">
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <FrameworkIcon frameworkId={ex.project_framework} size={20} />
                              <span className="text-sm text-foreground">{ex.project_name ?? '\u2014'}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-3 min-w-0">
                              <Avatar className="h-5 w-5 flex-shrink-0">
                                <AvatarImage src={ex.requester?.avatar_url ?? undefined} alt="" />
                                <AvatarFallback className="text-[10px] bg-background-subtle">
                                  {ex.requester?.full_name ? ex.requester.full_name.charAt(0).toUpperCase() : '?'}
                                </AvatarFallback>
                              </Avatar>
                              <div className="flex-1 min-w-0 flex items-center gap-2">
                                <span className="text-sm font-medium text-foreground truncate">{ex.requester?.full_name || '\u2014'}</span>
                                {ex.requester?.role && (
                                  <RoleBadge
                                    role={ex.requester.role}
                                    roleDisplayName={ex.requester.role_display_name}
                                    roleColor={ex.requester.role_color}
                                  />
                                )}
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-sm text-foreground">
                            {ex.policy_type === 'pull_request' ? 'Pull Request' : ex.policy_type === 'compliance' ? 'Compliance' : 'Full'}
                          </td>
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
                            {ex.status === 'revoked' && (
                              <Badge variant="destructive" className="gap-1"><Ban className="h-3 w-3" /> Revoked</Badge>
                            )}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              {(ex.status === 'accepted' || ex.status === 'rejected' || ex.status === 'revoked') && ex.base_policy_code && ex.requested_policy_code && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-7 text-xs opacity-0 group-hover:opacity-100 transition-opacity"
                                  onClick={() => setViewingExceptionId(ex.id)}
                                >
                                  <Eye className="h-3.5 w-3.5 mr-1" />
                                  View
                                </Button>
                              )}
                              {ex.status === 'pending' && canReviewExceptions && (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => setReviewingExceptionId(ex.id)}
                                >
                                  Review
                                </Button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* View Exception Sidebar */}
        {viewingExceptionId && (() => {
          const ex = exceptions.find((e) => e.id === viewingExceptionId);
          if (!ex?.base_policy_code || !ex?.requested_policy_code) return null;
          return (
            <PolicyExceptionSidebar
              key={viewingExceptionId}
              mode="view"
              baseCode={ex.base_policy_code}
              requestedCode={ex.requested_policy_code}
              projectName={ex.project_name ?? 'Project'}
              requester={ex.requester}
              reason={ex.reason}
              status={ex.status}
              onRevoke={ex.status === 'accepted' && id && canReviewExceptions ? async () => {
                try {
                  await api.revokePolicyException(id, ex.id);
                  toast({ title: 'Exception revoked', description: 'The project will now use the organization policy.' });
                  setViewingExceptionId(null);
                  await loadExceptions();
                } catch (e: any) {
                  const msg = e?.message?.toLowerCase().includes('already') ? 'This exception was already revoked.' : (e.message || 'Failed to revoke exception');
                  toast({ title: 'Error', description: msg, variant: 'destructive' });
                  setViewingExceptionId(null);
                  await loadExceptions();
                }
              } : undefined}
              onClose={() => setViewingExceptionId(null)}
            />
          );
        })()}

        {/* Review Exception Sidebar */}
        {reviewingException && reviewingException.status === 'pending' && id && (
          <PolicyExceptionSidebar
            mode="review"
            baseCode={reviewingException.base_policy_code ?? ''}
            requestedCode={reviewingException.requested_policy_code ?? ''}
            projectName={reviewingException.project_name ?? 'Project'}
            requester={reviewingException.requester}
            reason={reviewingException.reason}
            onAccept={async () => {
              try {
                await api.reviewPolicyException(id, reviewingException.id, 'accepted');
                toast({ title: 'Exception accepted' });
                setReviewingExceptionId(null);
                await loadExceptions();
              } catch (e: any) {
                const msg = e?.message?.toLowerCase().includes('already') ? 'This exception was already reviewed by someone else.' : (e.message || 'Failed to accept exception');
                toast({ title: 'Error', description: msg, variant: 'destructive' });
                setReviewingExceptionId(null);
                await loadExceptions();
              }
            }}
            onReject={async () => {
              try {
                await api.reviewPolicyException(id, reviewingException.id, 'rejected');
                toast({ title: 'Exception rejected' });
                setReviewingExceptionId(null);
                await loadExceptions();
              } catch (e: any) {
                const msg = e?.message?.toLowerCase().includes('already') ? 'This exception was already reviewed by someone else.' : (e.message || 'Failed to reject exception');
                toast({ title: 'Error', description: msg, variant: 'destructive' });
                setReviewingExceptionId(null);
                await loadExceptions();
              }
            }}
            onClose={() => setReviewingExceptionId(null)}
          />
        )}
        </main>

        {showAI && id && createPortal(
          <div className="fixed inset-0 z-50">
            <div
              className={cn(
                'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
                aiPanelVisible ? 'opacity-100' : 'opacity-0'
              )}
              onClick={closeAIPanel}
            />

            <div
              className={cn(
                'fixed right-4 top-4 bottom-4 w-full max-w-[40rem] bg-background-card-header border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
                aiPanelVisible ? 'translate-x-0' : 'translate-x-full'
              )}
              onClick={(e) => e.stopPropagation()}
            >
              <PolicyAIAssistant
                organizationId={id}
                complianceBody={complianceBody}
                pullRequestBody={pullRequestBody}
                onUpdateCompliance={setComplianceBody}
                onUpdatePullRequest={setPullRequestBody}
                onClose={closeAIPanel}
                variant="edge"
              />
            </div>
          </div>,
          document.body
        )}
      </div>

      <Toaster position="bottom-right" />
    </>
  );
}
