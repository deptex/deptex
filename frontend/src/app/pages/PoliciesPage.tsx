import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useParams, useOutletContext, useNavigate } from 'react-router-dom';
import { cn } from '../../lib/utils';
import { BookOpen, Sparkles, Loader2, Check, X, Clock, Eye, Ban, FileQuestion } from 'lucide-react';
import { api, Organization, RolePermissions, ProjectPolicyException, OrganizationPolicyChange } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { PolicyCodeEditor } from '../../components/PolicyCodeEditor';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '../../components/ui/avatar';
import { Toaster } from '../../components/ui/toaster';
import { PolicyAIAssistant } from '../../components/PolicyAIAssistant';
import { PolicyExceptionSidebar } from '../../components/PolicyExceptionSidebar';
import { PolicyDiffViewer } from '../../components/PolicyDiffViewer';

/** Extract the body of a named function from full code. */
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

/** Wrap packagePolicy body into full function. */
function wrapPackagePolicyBody(body: string): string {
  const lines = body.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
  return `function packagePolicy(context) {\n${lines.join('\n')}\n}`;
}

/** Wrap pullRequestCheck body into full function. */
function wrapPrCheckBody(body: string): string {
  const lines = body.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
  return `function pullRequestCheck(context) {\n${lines.join('\n')}\n}`;
}

const DEFAULT_PACKAGE_POLICY_BODY = 'return { allowed: true, reasons: [] };';
const DEFAULT_PR_CHECK_BODY = 'return { passed: true, violations: [] };';

/** Legacy helpers for backward-compat with old policy_code format. */
function assemblePolicyCode(pullRequestBody: string, complianceBody: string): string {
  const prLines = pullRequestBody.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
  const compLines = complianceBody.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
  return `function pullRequestCheck(context) {\n${prLines.join('\n')}\n}\n\nfunction projectCompliance(context) {\n${compLines.join('\n')}\n}`;
}

function parsePolicyCode(code: string): { pullRequestBody: string; complianceBody: string } {
  const prBody = extractFunctionBody(code, 'pullRequestCheck');
  const compBody = extractFunctionBody(code, 'projectCompliance');
  return {
    pullRequestBody: prBody ?? 'return { passed: true };',
    complianceBody: compBody ?? 'return { compliant: true };',
  };
}

function formatRelativeTime(dateStr: string): string {
  const d = new Date(dateStr);
  const now = new Date();
  const sec = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (sec < 60) return 'just now';
  if (sec < 3600) return `${Math.floor(sec / 60)} minutes ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} hours ago`;
  if (sec < 604800) return `${Math.floor(sec / 86400)} days ago`;
  return d.toLocaleDateString();
}


type SubTab = 'package_policy' | 'pr_check' | 'change_history';

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

  const [loading, setLoading] = useState(true);
  const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(null);
  const [permissionsLoaded, setPermissionsLoaded] = useState(false);
  const [subTab, setSubTab] = useState<SubTab>('package_policy');

  // Split policy code state
  const [packagePolicyCode, setPackagePolicyCode] = useState('');
  const [packagePolicyOriginal, setPackagePolicyOriginal] = useState('');
  const [prCheckCode, setPrCheckCode] = useState('');
  const [prCheckOriginal, setPrCheckOriginal] = useState('');
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any>(null);

  // AI sidebar
  const [showAI, setShowAI] = useState(false);
  const [aiPanelVisible, setAiPanelVisible] = useState(false);
  const aiCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Change history
  const [changes, setChanges] = useState<OrganizationPolicyChange[]>([]);
  const [loadingChanges, setLoadingChanges] = useState(false);
  const [selectedChange, setSelectedChange] = useState<OrganizationPolicyChange | null>(null);
  const [changeDetailVisible, setChangeDetailVisible] = useState(false);
  const changeDetailCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Legacy exceptions (backward compat)
  const [exceptions, setExceptions] = useState<ProjectPolicyException[]>([]);
  const [exceptionsLoading, setExceptionsLoading] = useState(false);
  const [reviewingExceptionId, setReviewingExceptionId] = useState<string | null>(null);
  const [viewingExceptionId, setViewingExceptionId] = useState<string | null>(null);

  const loadPolicyCode = useCallback(async () => {
    if (!id) return;
    try {
      setLoading(true);
      const data = await api.getOrganizationPolicyCode(id);
      const pkgFull = data.package_policy?.package_policy_code || '';
      const prFull = data.pr_check?.pr_check_code || '';
      const pkgBody = extractFunctionBody(pkgFull, 'packagePolicy') ?? DEFAULT_PACKAGE_POLICY_BODY;
      const prBody = extractFunctionBody(prFull, 'pullRequestCheck') ?? DEFAULT_PR_CHECK_BODY;
      setPackagePolicyCode(pkgBody);
      setPackagePolicyOriginal(pkgBody);
      setPrCheckCode(prBody);
      setPrCheckOriginal(prBody);
    } catch (error: any) {
      console.error('Failed to load policy code:', error);
      toast({ title: 'Error', description: error.message || 'Failed to load policy code', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [id, toast]);

  const loadExceptions = useCallback(async () => {
    if (!id) return;
    try {
      setExceptionsLoading(true);
      const list = await api.getOrganizationPolicyExceptions(id);
      setExceptions(list);
    } catch (e: any) {
      console.error('Failed to load exceptions:', e);
    } finally {
      setExceptionsLoading(false);
    }
  }, [id]);

  useEffect(() => {
    if (id) {
      loadPolicyCode();
      loadExceptions();
    }
  }, [id, loadPolicyCode, loadExceptions]);

  useEffect(() => {
    if (subTab === 'change_history' && id) {
      setLoadingChanges(true);
      Promise.all([
        api.getOrganizationPolicyChanges(id, 'package_policy'),
        api.getOrganizationPolicyChanges(id, 'pr_check'),
      ])
        .then(([pkgChanges, prChanges]) => {
          const all = [...pkgChanges, ...prChanges].sort(
            (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
          );
          setChanges(all);
        })
        .catch(console.error)
        .finally(() => setLoadingChanges(false));
    }
  }, [subTab, id]);

  // AI sidebar animation
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
    if (changeDetailCloseTimeoutRef.current) clearTimeout(changeDetailCloseTimeoutRef.current);
  }, []);

  // Change detail sidebar open/close
  useEffect(() => {
    if (selectedChange) {
      setChangeDetailVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setChangeDetailVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setChangeDetailVisible(false);
    }
  }, [selectedChange]);

  const closeChangeDetail = useCallback(() => {
    setChangeDetailVisible(false);
    if (changeDetailCloseTimeoutRef.current) clearTimeout(changeDetailCloseTimeoutRef.current);
    changeDetailCloseTimeoutRef.current = setTimeout(() => {
      changeDetailCloseTimeoutRef.current = null;
      setSelectedChange(null);
    }, 150);
  }, []);

  const closeAIPanel = useCallback(() => {
    setAiPanelVisible(false);
    if (aiCloseTimeoutRef.current) clearTimeout(aiCloseTimeoutRef.current);
    aiCloseTimeoutRef.current = setTimeout(() => {
      aiCloseTimeoutRef.current = null;
      setShowAI(false);
    }, 150);
  }, []);

  // Permissions
  useEffect(() => {
    const loadPermissions = async () => {
      if (!id || !organization?.role) {
        setPermissionsLoaded(true);
        return;
      }
      if (organization?.permissions) {
        setUserPermissions(organization.permissions);
        setPermissionsLoaded(true);
        return;
      }
      try {
        const roles = await api.getOrganizationRoles(id);
        const userRole = roles.find((r: any) => r.name === organization.role);
        if (userRole?.permissions) {
          setUserPermissions(userRole.permissions);
        }
      } catch (error) {
        console.error('Failed to load permissions:', error);
      } finally {
        setPermissionsLoaded(true);
      }
    };
    loadPermissions();
  }, [id, organization?.role]);

  const hasManageCompliance =
    userPermissions?.manage_compliance === true ||
    organization?.role === 'owner' ||
    organization?.role === 'admin';

  const packagePolicyDirty = packagePolicyCode !== packagePolicyOriginal;
  const prCheckDirty = prCheckCode !== prCheckOriginal;

  const handleSave = async (codeType: 'package_policy' | 'pr_check') => {
    if (!id) return;
    const body = codeType === 'package_policy' ? packagePolicyCode : prCheckCode;
    const code = codeType === 'package_policy' ? wrapPackagePolicyBody(body) : wrapPrCheckBody(body);

    setSaving(true);
    setValidating(true);
    setValidationResult(null);
    try {
      const validation = await api.validatePolicyCode(id, code, codeType);
      setValidationResult(validation);
      setValidating(false);

      if (!validation.allPassed) {
        toast({
          title: 'Validation failed',
          description: validation.syntaxError || validation.shapeError || validation.fetchResilienceError || 'Validation failed',
          variant: 'destructive',
        });
        return;
      }

      await api.updateOrganizationPolicyCode(id, codeType, code, `Updated ${codeType.replace('_', ' ')}`);

      if (codeType === 'package_policy') {
        setPackagePolicyOriginal(body);
      } else {
        setPrCheckOriginal(body);
      }

      toast({ title: 'Policy saved', description: `${codeType === 'package_policy' ? 'Package policy' : 'PR check'} updated successfully.` });
    } catch (error: any) {
      toast({ title: 'Error', description: error.message || 'Failed to save policy', variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const codeTypeBadge = (codeType: string) => {
    const labels: Record<string, string> = {
      package_policy: 'Package Policy',
      project_status: 'Status Code',
      pr_check: 'PR Check',
    };
    return (
      <Badge variant="outline" className="text-xs">
        {labels[codeType] || codeType}
      </Badge>
    );
  };

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

  const subTabs: { id: SubTab; label: string }[] = [
    { id: 'package_policy', label: 'Package Policy' },
    { id: 'pr_check', label: 'Pull Request Check' },
    { id: 'change_history', label: 'Change History' },
  ];

  return (
    <main className={`${isSettingsSubpage ? '' : 'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8'} py-8`}>
      {!isSettingsSubpage && <Toaster />}

      {/* Header */}
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
            <Button variant="outline" size="sm" className="text-xs" onClick={() => setShowAI(true)}>
              <Sparkles className="h-3.5 w-3.5 mr-1.5" />
              AI Assistant
            </Button>
            <Button variant="outline" size="sm" className="text-xs" onClick={() => window.open('/docs/policies', '_blank')}>
              <BookOpen className="h-3.5 w-3.5 mr-1.5" />
              Docs
            </Button>
          </div>
        </div>

        {/* Sub-tabs */}
        <div className="flex items-center border-b border-border pb-px">
          <div className="flex items-center gap-6">
            {subTabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSubTab(tab.id)}
                className={`pb-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
                  subTab === tab.id
                    ? 'text-foreground border-foreground'
                    : 'text-foreground-secondary border-transparent hover:text-foreground'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="pt-4">
          {/* Package Policy editor: header with function title + Save, body-only in editor */}
          {subTab === 'package_policy' && (
            <div className="space-y-4">
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
                  <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">packagePolicy(context)</span>
                  {hasManageCompliance && (
                    <div className="flex items-center gap-1.5">
                      {packagePolicyDirty && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setPackagePolicyCode(packagePolicyOriginal)}
                          disabled={saving}
                          className="h-7 min-h-7 px-2 py-0 text-xs"
                        >
                          Discard
                        </Button>
                      )}
                      <Button
                        size="sm"
                        onClick={() => handleSave('package_policy')}
                        disabled={!packagePolicyDirty || saving}
                        className="h-7 min-h-7 px-2 py-0 text-xs"
                      >
                        {saving && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                        Save
                      </Button>
                    </div>
                  )}
                </div>
                <div className="bg-background-card">
                  <PolicyCodeEditor
                    value={packagePolicyCode}
                    onChange={(val) => setPackagePolicyCode(val || '')}
                    readOnly={!hasManageCompliance}
                    fitContent
                  />
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Runs per dependency. Determines whether each package is allowed based on license, score, tier, and other metadata.
              </p>
              {validationResult && subTab === 'package_policy' && (
                <ValidationResultDisplay result={validationResult} />
              )}
            </div>
          )}

          {/* PR Check editor: header with function title + Save, body-only in editor */}
          {subTab === 'pr_check' && (
            <div className="space-y-4">
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
                  <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">pullRequestCheck(context)</span>
                  {hasManageCompliance && (
                    <div className="flex items-center gap-1.5">
                      {prCheckDirty && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setPrCheckCode(prCheckOriginal)}
                          disabled={saving}
                          className="h-7 min-h-7 px-2 py-0 text-xs"
                        >
                          Discard
                        </Button>
                      )}
                      <Button
                        size="sm"
                        onClick={() => handleSave('pr_check')}
                        disabled={!prCheckDirty || saving}
                        className="h-7 min-h-7 px-2 py-0 text-xs"
                      >
                        {saving && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                        Save
                      </Button>
                    </div>
                  )}
                </div>
                <div className="bg-background-card">
                  <PolicyCodeEditor
                    value={prCheckCode}
                    onChange={(val) => setPrCheckCode(val || '')}
                    readOnly={!hasManageCompliance}
                    fitContent
                  />
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Runs on pull requests that modify lockfiles. Determines whether the PR should pass or be blocked.
              </p>
              {validationResult && subTab === 'pr_check' && (
                <ValidationResultDisplay result={validationResult} />
              )}
            </div>
          )}

          {/* Change History – table (matches Members table style) */}
          {subTab === 'change_history' && (
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              {loadingChanges ? (
                <table className="w-full">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Message</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[140px]">Type</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Changed by</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[120px]">Date</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {[1, 2, 3].map((i) => (
                      <tr key={i} className="animate-pulse">
                        <td className="px-4 py-3">
                          <div className="h-4 bg-muted rounded w-48" />
                        </td>
                        <td className="px-4 py-3">
                          <div className="h-5 bg-muted rounded w-24" />
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-6 w-6 rounded-full bg-muted flex-shrink-0" />
                            <div className="h-4 bg-muted rounded w-24" />
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="h-4 bg-muted rounded w-16" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : changes.length === 0 ? (
                <div className="text-sm text-muted-foreground text-center py-12 px-4">
                  No changes recorded yet.
                </div>
              ) : (
                <table className="w-full">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Message</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[140px]">Type</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Changed by</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[120px]">Date</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {changes.map((change) => (
                      <tr
                        key={change.id}
                        onClick={() => setSelectedChange(change)}
                        className="hover:bg-table-hover transition-colors cursor-pointer"
                      >
                        <td className="px-4 py-3 text-sm text-foreground truncate max-w-[320px]">
                          {change.message}
                        </td>
                        <td className="px-4 py-3">{codeTypeBadge(change.code_type)}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <Avatar className="h-6 w-6 flex-shrink-0">
                              <AvatarImage src={change.author_avatar_url ?? undefined} alt="" />
                              <AvatarFallback className="text-[10px] bg-muted text-muted-foreground">
                                {(change.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                              </AvatarFallback>
                            </Avatar>
                            <span className="text-sm text-foreground truncate">
                              {change.author_display_name || 'Unknown'}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">
                          {formatRelativeTime(change.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}

      {/* Change detail sidebar – diff view */}
      {selectedChange && createPortal(
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              changeDetailVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeChangeDetail}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[560px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              changeDetailVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Policy change</h2>
              <p className="text-sm text-muted-foreground mt-1 truncate">{selectedChange.message}</p>
              <div className="flex items-center gap-2 mt-2">
                {codeTypeBadge(selectedChange.code_type)}
                <span className="text-xs text-muted-foreground">{formatRelativeTime(selectedChange.created_at)}</span>
              </div>
              <div className="flex items-center gap-2 mt-3">
                <Avatar className="h-6 w-6 flex-shrink-0">
                  <AvatarImage src={selectedChange.author_avatar_url ?? undefined} alt="" />
                  <AvatarFallback className="text-[10px] bg-muted text-muted-foreground">
                    {(selectedChange.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                  </AvatarFallback>
                </Avatar>
                <span className="text-sm text-muted-foreground">Changed by {selectedChange.author_display_name || 'Unknown'}</span>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto min-h-0 px-4 pb-4">
              <div className="rounded-lg overflow-hidden border border-border">
                <PolicyDiffViewer
                  baseCode={selectedChange.previous_code}
                  requestedCode={selectedChange.new_code}
                  minHeight="200px"
                  className="text-[11px]"
                />
              </div>
            </div>
            <div className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header flex items-center justify-end">
              <Button variant="outline" size="sm" onClick={closeChangeDetail}>
                Close
              </Button>
            </div>
          </div>
        </div>,
        document.body,
      )}

      {/* AI Assistant */}
      {showAI && createPortal(
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
              'fixed right-4 top-4 bottom-4 w-full max-w-[680px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              aiPanelVisible ? 'translate-x-0' : 'translate-x-full'
            )}
          >
            <PolicyAIAssistant
              variant="edge"
              organizationId={id || ''}
              complianceBody={packagePolicyCode}
              pullRequestBody={prCheckCode}
              onUpdateCompliance={(code: string) => setPackagePolicyCode(code)}
              onUpdatePullRequest={(code: string) => setPrCheckCode(code)}
              onClose={closeAIPanel}
            />
          </div>
        </div>,
        document.body,
      )}
    </main>
  );
}

function ValidationResultDisplay({ result }: { result: any }) {
  const items = [
    { label: 'Syntax', pass: result.syntaxPass, error: result.syntaxError },
    { label: 'Shape', pass: result.shapePass, error: result.shapeError },
    { label: 'Fetch resilience', pass: result.fetchResiliencePass, error: result.fetchResilienceError },
  ];

  return (
    <div className="border border-border rounded-lg p-3 space-y-1.5 bg-muted/30">
      {items.map((item) => (
        <div key={item.label} className="flex items-start gap-2 text-sm">
          {item.pass ? (
            <Check className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
          ) : (
            <X className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" />
          )}
          <span>
            <span className="font-medium">{item.label}:</span>{' '}
            {item.pass ? (
              <span className="text-green-400">Passed</span>
            ) : (
              <span className="text-red-400">{item.error || 'Failed'}</span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}
