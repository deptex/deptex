import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useParams, useOutletContext, useNavigate, Link } from 'react-router-dom';
import { cn } from '../../lib/utils';
import { BookOpen, Loader2, X, Check, Clock, Eye, Ban, FileQuestion, Info } from 'lucide-react';
import { api, Organization, RolePermissions, ProjectPolicyException, OrganizationPolicyChange, ProjectPolicyChangeRequest } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { PolicyCodeEditor } from '../../components/PolicyCodeEditor';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Badge } from '../../components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '../../components/ui/avatar';
import { Toaster } from '../../components/ui/toaster';
import { PolicyAIAssistant } from '../../components/PolicyAIAssistant';
import { PolicyExceptionSidebar } from '../../components/PolicyExceptionSidebar';
import { getDiffLineCounts } from '../../components/PolicyDiffViewer';
import { PolicyDiffCodeEditor } from '../../components/PolicyDiffCodeEditor';
import { CODE_BLOCK_BG } from '../../components/policy-monaco-setup';
import { JsLangBadge } from '../../components/JsLangBadge';
import { Card, CardContent } from '../../components/ui/card';

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

/** Skeleton for the policy code editor card (header + code lines). */
function PolicyEditorSkeleton() {
  const pulse = 'animate-pulse';
  return (
    <div className="rounded-lg border border-border bg-background-card overflow-hidden">
      <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
        <div className={`h-3.5 w-40 bg-muted rounded ${pulse}`} />
      </div>
      <div
        className="px-4 py-3 font-mono text-[13px] leading-6"
        style={{ minHeight: '180px', backgroundColor: CODE_BLOCK_BG }}
      >
        <div className="space-y-1.5">
          <div className="h-3 bg-white/10 rounded w-[70%] animate-pulse" />
          <div className="h-3 bg-white/10 rounded w-[55%] ml-4 animate-pulse" />
          <div className="h-3 bg-white/10 rounded w-[80%] ml-4 animate-pulse" />
          <div className="h-3 bg-white/10 rounded w-[40%] ml-8 animate-pulse" />
          <div className="h-3 bg-white/10 rounded w-[60%] ml-4 animate-pulse" />
          <div className="h-3 bg-white/10 rounded w-[30%] animate-pulse" />
          <div className="h-3" />
          <div className="h-3 bg-white/10 rounded w-[50%] ml-4 animate-pulse" />
          <div className="h-3 bg-white/10 rounded w-[45%] ml-4 animate-pulse" />
        </div>
      </div>
    </div>
  );
}

type SubTab = 'package_policy' | 'pr_check' | 'change_history' | 'project_requests';

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

  // Split policy code state (Package Policy + PR Check only; Project Status lives in Statuses)
  const [packagePolicyCode, setPackagePolicyCode] = useState('');
  const [packagePolicyOriginal, setPackagePolicyOriginal] = useState('');
  const [prCheckCode, setPrCheckCode] = useState('');
  const [prCheckOriginal, setPrCheckOriginal] = useState('');
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any>(null);

  // AI sidebar – keep mounted once opened so conversation persists when "closed"; reset when user navigates away (page unmounts)
  const [showAI, setShowAI] = useState(false);
  const [everOpenedAI, setEverOpenedAI] = useState(false);
  const [aiPanelVisible, setAiPanelVisible] = useState(false);
  const aiCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const aiAssistantCloseRef = useRef<(() => void) | null>(null);

  // Commit sidebar (open after validation passes)
  const [commitSidebarCodeType, setCommitSidebarCodeType] = useState<'package_policy' | 'pr_check' | null>(null);
  const [commitMessage, setCommitMessage] = useState('');
  const [commitSidebarVisible, setCommitSidebarVisible] = useState(false);
  const [committing, setCommitting] = useState(false);
  const commitSidebarCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const validationCardRef = useRef<HTMLDivElement>(null);

  // Change history
  const [changes, setChanges] = useState<OrganizationPolicyChange[]>([]);
  const [loadingChanges, setLoadingChanges] = useState(false);
  const [selectedChange, setSelectedChange] = useState<OrganizationPolicyChange | null>(null);
  const [changeDetailVisible, setChangeDetailVisible] = useState(false);
  const changeDetailCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const changeHistoryLoadedRef = useRef(false);
  const projectRequestsLoadedRef = useRef(false);

  // Project policy change requests (pending requests from projects)
  const [projectRequests, setProjectRequests] = useState<ProjectPolicyChangeRequest[]>([]);
  const [loadingProjectRequests, setLoadingProjectRequests] = useState(false);
  const [reviewingRequestId, setReviewingRequestId] = useState<string | null>(null);
  const [selectedRequest, setSelectedRequest] = useState<ProjectPolicyChangeRequest | null>(null);
  const [requestDetailVisible, setRequestDetailVisible] = useState(false);
  const requestDetailCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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

  // Reset cache refs when organization changes so we refetch on first visit to each tab
  useEffect(() => {
    changeHistoryLoadedRef.current = false;
    projectRequestsLoadedRef.current = false;
  }, [id]);

  useEffect(() => {
    if (subTab === 'change_history' && id && !changeHistoryLoadedRef.current) {
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
          changeHistoryLoadedRef.current = true;
        })
        .catch(console.error)
        .finally(() => setLoadingChanges(false));
    }
  }, [subTab, id]);

  useEffect(() => {
    if (subTab === 'project_requests' && id && !projectRequestsLoadedRef.current) {
      setLoadingProjectRequests(true);
      api.getOrganizationPolicyChangeRequests(id)
        .then((list) => {
          setProjectRequests(list);
          projectRequestsLoadedRef.current = true;
        })
        .catch((e) => {
          console.error(e);
          toast({ title: 'Error', description: e?.message || 'Failed to load change requests', variant: 'destructive' });
        })
        .finally(() => setLoadingProjectRequests(false));
    }
  }, [subTab, id, toast]);

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
    if (requestDetailCloseTimeoutRef.current) clearTimeout(requestDetailCloseTimeoutRef.current);
    if (commitSidebarCloseTimeoutRef.current) clearTimeout(commitSidebarCloseTimeoutRef.current);
  }, []);

  // Commit sidebar open/close animation
  useEffect(() => {
    if (commitSidebarCodeType) {
      setCommitSidebarVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setCommitSidebarVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setCommitSidebarVisible(false);
    }
  }, [commitSidebarCodeType]);

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

  useEffect(() => {
    if (selectedRequest) {
      setRequestDetailVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setRequestDetailVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setRequestDetailVisible(false);
    }
  }, [selectedRequest]);

  const closeChangeDetail = useCallback(() => {
    setChangeDetailVisible(false);
    if (changeDetailCloseTimeoutRef.current) clearTimeout(changeDetailCloseTimeoutRef.current);
    changeDetailCloseTimeoutRef.current = setTimeout(() => {
      changeDetailCloseTimeoutRef.current = null;
      setSelectedChange(null);
    }, 150);
  }, []);

  const closeRequestDetail = useCallback(() => {
    setRequestDetailVisible(false);
    if (requestDetailCloseTimeoutRef.current) clearTimeout(requestDetailCloseTimeoutRef.current);
    requestDetailCloseTimeoutRef.current = setTimeout(() => {
      requestDetailCloseTimeoutRef.current = null;
      setSelectedRequest(null);
    }, 150);
  }, []);

  const handleReviewRequest = useCallback(async (changeId: string, action: 'accept' | 'reject') => {
    if (!id) return;
    setReviewingRequestId(changeId);
    try {
      await api.reviewProjectPolicyChange(id, changeId, action);
      toast({ title: action === 'accept' ? 'Request accepted' : 'Request rejected' });
      setProjectRequests((prev) => prev.filter((r) => r.id !== changeId));
      setSelectedRequest(null);
      setRequestDetailVisible(false);
    } catch (e: any) {
      toast({ title: 'Error', description: e?.message || 'Failed to update request', variant: 'destructive' });
    } finally {
      setReviewingRequestId(null);
    }
  }, [id, toast]);

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

  /** Map policy API validation result to NotificationRulesSection-style checks for the validation-failed card. */
  type ValidationCheckItem = { name: string; pass: boolean; error?: string };
  const validationChecksFromResult: ValidationCheckItem[] | null = validationResult
    ? [
        { name: 'syntax', pass: validationResult.syntaxPass, error: validationResult.syntaxError },
        { name: 'shape', pass: validationResult.shapePass, error: validationResult.shapeError },
        { name: 'fetch_resilience', pass: validationResult.fetchResiliencePass, error: validationResult.fetchResilienceError },
      ]
    : null;
  const showValidationFailedCard =
    validationResult && validationChecksFromResult && validationChecksFromResult.some((c) => !c.pass);

  const closeCommitSidebar = useCallback(() => {
    setCommitSidebarVisible(false);
    if (commitSidebarCloseTimeoutRef.current) clearTimeout(commitSidebarCloseTimeoutRef.current);
    commitSidebarCloseTimeoutRef.current = setTimeout(() => {
      commitSidebarCloseTimeoutRef.current = null;
      setCommitSidebarCodeType(null);
      setCommitMessage('');
    }, 150);
  }, []);

  /** On Commit click: validate in background; if pass open sidebar, if fail show validation card. */
  const handleCommitClick = async (codeType: 'package_policy' | 'pr_check') => {
    if (!id) return;
    const body = codeType === 'package_policy' ? packagePolicyCode : prCheckCode;
    const code = codeType === 'package_policy' ? wrapPackagePolicyBody(body) : wrapPrCheckBody(body);

    setValidating(true);
    setValidationResult(null);
    try {
      const validation = await api.validatePolicyCode(id, code, codeType);
      setValidationResult(validation);

      if (validation.allPassed) {
        setValidationResult(null);
        setCommitMessage('');
        setCommitSidebarCodeType(codeType);
      } else {
        validationCardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    } catch (error: any) {
      toast({ title: 'Error', description: error.message || 'Validation failed', variant: 'destructive' });
    } finally {
      setValidating(false);
    }
  };

  /** Called from commit sidebar: save with message (validation already passed). */
  const handleCommitSubmit = async () => {
    if (!id || !commitSidebarCodeType) return;
    const body = commitSidebarCodeType === 'package_policy' ? packagePolicyCode : prCheckCode;
    const code = commitSidebarCodeType === 'package_policy' ? wrapPackagePolicyBody(body) : wrapPrCheckBody(body);

    setCommitting(true);
    try {
      await api.updateOrganizationPolicyCode(id, commitSidebarCodeType, code, commitMessage.trim() || undefined);
      if (commitSidebarCodeType === 'package_policy') {
        setPackagePolicyOriginal(body);
      } else {
        setPrCheckOriginal(body);
      }
      closeCommitSidebar();
      if (id) {
        const [pkgChanges, prChanges] = await Promise.all([
          api.getOrganizationPolicyChanges(id, 'package_policy'),
          api.getOrganizationPolicyChanges(id, 'pr_check'),
        ]);
        setChanges(
          [...pkgChanges, ...prChanges].sort(
            (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
          ),
        );
      }
      const label = commitSidebarCodeType === 'package_policy' ? 'Package policy' : 'PR check';
      toast({
        title: 'Policy saved',
        description: `${label} updated successfully.`,
      });
    } catch (error: any) {
      toast({ title: 'Error', description: error.message || 'Failed to save policy', variant: 'destructive' });
    } finally {
      setCommitting(false);
    }
  };

  const codeTypeLabel = (codeType: string): string => {
    const labels: Record<string, string> = {
      package_policy: 'Package Policy',
      project_status: 'Status Code',
      pr_check: 'PR Check',
    };
    return labels[codeType] || codeType;
  };

  const codeTypeBadge = (codeType: string) => (
    <Badge variant="outline" className="text-xs">
      {codeTypeLabel(codeType)}
    </Badge>
  );

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
    { id: 'project_requests', label: 'Change requests' },
  ];

  return (
    <main className={`${isSettingsSubpage ? '' : 'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8'} py-8`}>
      {!isSettingsSubpage && <Toaster />}

      {/* Header */}
      <div className="sticky top-0 z-10 bg-background pb-2">
        <div className="mb-6 flex items-start justify-between">
          <div className="flex items-center gap-2">
            {isSettingsSubpage ? (
              <h2 className="text-2xl font-bold text-foreground">Policies</h2>
            ) : (
              <h1 className="text-3xl font-bold text-foreground">Policies</h1>
            )}
            <Link to="/docs/policies" target="_blank" rel="noopener noreferrer" className="shrink-0 text-foreground-secondary hover:text-foreground" aria-label="Policies docs">
              <BookOpen className="h-4 w-4" />
            </Link>
          </div>
          <Button variant="outline" size="sm" className="text-xs" onClick={() => { setEverOpenedAI(true); setShowAI(true); }}>
            AI Assistant
          </Button>
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
      <div className="pt-4">
        {loading ? (
          (subTab === 'package_policy' || subTab === 'pr_check') ? (
            <PolicyEditorSkeleton />
          ) : subTab === 'change_history' ? (
            /* Change history has its own loading state below */
            null
          ) : null
        ) : (
          <>
            {/* Package Policy editor: header with function title; Clear/Commit on code block */}
            {subTab === 'package_policy' && (
              <div className="space-y-4">
                <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                  <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center gap-2">
                    <JsLangBadge className="text-xs" />
                    <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">packagePolicy</span>
                  </div>
                  <div className="bg-background-card relative">
                    {hasManageCompliance && packagePolicyDirty && (
                      <div className="absolute top-2 right-2 z-10 flex items-center gap-1.5">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => { setPackagePolicyCode(packagePolicyOriginal); setValidationResult(null); }}
                          disabled={validating}
                          className="h-7 px-2 text-[11px] font-medium backdrop-blur border-border bg-background-card/95 hover:bg-background-card shadow-sm"
                        >
                          Clear changes
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => handleCommitClick('package_policy')}
                          disabled={validating}
                          className="h-7 px-2 text-[11px] font-medium bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 shadow-sm"
                        >
                          {validating && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                          Commit changes
                        </Button>
                      </div>
                    )}
                    <PolicyCodeEditor
                      value={packagePolicyCode}
                      onChange={(val) => { setPackagePolicyCode(val || ''); setValidationResult(null); }}
                      readOnly={!hasManageCompliance}
                      fitContent
                    />
                  </div>
                </div>
                {showValidationFailedCard && subTab === 'package_policy' && validationChecksFromResult && (
                  <div
                    ref={validationCardRef}
                    className="mt-3 p-4 rounded-lg border border-destructive/30 bg-destructive/10"
                  >
                    <div className="flex items-center gap-3">
                      <div className="rounded-md bg-destructive/20 border border-destructive/40 w-9 h-9 flex items-center justify-center flex-shrink-0 text-destructive">
                        <X className="h-4 w-4" />
                      </div>
                      <span className="text-base font-medium text-destructive">Validation failed</span>
                    </div>
                    <div className="mt-3 space-y-2 pl-12">
                      {validationChecksFromResult
                        .filter((c) => !c.pass)
                        .map((check, i) => (
                          <div key={i} className="text-sm">
                            <span className="font-medium text-destructive">
                              {check.name === 'syntax' ? 'Syntax' : check.name === 'shape' ? 'Return value' : check.name === 'fetch_resilience' ? 'Fetch handling' : check.name.replace(/_/g, ' ')} failed
                            </span>
                            {check.error && (
                              <p className="text-foreground-secondary mt-0.5">{check.error}</p>
                            )}
                          </div>
                        ))}
                    </div>
                  </div>
                )}
                <Card className="rounded-lg border border-border bg-background-card/80 mt-6">
                  <CardContent className="p-5 flex gap-3">
                    <Info className="h-4 w-4 text-foreground-muted flex-shrink-0 mt-0.5" />
                    <div className="min-w-0 space-y-2 text-sm text-foreground-secondary leading-relaxed">
                      <p>
                        Define your organization&apos;s package policies as code. This runs once per dependency — you get a single package in <code className="font-mono text-foreground/90">context.dependency</code> and <code className="font-mono text-foreground/90">context.tier</code>. Return <code className="font-mono text-foreground/90">&#123; allowed, reasons &#125;</code>. Available on the dependency: name, version, license, dependencyScore, openSsfScore, weeklyDownloads, lastPublishedAt, releasesLast12Months, slsaLevel.
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* PR Check editor: header with function title; Clear/Commit on code block */}
            {subTab === 'pr_check' && (
              <div className="space-y-4">
                <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                  <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center gap-2">
                    <JsLangBadge className="text-xs" />
                    <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">pullRequestCheck</span>
                  </div>
                  <div className="bg-background-card relative">
                    {hasManageCompliance && prCheckDirty && (
                      <div className="absolute top-2 right-2 z-10 flex items-center gap-1.5">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => { setPrCheckCode(prCheckOriginal); setValidationResult(null); }}
                          disabled={validating}
                          className="h-7 px-2 text-[11px] font-medium backdrop-blur border-border bg-background-card/95 hover:bg-background-card shadow-sm"
                        >
                          Clear changes
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => handleCommitClick('pr_check')}
                          disabled={validating}
                          className="h-7 px-2 text-[11px] font-medium bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 shadow-sm"
                        >
                          {validating && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                          Commit changes
                        </Button>
                      </div>
                    )}
                    <PolicyCodeEditor
                      value={prCheckCode}
                      onChange={(val) => { setPrCheckCode(val || ''); setValidationResult(null); }}
                      readOnly={!hasManageCompliance}
                      fitContent
                    />
                  </div>
                </div>
                {showValidationFailedCard && subTab === 'pr_check' && validationChecksFromResult && (
                  <div
                    ref={validationCardRef}
                    className="mt-3 p-4 rounded-lg border border-destructive/30 bg-destructive/10"
                  >
                    <div className="flex items-center gap-3">
                      <div className="rounded-md bg-destructive/20 border border-destructive/40 w-9 h-9 flex items-center justify-center flex-shrink-0 text-destructive">
                        <X className="h-4 w-4" />
                      </div>
                      <span className="text-base font-medium text-destructive">Validation failed</span>
                    </div>
                    <div className="mt-3 space-y-2 pl-12">
                      {validationChecksFromResult
                        .filter((c) => !c.pass)
                        .map((check, i) => (
                          <div key={i} className="text-sm">
                            <span className="font-medium text-destructive">
                              {check.name === 'syntax' ? 'Syntax' : check.name === 'shape' ? 'Return value' : check.name === 'fetch_resilience' ? 'Fetch handling' : check.name.replace(/_/g, ' ')} failed
                            </span>
                            {check.error && (
                              <p className="text-foreground-secondary mt-0.5">{check.error}</p>
                            )}
                          </div>
                        ))}
                    </div>
                  </div>
                )}
                <Card className="rounded-lg border border-border bg-background-card/80 mt-6">
                  <CardContent className="p-5 flex gap-3">
                    <Info className="h-4 w-4 text-foreground-muted flex-shrink-0 mt-0.5" />
                    <div className="min-w-0 space-y-2 text-sm text-foreground-secondary leading-relaxed">
                      <p>
                        Runs when a pull request changes lockfiles or manifests. You receive <code className="font-mono text-foreground/90">context.project</code>, <code className="font-mono text-foreground/90">context.added</code>, <code className="font-mono text-foreground/90">context.updated</code>, and <code className="font-mono text-foreground/90">context.removed</code> (arrays of dependencies). Return <code className="font-mono text-foreground/90">&#123; passed: boolean, violations: string[] &#125;</code> — <code className="font-mono text-foreground/90">passed: true</code> to allow the merge, <code className="font-mono text-foreground/90">passed: false</code> to block. Each item in added/updated has: name, version, license, policyResult, vulnerability counts (critical, high, medium, low), is_direct, openssf_score, and vulnerability details. Use this to block PRs that add disallowed licenses, high-risk vulns, or low-score packages.
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </>
        )}

        {/* Change History – message with +x -x on same line right of message, type below; date + avatar */}
        {subTab === 'change_history' && (
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              {loadingChanges ? (
                <table className="w-full">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Change</th>
                      <th className="text-right px-4 py-3 w-[120px]" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {[1, 2, 3].map((i) => (
                      <tr key={i} className="animate-pulse">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-4">
                            <div>
                              <div className="h-4 bg-muted rounded w-48" />
                              <div className="h-3 bg-muted rounded w-28 mt-1" />
                            </div>
                            <div className="h-4 bg-muted rounded w-12 flex-shrink-0" />
                          </div>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="inline-flex items-center gap-2 justify-end">
                            <div className="h-4 bg-muted rounded w-16" />
                            <div className="h-8 w-8 rounded-full bg-muted flex-shrink-0" />
                          </div>
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
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Change</th>
                      <th className="text-right px-4 py-3 w-[120px]" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {changes.map((change) => {
                      const { added, removed } = getDiffLineCounts(change.previous_code ?? '', change.new_code ?? '');
                      return (
                        <tr
                          key={change.id}
                          onClick={() => setSelectedChange(change)}
                          className="hover:bg-table-hover transition-colors cursor-pointer"
                        >
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-4 min-w-0">
                              <div className="min-w-0">
                                <p className={cn('text-sm truncate', change.message?.trim() ? 'text-foreground' : 'text-muted-foreground')}>
                                  {change.message?.trim() || '—'}
                                </p>
                                <p className="text-xs text-muted-foreground mt-0.5">
                                  {codeTypeLabel(change.code_type)}
                                </p>
                              </div>
                              {(added > 0 || removed > 0) && (
                                <span className="inline-flex items-center gap-1.5 text-xs font-mono flex-shrink-0">
                                  {added > 0 && <span className="text-emerald-600 dark:text-emerald-400">+{added}</span>}
                                  {removed > 0 && <span className="text-red-600 dark:text-red-400">-{removed}</span>}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3 text-right align-middle">
                            <div className="inline-flex items-center gap-2 justify-end" title={change.author_display_name || undefined}>
                              <span className="text-xs text-muted-foreground whitespace-nowrap">
                                {formatRelativeTime(change.created_at)}
                              </span>
                              <Avatar className="h-8 w-8 flex-shrink-0 ring-1 ring-border rounded-full">
                                <AvatarImage src={change.author_avatar_url ?? undefined} alt="" />
                                <AvatarFallback className="text-xs bg-muted text-muted-foreground">
                                  {(change.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                                </AvatarFallback>
                              </Avatar>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          )}

        {/* Change requests – pending policy change requests from projects (package + PR only; status in Statuses) */}
        {subTab === 'project_requests' && (
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <table className="w-full table-fixed">
              <colgroup>
                <col className="w-[180px]" />
                <col className="w-[140px]" />
                <col className="w-[180px]" />
                <col />
                <col className="w-[120px]" />
                <col className="w-[180px]" />
              </colgroup>
              <thead className="bg-background-card-header border-b border-border">
                <tr>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Type</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Requested by</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Message</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Date</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {loadingProjectRequests ? (
                  [1, 2, 3].map((i) => (
                    <tr key={i} className="animate-pulse">
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-32" /></td>
                      <td className="px-4 py-3"><div className="h-5 bg-muted rounded w-24" /></td>
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-24" /></td>
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-48" /></td>
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-16" /></td>
                      <td className="px-4 py-3"><div className="h-8 bg-muted rounded w-20" /></td>
                    </tr>
                  ))
                ) : projectRequests.filter((r) => r.code_type === 'package_policy' || r.code_type === 'pr_check').length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-3 text-sm text-muted-foreground text-center">
                      No pending change requests.
                    </td>
                  </tr>
                ) : (
                  projectRequests.filter((r) => r.code_type === 'package_policy' || r.code_type === 'pr_check').map((req) => (
                    <tr key={req.id} className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-3 text-sm text-foreground font-medium truncate" title={req.project_name}>{req.project_name}</td>
                      <td className="px-4 py-3">{codeTypeBadge(req.code_type)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2 min-w-0">
                          <Avatar className="h-6 w-6 flex-shrink-0">
                            <AvatarImage src={req.author_avatar_url ?? undefined} alt="" />
                            <AvatarFallback className="text-[10px] bg-muted text-muted-foreground">
                              {(req.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                            </AvatarFallback>
                          </Avatar>
                          <span className="text-sm text-foreground truncate">{req.author_display_name || 'Unknown'}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-foreground truncate" title={req.message || undefined}>
                        {req.message?.trim() || '—'}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">{formatRelativeTime(req.created_at)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => { setSelectedRequest(req); setRequestDetailVisible(false); requestAnimationFrame(() => requestAnimationFrame(() => setRequestDetailVisible(true))); }}
                          >
                            <Eye className="h-3 w-3" />
                            View
                          </Button>
                          {hasManageCompliance && (
                            <>
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-7 text-xs"
                                disabled={reviewingRequestId === req.id}
                                onClick={(e) => { e.stopPropagation(); handleReviewRequest(req.id, 'accept'); }}
                              >
                                {reviewingRequestId === req.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
                                Accept
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-7 text-xs text-destructive hover:text-destructive"
                                disabled={reviewingRequestId === req.id}
                                onClick={(e) => { e.stopPropagation(); handleReviewRequest(req.id, 'reject'); }}
                              >
                                <X className="h-3 w-3" />
                                Reject
                              </Button>
                            </>
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
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <h2 className={cn('text-base font-semibold text-foreground', !selectedChange.message?.trim() && 'text-muted-foreground')}>
                    {selectedChange.message?.trim() || '—'}
                  </h2>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <p className="text-xs text-muted-foreground">{codeTypeLabel(selectedChange.code_type)}</p>
                    {(() => {
                      const { added, removed } = getDiffLineCounts(selectedChange.previous_code ?? '', selectedChange.new_code ?? '');
                      if (added > 0 || removed > 0) {
                        return (
                          <span className="inline-flex items-center gap-1.5 text-xs font-mono">
                            {added > 0 && <span className="text-emerald-600 dark:text-emerald-400">+{added}</span>}
                            {removed > 0 && <span className="text-red-600 dark:text-red-400">-{removed}</span>}
                          </span>
                        );
                      }
                      return null;
                    })()}
                  </div>
                </div>
                <div className="inline-flex items-center gap-2 flex-shrink-0" title={selectedChange.author_display_name || undefined}>
                  <span className="text-xs text-muted-foreground whitespace-nowrap">
                    {formatRelativeTime(selectedChange.created_at)}
                  </span>
                  <Avatar className="h-8 w-8 flex-shrink-0 ring-1 ring-border rounded-full">
                    <AvatarImage src={selectedChange.author_avatar_url ?? undefined} alt="" />
                    <AvatarFallback className="text-xs bg-muted text-muted-foreground">
                      {(selectedChange.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                    </AvatarFallback>
                  </Avatar>
                </div>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto min-h-0 px-6 py-4">
              <div className="rounded-lg overflow-hidden border border-border bg-background-card">
                <div className="px-3 py-2 border-b border-border flex items-center justify-between gap-2 bg-background-card">
                  <div className="flex items-center gap-2 min-w-0">
                    <JsLangBadge className="text-xs" />
                    <span className="text-xs font-medium text-foreground truncate">
                      {codeTypeLabel(selectedChange.code_type)}
                    </span>
                    {(() => {
                      const { added, removed } = getDiffLineCounts(
                        selectedChange.previous_code ?? '',
                        selectedChange.new_code ?? ''
                      );
                      return (
                        <>
                          {added > 0 && <span className="text-xs text-green-500">+{added}</span>}
                          {removed > 0 && <span className="text-xs text-red-500">-{removed}</span>}
                        </>
                      );
                    })()}
                  </div>
                </div>
                <PolicyDiffCodeEditor
                  original={selectedChange.previous_code ?? ''}
                  modified={selectedChange.new_code ?? ''}
                />
              </div>
            </div>
            <div className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header flex items-center justify-end gap-3">
              <Button variant="outline" size="sm" onClick={closeChangeDetail}>
                Close
              </Button>
            </div>
          </div>
        </div>,
        document.body,
      )}

      {/* Project request detail sidebar – diff and Accept/Reject */}
      {selectedRequest && createPortal(
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              requestDetailVisible ? 'opacity-100' : 'opacity-0',
            )}
            onClick={closeRequestDetail}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[560px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              requestDetailVisible ? 'translate-x-0' : 'translate-x-full',
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Project policy request</h2>
              <p className="text-sm text-foreground mt-1 font-medium">{selectedRequest.project_name}</p>
              <p className="text-sm text-muted-foreground mt-0.5 truncate">{selectedRequest.message?.trim() || '—'}</p>
              <div className="flex items-center gap-2 mt-2">
                {codeTypeBadge(selectedRequest.code_type)}
                <span className="text-xs text-muted-foreground">{formatRelativeTime(selectedRequest.created_at)}</span>
                {selectedRequest.has_conflict && (
                  <Badge variant="secondary" className="text-amber-600 border-amber-200 bg-amber-50">Conflict</Badge>
                )}
              </div>
              <div className="flex items-center gap-2 mt-3">
                <Avatar className="h-6 w-6 flex-shrink-0">
                  <AvatarImage src={selectedRequest.author_avatar_url ?? undefined} alt="" />
                  <AvatarFallback className="text-[10px] bg-muted text-muted-foreground">
                    {(selectedRequest.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                  </AvatarFallback>
                </Avatar>
                <span className="text-sm text-muted-foreground">Requested by {selectedRequest.author_display_name || 'Unknown'}</span>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto min-h-0 px-6 py-4">
              <div className="rounded-lg overflow-hidden border border-border bg-background-card">
                <div className="px-3 py-2 border-b border-border flex items-center justify-between gap-2 bg-background-card">
                  <div className="flex items-center gap-2 min-w-0">
                    <JsLangBadge className="text-xs" />
                    <span className="text-xs font-medium text-foreground truncate">
                      {codeTypeLabel(selectedRequest.code_type)}
                    </span>
                    {(() => {
                      const { added, removed } = getDiffLineCounts(
                        selectedRequest.base_code ?? '',
                        selectedRequest.proposed_code ?? ''
                      );
                      return (
                        <>
                          {added > 0 && <span className="text-xs text-green-500">+{added}</span>}
                          {removed > 0 && <span className="text-xs text-red-500">-{removed}</span>}
                        </>
                      );
                    })()}
                  </div>
                </div>
                <PolicyDiffCodeEditor
                  original={selectedRequest.base_code ?? ''}
                  modified={selectedRequest.proposed_code ?? ''}
                />
              </div>
            </div>
            <div className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header flex items-center justify-between gap-3">
              <Button variant="outline" size="sm" onClick={closeRequestDetail}>
                Close
              </Button>
              {hasManageCompliance && (
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-destructive hover:text-destructive"
                    disabled={reviewingRequestId === selectedRequest.id}
                    onClick={() => handleReviewRequest(selectedRequest.id, 'reject')}
                  >
                    <X className="h-3 w-3 mr-1" />
                    Reject
                  </Button>
                  <Button
                    size="sm"
                    disabled={reviewingRequestId === selectedRequest.id}
                    onClick={() => handleReviewRequest(selectedRequest.id, 'accept')}
                  >
                    {reviewingRequestId === selectedRequest.id ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Check className="h-3 w-3 mr-1" />}
                    Accept
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>,
        document.body,
      )}

      {/* Commit sidebar – message + diff, open after validation passes */}
      {commitSidebarCodeType && createPortal(
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              commitSidebarVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeCommitSidebar}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[560px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              commitSidebarVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Commit policy change</h2>
              <p className="text-sm text-muted-foreground mt-1">Add a message and review the diff before applying.</p>
            </div>
            <div className="flex-1 overflow-y-auto min-h-0 px-6 py-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground">Message</label>
                  <Input
                    type="text"
                    value={commitMessage}
                    onChange={(e) => setCommitMessage(e.target.value)}
                    placeholder=""
                    disabled={committing}
                    className="h-9 w-full"
                  />
                </div>
                <div className="rounded-lg overflow-hidden border border-border bg-background-card">
                  <div className="px-3 py-2 border-b border-border flex items-center justify-between gap-2 bg-background-card">
                    <div className="flex items-center gap-2 min-w-0">
                      <JsLangBadge className="text-xs" />
                      <span className="text-xs font-medium text-foreground">
                        {commitSidebarCodeType === 'package_policy' ? 'Package policy' : 'PR Check'}
                      </span>
                    </div>
                  </div>
                  <PolicyDiffCodeEditor
                    original={
                      commitSidebarCodeType === 'package_policy'
                        ? wrapPackagePolicyBody(packagePolicyOriginal)
                        : wrapPrCheckBody(prCheckOriginal)
                    }
                    modified={
                      commitSidebarCodeType === 'package_policy'
                        ? wrapPackagePolicyBody(packagePolicyCode)
                        : wrapPrCheckBody(prCheckCode)
                    }
                  />
                </div>
              </div>
            </div>
            <div className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header flex items-center justify-end gap-3">
              <Button variant="outline" size="sm" onClick={closeCommitSidebar} disabled={committing}>
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={handleCommitSubmit}
                disabled={committing || !commitMessage.trim()}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              >
                {committing && <Loader2 className="h-3 w-3 mr-1.5 animate-spin" />}
                Commit
              </Button>
            </div>
          </div>
        </div>,
        document.body,
      )}

      {/* AI Assistant – stay mounted once opened so conversation persists when closed; only unmount when user leaves the page */}
      {everOpenedAI && createPortal(
        <div className={cn('fixed inset-0 z-50', !showAI && 'pointer-events-none')}>
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              !showAI ? 'opacity-0' : (aiPanelVisible ? 'opacity-100' : 'opacity-0')
            )}
            onClick={() => { aiAssistantCloseRef.current ? aiAssistantCloseRef.current() : closeAIPanel(); }}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[680px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              // Extra offset past 100% so border/shadow don’t peek when closed
              !showAI ? 'translate-x-[calc(100%+32px)]' : (aiPanelVisible ? 'translate-x-0' : 'translate-x-[calc(100%+32px)]')
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
              innerCloseRef={aiAssistantCloseRef}
            />
          </div>
        </div>,
        document.body,
      )}
    </main>
  );
}

