import { useState, useEffect } from 'react';
import { FileCode, CheckCircle2, GitCommit, Bot, ShieldAlert, AlertOctagon, AlertTriangle, Loader2, User, Clock, ExternalLink, ShieldOff, Check } from 'lucide-react';
import { Button } from './ui/button';
import { api, WatchtowerCommit } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import { ANOMALY_HIGH_THRESHOLD } from '../lib/watchtower-constants';

interface CommitSidebarProps {
    commit: WatchtowerCommit;
    packageName: string;
    repoFullName: string;
    /** When provided (e.g. from dependencies.github_url), used for the GitHub issue link instead of repoFullName. */
    githubUrl?: string | null;
    onClose: () => void;
    /** When provided, "Quarantine next release" button toggles org watchlist quarantine and calls this after update. */
    organizationId?: string;
    projectId?: string;
    dependencyId?: string;
    quarantineNextRelease?: boolean;
    onQuarantineToggle?: () => void;
    /** When provided, "Acknowledge" clears this commit and removes it from the list; called with the commit, then sidebar closes. */
    onClearCommit?: (commit: WatchtowerCommit) => void;
    /** When false, hide Acknowledge button and disable Quarantine next release. */
    canManageWatchtower?: boolean;
}

/** Parse owner/repo from a GitHub URL (e.g. https://github.com/owner/repo.git -> owner/repo). */
function repoFullNameFromGithubUrl(githubUrl: string): string | null {
    const match = githubUrl.match(/github\.com\/([^/]+\/[^/]+?)(\.git)?$/);
    return match ? match[1] : null;
}

export function CommitSidebar({
    commit,
    packageName,
    repoFullName,
    githubUrl,
    onClose,
    organizationId,
    projectId,
    dependencyId,
    quarantineNextRelease,
    onQuarantineToggle,
    onClearCommit,
    canManageWatchtower = true,
}: CommitSidebarProps) {
    const issueRepo = githubUrl ? repoFullNameFromGithubUrl(githubUrl) : null;
    /** Prefer repo from dependency.github_url; fall back to repoFullName so the link is always shown. */
    const repoForIssue = issueRepo ?? (repoFullName || 'owner/repo');
    // #region agent log
    fetch('http://127.0.0.1:7243/ingest/abaca787-5416-40c4-b6fe-aea97fa8dfd8', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'CommitSidebar.tsx:repoForIssue', message: 'GitHub issue repo resolution', data: { githubUrl: githubUrl ?? null, issueRepo, repoFullName, repoForIssue }, timestamp: Date.now(), sessionId: 'debug-session', hypothesisId: 'A' }) }).catch(() => { });
    // #endregion
    const [analyzing, setAnalyzing] = useState(false);
    const [analysis, setAnalysis] = useState<string | null>(null);

    const [contributorProfile, setContributorProfile] = useState<any | null>(null);
    const [loadingContributors, setLoadingContributors] = useState(true);
    const [quarantineUpdating, setQuarantineUpdating] = useState(false);
    const [clearingCommit, setClearingCommit] = useState(false);
    const { toast } = useToast();

    const handleAcknowledge = async () => {
        if (!organizationId || !projectId || !dependencyId || !onClearCommit) return;
        setClearingCommit(true);
        try {
            await api.clearWatchtowerCommit(organizationId, projectId, dependencyId, commit.sha);
            onClearCommit(commit);
            onClose();
        } catch (e: any) {
            toast({ title: 'Error', description: e.message ?? 'Failed to acknowledge commit', variant: 'destructive' });
        } finally {
            setClearingCommit(false);
        }
    };

    const handleQuarantineNextRelease = async () => {
        if (!organizationId || !projectId || !dependencyId) {
            toast({ title: 'Cannot update quarantine', description: 'Missing project context.', variant: 'destructive' });
            return;
        }
        setQuarantineUpdating(true);
        try {
            const next = !(quarantineNextRelease ?? false);
            await api.patchWatchlistQuarantine(organizationId, projectId, dependencyId, next);
            onQuarantineToggle?.();
            toast({
                title: next ? 'Quarantining next version' : 'No longer quarantining next version',
                description: next ? 'The next release will be in quarantine for 7 days.' : undefined,
            });
        } catch (e: any) {
            toast({ title: 'Error', description: e.message ?? 'Failed to update quarantine', variant: 'destructive' });
        } finally {
            setQuarantineUpdating(false);
        }
    };

    // Load contributor data
    useEffect(() => {
        let mounted = true;
        setLoadingContributors(true);
        api.getWatchtowerContributors(packageName)
            .then(data => {
                if (mounted) {

                    // Try to find matching contributor by email or name
                    const match = data.find((c: any) =>
                        c.author_email === commit.author_email ||
                        (commit.author_email && c.author_email && c.author_email.toLowerCase() === commit.author_email.toLowerCase())
                    );
                    setContributorProfile(match || null);
                }
            })
            .catch(err => console.error('Failed to load contributors', err))
            .finally(() => {
                if (mounted) setLoadingContributors(false);
            });

        return () => { mounted = false; };
    }, [packageName, commit.author_email]);

    const handleAnalyze = async () => {
        setAnalyzing(true);
        try {
            const repoForApi = issueRepo ?? repoFullName;
            const result = await api.analyzeWatchtowerCommit(packageName, commit.sha, repoForApi);
            setAnalysis(result.analysis);
        } catch (error: any) {
            toast({
                title: "Analysis Failed",
                description: error.message || "Could not fetch analysis. Ensure GitHub App is connected.",
                variant: "destructive"
            });
        } finally {
            setAnalyzing(false);
        }
    };

    const isHighRisk = commit.anomaly && commit.anomaly.score >= ANOMALY_HIGH_THRESHOLD;

    return (
        <div className="fixed inset-0 z-50">
            {/* Backdrop */}
            <div
                className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
                onClick={onClose}
            />

            {/* Side Panel */}
            <div
                className="fixed right-0 top-0 h-full w-full max-w-xl bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
                    <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-3">
                            <span className="inline-flex items-center gap-1.5 text-xs font-mono text-foreground-secondary">
                                <GitCommit className="h-3 w-3" />
                                {commit.sha.substring(0, 7)}
                            </span>
                            <span className="text-xs text-foreground-secondary">
                                {new Date(commit.timestamp).toLocaleString()}
                            </span>
                        </div>
                        <a
                            href={`https://github.com/${repoForIssue}/commit/${commit.sha}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-foreground-secondary hover:text-foreground inline-flex items-center gap-1 transition-colors"
                        >
                            <ExternalLink className="h-3 w-3" />
                            GitHub
                        </a>
                    </div>
                    <h2 className="text-lg font-semibold text-foreground leading-tight line-clamp-2">
                        {commit.message}
                    </h2>
                    {/* Compact action row */}
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                        {canManageWatchtower && onClearCommit && organizationId && projectId && dependencyId && (
                            <Button
                                variant="outline"
                                size="sm"
                                className="gap-1.5 border border-border bg-transparent text-foreground hover:bg-background-subtle/30"
                                onClick={handleAcknowledge}
                                disabled={clearingCommit}
                            >
                                {clearingCommit ? (
                                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                ) : (
                                    <Check className="h-3.5 w-3.5" />
                                )}
                                Acknowledge
                            </Button>
                        )}
                        {canManageWatchtower && (
                            <Button
                                variant="outline"
                                size="sm"
                                className={quarantineNextRelease
                                    ? 'gap-1.5 border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-400 hover:bg-amber-500/25 hover:border-amber-500/50'
                                    : 'gap-1.5 border-warning/20 bg-warning/5 text-warning hover:bg-warning/10 hover:border-warning/30'
                                }
                                onClick={organizationId && projectId && dependencyId ? handleQuarantineNextRelease : undefined}
                                disabled={quarantineUpdating}
                            >
                                {quarantineUpdating ? (
                                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                ) : (
                                    <ShieldOff className="h-3.5 w-3.5" />
                                )}
                                {quarantineNextRelease ? 'Quarantining next version' : 'Quarantine Next Release'}
                            </Button>
                        )}
                    </div>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto no-scrollbar">
                    <div className="px-6 py-6 space-y-6">

                        {/* Aegis Analysis */}
                        <div>
                            <div className="mb-3 flex items-center justify-between gap-3">
                                <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                                    <Bot className="h-4 w-4 text-primary" />
                                    Aegis AI Analysis
                                </h3>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={handleAnalyze}
                                    disabled={analyzing}
                                    className="gap-1.5 shrink-0 border-border/50 bg-transparent text-foreground-secondary hover:bg-background-subtle/20 hover:text-foreground"
                                >
                                    {analyzing ? (
                                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                    ) : (
                                        <ShieldAlert className="h-3.5 w-3.5" />
                                    )}
                                    {analyzing ? 'Analyzing…' : 'Ask Aegis'}
                                </Button>
                            </div>

                            {!analysis ? (
                                <p className="text-xs text-foreground-secondary py-1">
                                    Run an AI analysis of this commit.
                                </p>
                            ) : (
                                <div className="animate-in fade-in zoom-in-95 duration-200">
                                    {(() => {
                                        const isSafe = analysis.includes('**SAFE**') || analysis.toLowerCase().startsWith('safe');
                                        const isSuspicious = analysis.includes('**SUSPICIOUS**') || analysis.toLowerCase().startsWith('suspicious');
                                        const isCaution = analysis.includes('**CAUTION**') || analysis.toLowerCase().startsWith('caution');

                                        // Determine code block color based on verdict
                                        const codeBlockColor = isSuspicious ? 'error' : 'warning';

                                        // Parse the content after the verdict
                                        const parseContent = (text: string) => {
                                            // Remove the verdict marker
                                            let content = text
                                                .replace(/\*\*SAFE\*\*/gi, '')
                                                .replace(/\*\*SUSPICIOUS\*\*/gi, '')
                                                .replace(/\*\*CAUTION\*\*/gi, '')
                                                .trim();

                                            // Convert markdown bold to JSX and handle code blocks
                                            const parts: React.ReactNode[] = [];
                                            const lines = content.split('\n');

                                            let inCodeBlock = false;
                                            let codeContent = '';

                                            lines.forEach((line, idx) => {
                                                // Check for code block start/end
                                                if (line.startsWith('```')) {
                                                    if (!inCodeBlock) {
                                                        inCodeBlock = true;
                                                        codeContent = '';
                                                    } else {
                                                        // End of code block
                                                        parts.push(
                                                            <pre key={`code-${idx}`} className={`my-2 p-3 rounded-md bg-${codeBlockColor}/10 border border-${codeBlockColor}/30 overflow-x-auto`}>
                                                                <code className={`text-xs font-mono text-${codeBlockColor}`}>{codeContent}</code>
                                                            </pre>
                                                        );
                                                        inCodeBlock = false;
                                                        codeContent = '';
                                                    }
                                                    return;
                                                }

                                                if (inCodeBlock) {
                                                    codeContent += (codeContent ? '\n' : '') + line;
                                                    return;
                                                }

                                                // Handle inline formatting
                                                if (line.trim()) {
                                                    // Parse inline bold (**text**) and inline code (`text`)
                                                    const formattedLine = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/).map((part, i) => {
                                                        if (part.startsWith('**') && part.endsWith('**')) {
                                                            return <strong key={i} className="font-semibold text-foreground">{part.slice(2, -2)}</strong>;
                                                        }
                                                        if (part.startsWith('`') && part.endsWith('`')) {
                                                            return <code key={i} className={`px-1 py-0.5 rounded bg-background-subtle text-xs font-mono text-${codeBlockColor}`}>{part.slice(1, -1)}</code>;
                                                        }
                                                        return part;
                                                    });

                                                    // Check if it's a list item
                                                    if (line.trim().startsWith('-') || line.trim().startsWith('•')) {
                                                        parts.push(
                                                            <div key={idx} className="flex items-start gap-2 text-sm">
                                                                <span className="text-foreground-secondary mt-0.5">•</span>
                                                                <span>{formattedLine}</span>
                                                            </div>
                                                        );
                                                    } else {
                                                        parts.push(<p key={idx} className="text-sm">{formattedLine}</p>);
                                                    }
                                                }
                                            });

                                            return parts;
                                        };

                                        if (isSafe) {
                                            return (
                                                <div className="rounded-lg border border-success/30 bg-success/5 p-4">
                                                    <div className="flex items-center gap-2 mb-3">
                                                        <div className="flex items-center justify-center w-6 h-6 rounded-full bg-success/20">
                                                            <CheckCircle2 className="h-4 w-4 text-success" />
                                                        </div>
                                                        <span className="font-semibold text-success">SAFE</span>
                                                    </div>
                                                    <div className="text-foreground-secondary space-y-1">
                                                        {parseContent(analysis)}
                                                    </div>
                                                </div>
                                            );
                                        }

                                        if (isCaution) {
                                            const issueUrl = `https://github.com/${repoForIssue}/issues/new?title=${encodeURIComponent(`[Security Review] Potential concern in ${commit.sha.substring(0, 7)}`)}&body=${encodeURIComponent(`## Aegis Security Review\n\n**Commit:** ${commit.sha}\n**Package:** ${packageName}\n\n### Findings\n\n${analysis.replace(/\*\*/g, '')}`)}`;
                                            return (
                                                <div className="rounded-lg border border-warning/30 bg-warning/5 p-4">
                                                    <div className="flex items-center gap-2 mb-3">
                                                        <div className="flex items-center justify-center w-6 h-6 rounded-full bg-warning/20">
                                                            <AlertTriangle className="h-4 w-4 text-warning" />
                                                        </div>
                                                        <span className="font-semibold text-warning">CAUTION</span>
                                                    </div>
                                                    <div className="text-foreground space-y-2">
                                                        {parseContent(analysis)}
                                                    </div>
                                                    <a
                                                        href={issueUrl}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="mt-4 inline-flex items-center gap-2 text-sm text-warning hover:text-warning/80 transition-colors"
                                                    >
                                                        <ExternalLink className="h-3.5 w-3.5" />
                                                        Create GitHub Issue
                                                    </a>
                                                </div>
                                            );
                                        }

                                        if (isSuspicious) {
                                            const issueUrl = `https://github.com/${repoForIssue}/issues/new?title=${encodeURIComponent(`[SECURITY ALERT] Suspicious code in ${commit.sha.substring(0, 7)}`)}&body=${encodeURIComponent(`## ⚠️ Aegis Security Alert\n\n**Commit:** ${commit.sha}\n**Package:** ${packageName}\n\n### Suspicious Findings\n\n${analysis.replace(/\*\*/g, '')}\n\n---\n*This issue was flagged by Aegis AI security analysis.*`)}`;
                                            return (
                                                <div className="rounded-lg border border-error/30 bg-error/5 p-4">
                                                    <div className="flex items-center gap-2 mb-3">
                                                        <div className="flex items-center justify-center w-6 h-6 rounded-full bg-error/20 animate-pulse">
                                                            <AlertOctagon className="h-4 w-4 text-error" />
                                                        </div>
                                                        <span className="font-semibold text-error">SUSPICIOUS</span>
                                                    </div>
                                                    <div className="text-foreground space-y-2">
                                                        {parseContent(analysis)}
                                                    </div>
                                                    <a
                                                        href={issueUrl}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="mt-4 inline-flex items-center gap-2 text-sm text-error hover:text-error/80 transition-colors"
                                                    >
                                                        <ExternalLink className="h-3.5 w-3.5" />
                                                        Create GitHub Issue
                                                    </a>
                                                </div>
                                            );
                                        }

                                        // Fallback for unknown format
                                        return (
                                            <div className="rounded-lg border border-border bg-background-card p-4">
                                                <div className="text-sm text-foreground whitespace-pre-wrap">
                                                    {parseContent(analysis)}
                                                </div>
                                            </div>
                                        );
                                    })()}

                                    <Button
                                        onClick={() => setAnalysis(null)}
                                        variant="ghost"
                                        size="sm"
                                        className="mt-3 text-xs text-foreground-secondary"
                                    >
                                        Reset Analysis
                                    </Button>
                                </div>
                            )}
                        </div>

                        {/* Anomaly Detection Breakdown */}
                        <div className="pt-4 border-t border-border">
                            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                                <AlertOctagon className="h-4 w-4 text-warning" />
                                Anomaly Detection Breakdown
                            </h3>

                            {commit.anomaly ? (
                                <div className={`rounded-lg border p-4 ${isHighRisk ? 'bg-error/5 border-error/20' : 'bg-warning/5 border-warning/20'}`}>
                                    <div className="flex items-center justify-between mb-4">
                                        <span className="text-sm font-medium text-foreground">Score Breakdown</span>
                                        <span className={`text-lg font-bold tabular-nums ${isHighRisk ? 'text-error' : 'text-warning'}`}>
                                            {commit.anomaly.score}
                                        </span>
                                    </div>
                                    <div className="space-y-2">
                                        {commit.anomaly.breakdown.map((item: any, idx: number) => (
                                            <div key={idx} className="flex items-start gap-3 text-sm">
                                                <span className={`font-mono font-medium min-w-[32px] ${isHighRisk ? 'text-error' : 'text-warning'}`}>
                                                    +{item.points}
                                                </span>
                                                <span className="text-foreground">{item.reason}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ) : (
                                <div className="rounded-lg border border-border/50 bg-transparent p-4 flex items-center gap-3">
                                    <CheckCircle2 className="h-5 w-5 text-success" />
                                    <div>
                                        <p className="text-sm font-medium text-foreground">No anomalies detected</p>
                                        <p className="text-xs text-foreground-secondary">This commit matches typical behavior patterns.</p>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Commit Analysis */}
                        <div className="pt-4 border-t border-border">
                            <h3 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
                                <FileCode className="h-4 w-4 text-foreground-secondary" />
                                Commit Analysis
                            </h3>

                            <div className="space-y-3">
                                <div className="flex items-center justify-between text-sm">
                                    <span className="text-foreground-secondary">Additions</span>
                                    <span className="font-mono font-medium text-success">+{commit.lines_added}</span>
                                </div>
                                <div className="flex items-center justify-between text-sm">
                                    <span className="text-foreground-secondary">Deletions</span>
                                    <span className="font-mono font-medium text-error">-{commit.lines_deleted}</span>
                                </div>
                                <div className="flex items-center justify-between text-sm">
                                    <span className="text-foreground-secondary">Files Changed</span>
                                    <span className="font-mono font-medium text-foreground">{commit.files_changed}</span>
                                </div>
                            </div>

                            {/* Functions worked on */}
                            <div className="mt-4 pt-3 border-t border-border">
                                <div className="text-xs text-foreground-secondary mb-2 font-medium">Functions worked on</div>
                                {commit.touched_functions && commit.touched_functions.length > 0 ? (
                                    <div className="flex flex-wrap gap-1.5">
                                        {commit.touched_functions.map((fn) => (
                                            <span
                                                key={fn}
                                                className="inline-flex items-center rounded-md bg-transparent px-2 py-0.5 text-xs font-mono text-foreground-secondary border border-border/50"
                                            >
                                                {fn}
                                            </span>
                                        ))}
                                    </div>
                                ) : (
                                    <p className="text-xs text-foreground-secondary italic">No exported functions detected in changed files.</p>
                                )}
                            </div>

                            {/* Contributor Norms */}
                            {loadingContributors ? (
                                <div className="mt-5 pt-4 border-t border-border animate-pulse">
                                    <div className="flex items-center gap-3 mb-4">
                                        <div className="w-8 h-8 rounded-full bg-border/40" />
                                        <div className="space-y-1.5">
                                            <div className="h-3 w-24 bg-border/40 rounded" />
                                            <div className="h-2 w-32 bg-border/40 rounded" />
                                        </div>
                                    </div>

                                    {/* Stats Grid Skeleton */}
                                    <div className="space-y-3 mb-4">
                                        {[1, 2, 3].map((i) => (
                                            <div key={i} className="flex items-center justify-between">
                                                <div className="h-2 w-20 bg-border/40 rounded" />
                                                <div className="h-3 w-8 bg-border/40 rounded" />
                                            </div>
                                        ))}
                                    </div>

                                    {/* Active Hours/Days Skeleton */}
                                    <div className="mb-4 pt-3">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-3 h-3 bg-border/40 rounded-full" />
                                            <div className="h-2 w-20 bg-border/40 rounded" />
                                        </div>
                                        <div className="h-3 w-full max-w-[200px] bg-border/40 rounded" />
                                    </div>
                                </div>
                            ) : contributorProfile && (
                                <div className="mt-5 pt-4 border-t border-border">
                                    <div className="flex items-center gap-3 mb-4">
                                        <div className="w-8 h-8 rounded-full bg-background-subtle border border-border flex items-center justify-center">
                                            <User className="h-4 w-4 text-foreground-secondary" />
                                        </div>
                                        <div>
                                            <div className="text-sm font-medium text-foreground">{commit.author}</div>
                                            <div className="text-xs text-foreground-secondary">
                                                {contributorProfile.total_commits} commits analyzed
                                            </div>
                                        </div>
                                    </div>

                                    {/* Stats Grid */}
                                    <div className="space-y-2 mb-4">
                                        <div className="flex items-center justify-between text-sm">
                                            <span className="text-foreground-secondary">Typical Additions</span>
                                            <span className="font-mono text-foreground">~{Math.round(contributorProfile.avg_lines_added)}</span>
                                        </div>
                                        <div className="flex items-center justify-between text-sm">
                                            <span className="text-foreground-secondary">Typical Deletions</span>
                                            <span className="font-mono text-foreground">~{Math.round(contributorProfile.avg_lines_deleted)}</span>
                                        </div>
                                        {contributorProfile.avg_files_changed > 0 && (
                                            <div className="flex items-center justify-between text-sm">
                                                <span className="text-foreground-secondary">Typical Files Changed</span>
                                                <span className="font-mono text-foreground">~{Math.round(contributorProfile.avg_files_changed)}</span>
                                            </div>
                                        )}
                                    </div>

                                    {/* Active Hours/Days */}
                                    {(contributorProfile.typical_days_active && Object.keys(contributorProfile.typical_days_active).length > 0) && (
                                        <div className="mb-4 pt-3">
                                            <div className="flex items-center gap-2 text-xs text-foreground-secondary mb-2">
                                                <Clock className="h-3 w-3" />
                                                <span>Usually Active</span>
                                            </div>
                                            <div className="text-sm text-foreground">
                                                {(() => {
                                                    const days = contributorProfile.typical_days_active;
                                                    const sortedDays = Object.entries(days)
                                                        .sort(([, a]: any, [, b]: any) => b - a)
                                                        .slice(0, 3)
                                                        .map(([day]) => day.substring(0, 3));
                                                    return sortedDays.join(', ');
                                                })()}
                                                {contributorProfile.commit_time_histogram && Object.keys(contributorProfile.commit_time_histogram).length > 0 && (
                                                    <span className="text-foreground-secondary">
                                                        {' • '}
                                                        {(() => {
                                                            const hours = contributorProfile.commit_time_histogram;
                                                            const sortedHours = Object.entries(hours)
                                                                .sort(([, a]: any, [, b]: any) => b - a)
                                                                .slice(0, 3)
                                                                .map(([hour]) => parseInt(hour));
                                                            const min = Math.min(...sortedHours);
                                                            const max = Math.max(...sortedHours);
                                                            const formatHour = (h: number) => h === 0 ? '12am' : h < 12 ? `${h}am` : h === 12 ? '12pm' : `${h - 12}pm`;
                                                            return `${formatHour(min)}-${formatHour(max + 1)}`;
                                                        })()}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                </div>
                            )}

                            {!loadingContributors && !contributorProfile && (
                                <p className="mt-4 text-xs text-foreground-secondary italic">
                                    No historical data for {commit.author}. This may be their first commit.
                                </p>
                            )}
                        </div>

                        {/* Full-width border: end of sidebar content (matches header border) */}
                        <div className="border-b border-border -mx-6" aria-hidden />
                    </div>
                </div>


            </div>
        </div>
    );
}
