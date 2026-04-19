import { ShieldCheck, CircleCheck, AlertCircle, User } from 'lucide-react';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';

type MockVulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low';
type MockVulnerabilityStatus = 'new' | 'to_do' | 'in_progress';

interface MockVulnerability {
  id: string;
  name: string;
  severity: MockVulnerabilitySeverity;
  status: MockVulnerabilityStatus;
  assignee: string | null;
}

const MOCK_VULNERABILITIES: MockVulnerability[] = [
  { id: '1', name: 'CVE-2024-1234 - Prototype Pollution in lodash', severity: 'critical', status: 'new', assignee: null },
  { id: '2', name: 'CVE-2024-2345 - SQL Injection in pg-promise', severity: 'high', status: 'to_do', assignee: 'Alex Chen' },
  { id: '3', name: 'CVE-2024-3456 - XSS in marked', severity: 'medium', status: 'in_progress', assignee: 'Sarah Kim' },
  { id: '4', name: 'CVE-2024-4567 - ReDoS in validator', severity: 'low', status: 'to_do', assignee: null },
  { id: '5', name: 'CVE-2024-5678 - Path Traversal in express-fileupload', severity: 'high', status: 'new', assignee: 'Jordan Lee' },
  { id: '6', name: 'CVE-2024-6789 - Buffer Overflow in sharp', severity: 'critical', status: 'in_progress', assignee: 'Morgan Taylor' },
  { id: '7', name: 'CVE-2024-7890 - SSRF in axios', severity: 'high', status: 'to_do', assignee: null },
  { id: '8', name: 'CVE-2024-8901 - Denial of Service in express', severity: 'medium', status: 'new', assignee: 'Casey Rivera' },
];

const MOCK_STATS = {
  overallSafety: 87,
  issuesSolved: 23,
  newIssues: 5,
  criticalCount: 2,
};

const getSeverityBadge = (severity: MockVulnerabilitySeverity) => {
  switch (severity) {
    case 'critical':
      return <Badge variant="destructive">Critical</Badge>;
    case 'high':
      return <Badge className="border-orange-500/20 bg-orange-500/10 text-orange-500">High</Badge>;
    case 'medium':
      return <Badge variant="warning">Medium</Badge>;
    case 'low':
      return <Badge variant="default">Low</Badge>;
  }
};

const getStatusBadge = (status: MockVulnerabilityStatus) => {
  switch (status) {
    case 'new':
      return <Badge className="border-blue-500/20 bg-blue-500/10 text-blue-500">New</Badge>;
    case 'to_do':
      return <Badge variant="default">To Do</Badge>;
    case 'in_progress':
      return <Badge variant="warning">In Progress</Badge>;
  }
};

export default function OrganizationVulnerabilitiesTabPage() {
  return (
    <main className="flex flex-col flex-1 min-h-0 w-full bg-background overflow-y-auto">
      <div className="mx-auto max-w-7xl w-full px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Overall Safety Card */}
          <div className="rounded-lg border border-border bg-background-card p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Overall Safety</span>
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-emerald-500/10">
                <ShieldCheck className="h-4 w-4 text-emerald-500" />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <p className="text-2xl font-bold text-foreground tabular-nums">{MOCK_STATS.overallSafety}%</p>
              <Badge variant="success" className="text-[10px]">Good</Badge>
            </div>
            <p className="text-xs text-foreground-secondary mt-1">Good security posture</p>
          </div>

          {/* Issues Solved Card */}
          <div className="rounded-lg border border-border bg-background-card p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Issues Solved</span>
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-blue-500/10">
                <CircleCheck className="h-4 w-4 text-blue-500" />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <p className="text-2xl font-bold text-foreground tabular-nums">{MOCK_STATS.issuesSolved}</p>
            </div>
            <p className="text-xs text-foreground-secondary mt-1">This month</p>
          </div>

          {/* New Issues Card */}
          <div className="rounded-lg border border-border bg-background-card p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">New Issues</span>
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-amber-500/10">
                <AlertCircle className="h-4 w-4 text-amber-500" />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <p className="text-2xl font-bold text-foreground tabular-nums">{MOCK_STATS.newIssues}</p>
              <Badge variant="destructive" className="text-[10px]">{MOCK_STATS.criticalCount} critical</Badge>
            </div>
            <p className="text-xs text-foreground-secondary mt-1">Requires attention</p>
          </div>
        </div>

        {/* Vulnerabilities Table */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">Recent Vulnerabilities</h2>
            <Button variant="outline" size="sm" className="h-8 text-xs">
              View All
            </Button>
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            {/* Header row */}
            <div className="px-4 py-3 bg-background-card-header border-b border-border grid grid-cols-[1fr_100px_120px_140px] gap-4 items-center">
              <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Vulnerability</div>
              <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Severity</div>
              <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</div>
              <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Assignee</div>
            </div>
            {/* Table rows */}
            <div className="divide-y divide-border">
              {MOCK_VULNERABILITIES.map((vuln) => (
                <div
                  key={vuln.id}
                  className="px-4 py-3 grid grid-cols-[1fr_100px_120px_140px] gap-4 items-center hover:bg-table-hover transition-colors cursor-pointer"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{vuln.name}</p>
                  </div>
                  <div>
                    {getSeverityBadge(vuln.severity)}
                  </div>
                  <div>
                    {getStatusBadge(vuln.status)}
                  </div>
                  <div className="flex items-center gap-2 min-w-0">
                    {vuln.assignee ? (
                      <>
                        <div className="h-6 w-6 rounded-full bg-background-subtle border border-border flex items-center justify-center flex-shrink-0">
                          <User className="h-3 w-3 text-foreground-secondary" />
                        </div>
                        <span className="text-sm text-foreground truncate">{vuln.assignee}</span>
                      </>
                    ) : (
                      <span className="text-sm text-foreground-secondary">Unassigned</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
