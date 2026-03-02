import { useState, useEffect, useCallback } from 'react';
import { Download, FileText, Loader2, Clock, ShieldAlert, TrendingUp } from 'lucide-react';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { api, type SlaComplianceResponse } from '../../lib/api';
import SLAAdherenceChart from './SLAAdherenceChart';
import SLAViolationsTable from './SLAViolationsTable';
import SLATeamBreakdown from './SLATeamBreakdown';
import SLAPDFReport from './SLAPDFReport';
import { PDFDownloadLink } from '@react-pdf/renderer';

interface SLAComplianceDashboardProps {
  organizationId: string;
  organizationName: string;
}

const TIME_RANGES = [
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: '6m', label: 'Last 6 months' },
  { value: '12m', label: 'Last 12 months' },
] as const;

function downloadCsv(rows: Array<Record<string, string | null>>, headers: string[], filename: string) {
  const headerLine = headers.join(',');
  const escape = (v: string | null) => {
    if (v == null) return '""';
    const s = String(v);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) return `"${s.replace(/"/g, '""')}"`;
    return `"${s}"`;
  };
  const lines = [headerLine, ...rows.map((r) => headers.map((h) => escape(r[h] ?? null)).join(','))];
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function SLAComplianceDashboard({ organizationId, organizationName }: SLAComplianceDashboardProps) {
  const [timeRange, setTimeRange] = useState<string>('90d');
  const [data, setData] = useState<SlaComplianceResponse | null>(null);
  const [exportData, setExportData] = useState<{ rows: Array<{ project_name: string; project_id: string; osv_id: string; severity: string; sla_status: string; detected_at: string; deadline: string | null; met_at: string | null; breached_at: string | null }>; summary: { time_range: string; total_vulnerabilities: number; met_within_sla: number; resolved_late: number; current_breaches: number; compliance_percent: number } } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!organizationId) return;
    setLoading(true);
    setError(null);
    try {
      const [compliance, exportRes] = await Promise.all([
        api.getSlaCompliance(organizationId, timeRange),
        api.getSlaComplianceExport(organizationId, timeRange),
      ]);
      setData(compliance);
      setExportData(exportRes);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load SLA compliance');
      setData(null);
      setExportData(null);
    } finally {
      setLoading(false);
    }
  }, [organizationId, timeRange]);

  useEffect(() => {
    load();
  }, [load]);

  const handleDownloadCsv = () => {
    if (!exportData) return;
    const headers = ['project_name', 'project_id', 'osv_id', 'severity', 'sla_status', 'detected_at', 'deadline', 'met_at', 'breached_at'];
    downloadCsv(exportData.rows, headers, `sla-compliance-${organizationName.replace(/\s+/g, '-')}-${timeRange}.csv`);
  };

  const avgMttr = data?.average_mttr_by_severity
    ? Object.values(data.average_mttr_by_severity).reduce((a, b) => a + b, 0) / Object.keys(data.average_mttr_by_severity).length
    : 0;

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-4 text-sm text-destructive">
        {error}
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2">
          {TIME_RANGES.map(({ value, label }) => (
            <Button
              key={value}
              variant={timeRange === value ? 'default' : 'outline'}
              size="sm"
              onClick={() => setTimeRange(value)}
            >
              {label}
            </Button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleDownloadCsv} disabled={!exportData}>
            <Download className="h-4 w-4 mr-2" />
            Download CSV
          </Button>
          {exportData && data && (
            <PDFDownloadLink
              document={
                <SLAPDFReport
                  orgName={organizationName}
                  compliance={data}
                  exportSummary={exportData.summary}
                  exportRows={exportData.rows}
                />
              }
              fileName={`sla-compliance-${organizationName.replace(/\s+/g, '-')}-${timeRange}.pdf`}
            >
              {({ loading: pdfLoading }) => (
                <Button variant="outline" size="sm" disabled={pdfLoading}>
                  {pdfLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <FileText className="h-4 w-4 mr-2" />}
                  Download PDF
                </Button>
              )}
            </PDFDownloadLink>
          )}
        </div>
      </div>

      {/* 3 metric cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" />
              Overall compliance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-foreground tabular-nums">{data.overall_compliance_percent}%</p>
            <p className="text-xs text-muted-foreground mt-1">Met within SLA vs resolved late</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Current breaches
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className={`text-2xl font-bold tabular-nums ${data.current_breaches > 0 ? 'text-red-500' : 'text-foreground'}`}>
              {data.current_breaches}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Past deadline</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <TrendingUp className="h-4 w-4" />
              Average MTTR (h)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-foreground tabular-nums">{avgMttr > 0 ? avgMttr.toFixed(1) : '—'}</p>
            <p className="text-xs text-muted-foreground mt-1">Mean time to resolve by severity</p>
          </CardContent>
        </Card>
      </div>

      {/* Adherence trend */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Adherence trend</CardTitle>
          <p className="text-sm text-muted-foreground">Met / resolved late / breached / exempt by month</p>
        </CardHeader>
        <CardContent>
          <SLAAdherenceChart adherenceByMonth={data.adherence_by_month} />
        </CardContent>
      </Card>

      {/* Violations table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Current violations</CardTitle>
          <p className="text-sm text-muted-foreground">Warning and breached items; select and fix with AI</p>
        </CardHeader>
        <CardContent>
          <SLAViolationsTable organizationId={organizationId} violations={data.violations} onFixTriggered={load} />
        </CardContent>
      </Card>

      {/* Team breakdown */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Per-team breakdown</CardTitle>
        </CardHeader>
        <CardContent>
          <SLATeamBreakdown teamBreakdown={data.team_breakdown} />
        </CardContent>
      </Card>
    </div>
  );
}
