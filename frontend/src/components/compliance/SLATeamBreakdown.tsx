import type { SlaComplianceResponse } from '../../lib/api';

interface SLATeamBreakdownProps {
  teamBreakdown: SlaComplianceResponse['team_breakdown'];
}

export default function SLATeamBreakdown({ teamBreakdown }: SLATeamBreakdownProps) {
  if (teamBreakdown.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-muted/30 px-4 py-6 text-center text-sm text-muted-foreground">
        No team breakdown (no teams or no SLA data).
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th className="text-left font-medium px-4 py-2.5 text-foreground">Team</th>
            <th className="text-right font-medium px-4 py-2.5 text-foreground">Total vulns</th>
            <th className="text-right font-medium px-4 py-2.5 text-foreground">On track %</th>
            <th className="text-right font-medium px-4 py-2.5 text-foreground">Warning</th>
            <th className="text-right font-medium px-4 py-2.5 text-foreground">Breached</th>
            <th className="text-right font-medium px-4 py-2.5 text-foreground">Avg MTTR (h)</th>
          </tr>
        </thead>
        <tbody>
          {teamBreakdown.map((row) => (
            <tr key={row.team_id} className="border-b border-border last:border-0 hover:bg-muted/30">
              <td className="px-4 py-2.5 font-medium text-foreground">{row.team_name}</td>
              <td className="px-4 py-2.5 text-right tabular-nums text-foreground">{row.total}</td>
              <td className="px-4 py-2.5 text-right tabular-nums text-foreground">{row.on_track_pct}%</td>
              <td className="px-4 py-2.5 text-right tabular-nums text-amber-500">{row.warning}</td>
              <td className="px-4 py-2.5 text-right tabular-nums text-red-500">{row.breached}</td>
              <td className="px-4 py-2.5 text-right tabular-nums text-foreground">{row.avg_mttr > 0 ? row.avg_mttr.toFixed(1) : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
