import { useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import type { SlaComplianceResponse } from '../../lib/api';

const MET_COLOR = '#22c55e';
const MET_LATE_COLOR = '#f59e0b';
const BREACHED_COLOR = '#ef4444';
const EXEMPT_COLOR = '#64748b';

interface SLAAdherenceChartProps {
  adherenceByMonth: SlaComplianceResponse['adherence_by_month'];
}

export default function SLAAdherenceChart({ adherenceByMonth }: SLAAdherenceChartProps) {
  const data = useMemo(() => {
    return adherenceByMonth.map((row) => ({
      name: row.month,
      Met: row.met,
      'Resolved late': row.met_late,
      Breached: row.breached,
      Exempt: row.exempt,
    }));
  }, [adherenceByMonth]);

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 rounded-lg border border-border bg-muted/30 text-sm text-muted-foreground">
        No adherence data for the selected period.
      </div>
    );
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
          <XAxis dataKey="name" tick={{ fontSize: 11 }} className="text-muted-foreground" />
          <YAxis tick={{ fontSize: 11 }} className="text-muted-foreground" allowDecimals={false} />
          <Tooltip
            formatter={(value: number) => [value, '']}
            labelFormatter={(label) => `Month: ${label}`}
            contentStyle={{ backgroundColor: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', borderRadius: '8px' }}
          />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          <Bar dataKey="Met" stackId="a" fill={MET_COLOR} name="Met" radius={[0, 0, 0, 0]} />
          <Bar dataKey="Resolved late" stackId="a" fill={MET_LATE_COLOR} name="Resolved late" radius={[0, 0, 0, 0]} />
          <Bar dataKey="Breached" stackId="a" fill={BREACHED_COLOR} name="Breached" radius={[0, 0, 0, 0]} />
          <Bar dataKey="Exempt" stackId="a" fill={EXEMPT_COLOR} name="Exempt" radius={[0, 0, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
