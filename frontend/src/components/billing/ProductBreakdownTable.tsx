import React from 'react';
import { Line, LineChart, ResponsiveContainer } from 'recharts';
import {
  type ProductRow,
  featureColor,
  featureLabel,
  formatCents,
  formatQuantity,
} from './usage-types';

interface ProductBreakdownTableProps {
  products: ProductRow[];
  loading: boolean;
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const data = values.map((v, i) => ({ i, v }));
  if (data.length === 0 || data.every((d) => d.v === 0)) {
    return <div className="h-8 w-24 text-foreground-secondary/40">—</div>;
  }
  return (
    <div className="h-8 w-24">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <Line type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ProductBreakdownTable({ products, loading }: ProductBreakdownTableProps) {
  if (loading && products.length === 0) {
    return (
      <div className="p-6 text-sm text-foreground-secondary">Loading…</div>
    );
  }
  if (products.length === 0) {
    return (
      <div className="p-6 text-sm text-foreground-secondary">No products billed in this range.</div>
    );
  }
  return (
    <div className="overflow-hidden">
      <div className="px-5 pb-3 pt-4">
        <h4 className="text-sm font-semibold text-foreground">Products</h4>
      </div>
      <table className="w-full text-sm">
        <tbody className="divide-y divide-border">
          {products.map((product, idx) => {
            const color = featureColor(product.feature, idx);
            return (
              <tr key={product.feature} className="hover:bg-background-card-hover">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2 text-foreground">
                    <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                    <span>{featureLabel(product.feature)}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <Sparkline values={product.sparkline} color={color} />
                </td>
                <td className="px-4 py-3 text-right font-mono text-foreground-secondary">
                  {formatQuantity(product.eventType, product.totalQuantity)}
                </td>
                <td className="px-4 py-3 text-right font-mono text-foreground">{formatCents(product.totalCents)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
