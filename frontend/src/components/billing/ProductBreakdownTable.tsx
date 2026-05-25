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

const COL_GRID = 'grid grid-cols-[2fr_2fr_1fr] items-center gap-4';

export function ProductBreakdownTable({ products, loading }: ProductBreakdownTableProps) {
  return (
    <div className="overflow-hidden">
      <div className={`${COL_GRID} border-b border-border px-5 pb-3 pt-4`}>
        <h4 className="text-sm font-semibold text-foreground">Products</h4>
        <h4 className="text-sm font-semibold text-foreground">Usage</h4>
        <h4 className="text-right text-sm font-semibold text-foreground">Costs</h4>
      </div>

      {loading && products.length === 0 ? (
        <div className="px-5 py-6 text-sm text-foreground-secondary">Loading…</div>
      ) : products.length === 0 ? (
        <div className="px-5 py-6 text-sm text-foreground-secondary">No products billed in this range.</div>
      ) : (
        <div className="divide-y divide-border">
          {products.map((product, idx) => {
            const color = featureColor(product.feature, idx);
            return (
              <div
                key={product.feature}
                className={`${COL_GRID} px-5 py-3 hover:bg-background-card-hover`}
              >
                <div className="flex items-center gap-2 text-foreground">
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                  <span>{featureLabel(product.feature)}</span>
                </div>
                <div className="flex items-center gap-3">
                  <Sparkline values={product.sparkline} color={color} />
                  <span className="font-mono text-sm text-foreground-secondary">
                    {formatQuantity(product.eventType, product.totalQuantity)}
                  </span>
                </div>
                <div className="text-right font-mono text-sm text-foreground">
                  {formatCents(product.totalCents)}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
