import React from 'react';
import { Line, LineChart, ResponsiveContainer } from 'recharts';
import { Skeleton } from '../ui/skeleton';
import { cn } from '../../lib/utils';
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
  onProductHover?: (feature: string | null) => void;
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

export function ProductBreakdownTable({
  products,
  loading,
  onProductHover,
}: ProductBreakdownTableProps) {
  return (
    <div className="overflow-hidden">
      <div className={`${COL_GRID} border-b border-border px-5 pb-3 pt-4`}>
        <h4 className="text-base font-semibold tracking-tight text-foreground">Products</h4>
        <h4 className="text-base font-semibold tracking-tight text-foreground">Usage</h4>
        <h4 className="text-right text-base font-semibold tracking-tight text-foreground">Costs</h4>
      </div>

      {loading && products.length === 0 ? (
        <div>
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className={`${COL_GRID} px-5 py-3`}>
              <Skeleton className="h-4 w-32" />
              <div className="flex items-center gap-3">
                <Skeleton className="h-4 w-14" />
                <Skeleton className="h-8 w-24" />
              </div>
              <Skeleton className="ml-auto h-4 w-16" />
            </div>
          ))}
        </div>
      ) : products.length === 0 ? (
        <div className="px-5 py-6 text-sm text-foreground-secondary">No products billed in this range.</div>
      ) : (
        <div>
          {products.map((product, idx) => {
            const color = featureColor(product.feature, idx);
            return (
              <div
                key={product.feature}
                onMouseEnter={() => onProductHover?.(product.feature)}
                onMouseLeave={() => onProductHover?.(null)}
                className={`${COL_GRID} cursor-default px-5 py-3 transition-colors hover:bg-table-hover`}
              >
                <div className="text-sm text-foreground">{featureLabel(product.feature)}</div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm text-foreground-secondary">
                    {formatQuantity(product.eventType, product.totalQuantity)}
                  </span>
                  <Sparkline values={product.sparkline} color={color} />
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
