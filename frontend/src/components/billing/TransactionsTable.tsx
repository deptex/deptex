import React, { useCallback, useEffect, useState } from 'react';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';
import { Skeleton } from '../ui/skeleton';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface Transaction {
  id: string;
  kind: 'signup_grant' | 'topup' | 'auto_recharge_topup' | 'usage_deduction' | 'refund' | 'adjustment';
  amountCents: number;
  description: string;
  createdAt: string;
  stripePaymentIntentId: string | null;
}

interface TransactionsResponse {
  transactions: Transaction[];
  nextCursor: string | null;
}

const KIND_LABEL: Record<Transaction['kind'], string> = {
  signup_grant: 'Welcome credit',
  topup: 'Top up',
  auto_recharge_topup: 'Auto-recharge',
  usage_deduction: 'Usage',
  refund: 'Refund',
  adjustment: 'Adjustment',
};

function formatAmount(cents: number): string {
  const dollars = Math.abs(cents) / 100;
  const sign = cents < 0 ? '−' : '+';
  return `${sign}$${dollars.toFixed(2)}`;
}

function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

interface TransactionsTableProps {
  organizationId: string;
}

export function TransactionsTable({ organizationId }: TransactionsTableProps) {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadPage = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      setError(null);
      try {
        const { data: session } = await supabase.auth.getSession();
        const token = session.session?.access_token;
        if (!token) throw new Error('Not authenticated');
        const url = new URL(`${API_BASE_URL}/api/organizations/${organizationId}/billing/transactions`);
        if (cursor) url.searchParams.set('cursor', cursor);
        const res = await fetch(url.toString(), { headers: { Authorization: `Bearer ${token}` } });
        if (!res.ok) throw new Error(`Failed to load transactions (${res.status})`);
        const data = (await res.json()) as TransactionsResponse;
        setTransactions((prev) => (cursor ? [...prev, ...data.transactions] : data.transactions));
        setNextCursor(data.nextCursor);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load transactions');
      } finally {
        setLoading(false);
      }
    },
    [organizationId],
  );

  useEffect(() => {
    void loadPage();
  }, [loadPage]);

  if (loading && transactions.length === 0) {
    return (
      <div
        className="space-y-2 pointer-events-none select-none"
        style={{
          maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
          WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
        }}
      >
        {Array.from({ length: 7 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  if (error) {
    return <p className="text-sm text-destructive">{error}</p>;
  }

  if (transactions.length === 0) {
    return <p className="text-sm text-muted-foreground">No transactions yet.</p>;
  }

  return (
    <div className="space-y-2">
      <div className="rounded-lg border border-border bg-background-card">
        <table className="w-full text-sm">
          <thead className="bg-background-card-header">
            <tr className="text-left text-xs text-muted-foreground">
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Description</th>
              <th className="px-4 py-2 font-medium text-right">Amount</th>
              <th className="px-4 py-2 font-medium text-right">Date</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {transactions.map((tx) => (
              <tr key={tx.id} className="hover:bg-background-card-hover">
                <td className="px-4 py-2 text-foreground">{KIND_LABEL[tx.kind]}</td>
                <td className="px-4 py-2 text-foreground-secondary">{tx.description}</td>
                <td className={`px-4 py-2 text-right font-mono ${tx.amountCents < 0 ? 'text-foreground-secondary' : 'text-foreground'}`}>
                  {formatAmount(tx.amountCents)}
                </td>
                <td className="px-4 py-2 text-right text-foreground-secondary">{formatTimestamp(tx.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {nextCursor && (
        <div className="flex justify-center pt-2">
          <Button
            variant="outline"
            size="sm"
            disabled={loading}
            onClick={() => loadPage(nextCursor)}
          >
            {loading ? 'Loading…' : 'Load more'}
          </Button>
        </div>
      )}
    </div>
  );
}
