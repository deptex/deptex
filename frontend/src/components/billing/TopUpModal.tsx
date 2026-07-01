import { useCallback, useEffect, useRef, useState } from 'react';
import { Coins, Loader2, CreditCard } from 'lucide-react';
import { supabase } from '../../lib/supabase';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { TopUpForm } from './TopUpForm';
import { AddCardModal } from './AddCardModal';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

export type TopUpReason = 'insufficient_credit' | 'low_balance' | 'manual';

interface TopUpModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizationId: string;
  reason?: TopUpReason;
  /** Gate: the form only renders for members who can actually pay. */
  canManageBilling: boolean;
  userEmail?: string | null;
  /** Fired once a top-up is *confirmed credited* to the balance (webhook landed). */
  onCredited?: () => void;
}

interface BillingSnapshot {
  balanceCents: number;
  hasPaymentMethod: boolean;
}

async function fetchBillingSnapshot(organizationId: string): Promise<BillingSnapshot | null> {
  const { data: session } = await supabase.auth.getSession();
  const token = session.session?.access_token;
  if (!token) return null;
  const res = await fetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  // 404 = org has no billing row yet (legacy pre-trigger org). Treat as $0 / no card —
  // a top-up provisions the Stripe customer, so we still let them proceed.
  if (res.status === 404) return { balanceCents: 0, hasPaymentMethod: false };
  if (!res.ok) return null;
  const data = (await res.json()) as { balanceCents?: number; paymentMethod?: unknown };
  return {
    balanceCents: typeof data.balanceCents === 'number' ? data.balanceCents : 0,
    hasPaymentMethod: !!data.paymentMethod,
  };
}

const HEADERS: Record<TopUpReason, { title: string; description: string }> = {
  insufficient_credit: {
    title: "You're out of AI credit",
    description: 'Add credit to keep using Aegis and AI features.',
  },
  low_balance: {
    title: 'Your AI credit is running low',
    description: 'Top up so your AI features keep running.',
  },
  manual: {
    title: 'Add AI credit',
    description: 'Top up your prepaid balance.',
  },
};

// How long to wait for the async Stripe webhook to credit the balance before
// giving up and showing the "it'll land shortly" note. The credit lands
// out-of-band (payment_intent.succeeded → credit_balance), so the synchronous
// 'succeeded' from topup-intent does NOT mean the balance is up yet.
const CREDIT_CONFIRM_TIMEOUT_MS = 15_000;
const CREDIT_POLL_INTERVAL_MS = 1_500;

export function TopUpModal({
  open,
  onOpenChange,
  organizationId,
  reason = 'manual',
  canManageBilling,
  userEmail = null,
  onCredited,
}: TopUpModalProps) {
  const [snapshot, setSnapshot] = useState<BillingSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [addingCard, setAddingCard] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [confirmTimedOut, setConfirmTimedOut] = useState(false);

  // Balance at the moment the top-up was submitted — we poll until the balance
  // rises above this, which is how we know the webhook credit actually landed.
  const preTopUpBalanceRef = useRef(0);
  // Flipped true on close/unmount so an in-flight credit poll stops touching state.
  const closedRef = useRef(false);

  const loadBilling = useCallback(async () => {
    setLoading(true);
    setLoadError(false);
    const snap = await fetchBillingSnapshot(organizationId);
    if (closedRef.current) return;
    if (snap) {
      setSnapshot(snap);
      preTopUpBalanceRef.current = snap.balanceCents;
    } else {
      setLoadError(true);
    }
    setLoading(false);
  }, [organizationId]);

  useEffect(() => {
    if (!open) {
      closedRef.current = true;
      setSnapshot(null);
      setAddingCard(false);
      setConfirming(false);
      setConfirmTimedOut(false);
      return;
    }
    closedRef.current = false;
    console.info('[monetize] topup_modal_opened', { organizationId, reason });
    void loadBilling();
  }, [open, organizationId, reason, loadBilling]);

  // After a successful charge, wait for the balance to actually rise (the credit
  // arrives via the async Stripe webhook). Closing immediately on the synchronous
  // 'succeeded' would show a stale $0 and read as a failed payment.
  const confirmCreditThenClose = useCallback(async () => {
    setConfirming(true);
    setConfirmTimedOut(false);
    const before = preTopUpBalanceRef.current;
    const deadline = Date.now() + CREDIT_CONFIRM_TIMEOUT_MS;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, CREDIT_POLL_INTERVAL_MS));
      if (closedRef.current) return;
      const snap = await fetchBillingSnapshot(organizationId);
      if (closedRef.current) return;
      if (snap && snap.balanceCents > before) {
        console.info('[monetize] topup_credited', {
          organizationId,
          balanceCents: snap.balanceCents,
        });
        setConfirming(false);
        onCredited?.();
        onOpenChange(false);
        return;
      }
    }
    // Webhook hasn't landed within the window — keep the modal up with a note.
    // The credit will still arrive; the cost_cap bubble's Retry re-checks the
    // balance server-side, so the user isn't stuck.
    if (closedRef.current) return;
    setConfirming(false);
    setConfirmTimedOut(true);
  }, [organizationId, onCredited, onOpenChange]);

  const header = HEADERS[reason];
  const balanceDollars = snapshot ? (snapshot.balanceCents / 100).toFixed(2) : null;

  return (
    <>
      <Dialog
        open={open && !addingCard}
        onOpenChange={(o) => {
          if (!o) onOpenChange(false);
        }}
      >
        <DialogContent className="max-w-md bg-background-card">
          <DialogHeader>
            <DialogTitle>{header.title}</DialogTitle>
            <DialogDescription>{header.description}</DialogDescription>
          </DialogHeader>

          {!canManageBilling ? (
            <div className="py-2 text-sm text-foreground-secondary">
              Only members with billing access can add credit. Ask an organization owner or a
              member with the Manage Billing permission to top up.
            </div>
          ) : loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
            </div>
          ) : loadError ? (
            <div className="space-y-3 py-2">
              <p className="text-sm text-destructive">Couldn't load your billing balance.</p>
              <Button variant="outline" onClick={() => void loadBilling()} className="!h-8 !px-3 !rounded-lg">
                Try again
              </Button>
            </div>
          ) : confirming ? (
            <div className="flex flex-col items-center gap-3 py-8 text-center">
              <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
              <p className="text-sm text-foreground-secondary">Confirming your payment…</p>
            </div>
          ) : confirmTimedOut ? (
            <div className="space-y-3 py-2">
              <p className="text-sm text-foreground">
                Payment received — your balance will update in a moment.
              </p>
              <p className="text-xs text-foreground-secondary">
                Close this and retry your message; it'll go through once the credit lands.
              </p>
              <Button variant="white" onClick={() => onOpenChange(false)}>
                Close
              </Button>
            </div>
          ) : snapshot && !snapshot.hasPaymentMethod ? (
            <div className="space-y-4 py-1">
              <div className="flex items-center gap-3 rounded-md border border-border bg-background-card-header px-4 py-3">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                  <Coins className="h-4 w-4 text-foreground-secondary" />
                </span>
                <div>
                  <p className="text-xs text-foreground-secondary">Current balance</p>
                  <p className="text-lg font-semibold tabular-nums text-foreground">${balanceDollars}</p>
                </div>
              </div>
              <p className="text-sm text-foreground-secondary">
                Add a payment method to add credit.
              </p>
              <Button variant="white" onClick={() => setAddingCard(true)} className="gap-2">
                <CreditCard className="h-4 w-4" />
                Add a card
              </Button>
            </div>
          ) : (
            <div className="space-y-4 py-1">
              <div className="flex items-center gap-3 rounded-md border border-border bg-background-card-header px-4 py-3">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                  <Coins className="h-4 w-4 text-foreground-secondary" />
                </span>
                <div>
                  <p className="text-xs text-foreground-secondary">Current balance</p>
                  <p className="text-lg font-semibold tabular-nums text-foreground">${balanceDollars}</p>
                </div>
              </div>
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm text-foreground-secondary">Add credit to your balance</p>
                <TopUpForm organizationId={organizationId} onSuccess={confirmCreditThenClose} />
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {open && addingCard && (
        <AddCardModal
          open={addingCard}
          onOpenChange={(o) => setAddingCard(o)}
          organizationId={organizationId}
          defaultEmail={userEmail}
          onSaved={async () => {
            setAddingCard(false);
            await loadBilling();
          }}
        />
      )}
    </>
  );
}

export default TopUpModal;
