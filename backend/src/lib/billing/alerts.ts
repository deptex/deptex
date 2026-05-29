import { supabase } from '../supabase';
import { sendEmail } from '../email';
import { captureBillingError } from '../observability/capture';

type BillingAlertKind =
  | 'low_balance'
  | 'zero_balance'
  | 'credit_added'
  | 'auto_recharge_failed'
  | 'auto_recharge_cap_reached';

interface OrgMemberRow {
  user_id: string;
  role: string;
}

export async function resolveBillingRecipients(orgId: string): Promise<string[]> {
  // Send to every org member whose role has the manage_billing permission. `owner` is
  // a structural role per CLAUDE.md and is always included regardless of what the seeded
  // permissions JSONB says (mirrors userHasOrgPermission's owner short-circuit).
  //
  // We don't call userHasOrgPermission per member because that would be N member-row
  // lookups + N role lookups — this batches both into 2 queries total. The duplicated
  // permission-check pattern is acknowledged technical drift; see audit P2 backlog.

  const { data: members } = await supabase
    .from('organization_members')
    .select('user_id, role')
    .eq('organization_id', orgId);

  if (!members || members.length === 0) return [];

  const { data: roles } = await supabase
    .from('organization_roles')
    .select('name, permissions')
    .eq('organization_id', orgId);

  const billingRoleNames = new Set<string>();
  for (const role of roles || []) {
    const perms = (role.permissions ?? {}) as Record<string, unknown>;
    if (role.name === 'owner' || perms.manage_billing === true) {
      billingRoleNames.add(role.name);
    }
  }

  const billingMembers = (members as unknown as OrgMemberRow[]).filter((m) =>
    billingRoleNames.has(m.role),
  );

  const emails = await Promise.all(
    billingMembers.map(async (m) => {
      try {
        const { data } = await supabase.auth.admin.getUserById(m.user_id);
        return data.user?.email ?? null;
      } catch (err) {
        console.warn('[billing.alerts] getUserById failed for', m.user_id, err);
        return null;
      }
    }),
  );

  return emails.filter((e): e is string => !!e);
}

async function orgName(orgId: string): Promise<string> {
  const { data } = await supabase.from('organizations').select('name').eq('id', orgId).single();
  return data?.name ?? 'Your organization';
}

// Gmail (and most mail clients) group emails into a thread by exact-match subject when the
// In-Reply-To/References headers are absent. Repeating subjects like "Auto-recharge failed"
// would pile up in one conversation. Appending a UTC timestamp keeps each notification its
// own conversation while still being readable.
function nowStamp(): string {
  const d = new Date();
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const mm = months[d.getUTCMonth()];
  const dd = d.getUTCDate();
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mn = String(d.getUTCMinutes()).padStart(2, '0');
  return `${mm} ${dd} ${hh}:${mn} UTC`;
}

async function tryClaimAlertSlot(orgId: string, column: 'low_balance_alert_sent_at' | 'zero_balance_alert_sent_at'): Promise<boolean> {
  // Atomic claim via conditional UPDATE: `… WHERE column IS NULL` lets exactly one concurrent
  // caller win (Postgres serializes the row write). .select() returns the rows actually
  // updated — reliable affected-row detection that doesn't depend on PostgREST populating a
  // count header on an UPDATE (which is undocumented and may silently no-op the claim).
  const { data, error } = await supabase
    .from('organization_billing')
    .update({ [column]: new Date().toISOString() })
    .eq('organization_id', orgId)
    .is(column, null)
    .select('organization_id');
  if (error) {
    console.error('[billing.alerts] tryClaimAlertSlot failed', error);
    captureBillingError(error, 'alert_slot_claim_failed', { orgId, extra: { column } });
    return false;
  }
  return (data?.length ?? 0) > 0;
}

async function releaseAlertSlot(orgId: string, column: 'low_balance_alert_sent_at' | 'zero_balance_alert_sent_at'): Promise<void> {
  await supabase.from('organization_billing').update({ [column]: null }).eq('organization_id', orgId);
}

export interface AlertSendResult {
  sent: boolean;
  reason?: 'no_recipients' | 'already_sent' | 'send_failed' | 'enforcement_off';
}

export async function sendLowBalanceAlert(orgId: string, balanceCents: number): Promise<AlertSendResult> {
  const claimed = await tryClaimAlertSlot(orgId, 'low_balance_alert_sent_at');
  if (!claimed) return { sent: false, reason: 'already_sent' };

  const recipients = await resolveBillingRecipients(orgId);
  const name = await orgName(orgId);
  if (recipients.length === 0) {
    await releaseAlertSlot(orgId, 'low_balance_alert_sent_at');
    return { sent: false, reason: 'no_recipients' };
  }

  const dollars = (balanceCents / 100).toFixed(2);
  const result = await sendEmail({
    to: recipients,
    subject: `Low balance ${name} — $${dollars} remaining (${nowStamp()})`,
    text: `Your account balance is low: $${dollars}.\n\nTo avoid disruptions, please consider topping up in billing.`,
  });

  if (!result.sent) {
    await releaseAlertSlot(orgId, 'low_balance_alert_sent_at');
    return { sent: false, reason: 'send_failed' };
  }
  return { sent: true };
}

export async function sendZeroBalanceAlert(orgId: string, autoRechargeEnabled: boolean): Promise<AlertSendResult> {
  const claimed = await tryClaimAlertSlot(orgId, 'zero_balance_alert_sent_at');
  if (!claimed) return { sent: false, reason: 'already_sent' };

  const recipients = await resolveBillingRecipients(orgId);
  const name = await orgName(orgId);
  if (recipients.length === 0) {
    await releaseAlertSlot(orgId, 'zero_balance_alert_sent_at');
    return { sent: false, reason: 'no_recipients' };
  }

  const tailText = autoRechargeEnabled
    ? `Auto-recharge appears to have failed. Please check your payment method in billing.`
    : `To resume Aegis chats and scans, please top up in billing.`;

  const result = await sendEmail({
    to: recipients,
    subject: `Account out of credit — ${name} (${nowStamp()})`,
    text: `Your account balance is at $0.00.\n\nAegis chats and metered scans are paused until you top up.\n\n${tailText}`,
  });

  if (!result.sent) {
    await releaseAlertSlot(orgId, 'zero_balance_alert_sent_at');
    return { sent: false, reason: 'send_failed' };
  }
  return { sent: true };
}

export async function sendCreditAddedEmail(
  orgId: string,
  amountCents: number,
  source: 'topup' | 'auto_recharge_topup',
): Promise<AlertSendResult> {
  const recipients = await resolveBillingRecipients(orgId);
  const name = await orgName(orgId);
  if (recipients.length === 0) return { sent: false, reason: 'no_recipients' };

  const dollars = (amountCents / 100).toFixed(2);
  const verb = source === 'auto_recharge_topup' ? 'auto-recharged' : 'topped up';
  const result = await sendEmail({
    to: recipients,
    subject: `Receipt ${name} — $${dollars} added (${nowStamp()})`,
    text: `Your account was ${verb} by $${dollars}.`,
  });

  return result.sent ? { sent: true } : { sent: false, reason: 'send_failed' };
}

// 30-day rolling cooldown on the cap-reached email — matches the rolling-30-day window the
// cap itself uses. Atomic conditional UPDATE (WHERE column IS NULL OR column < cutoff) so two
// concurrent cap-reached events can't both pass the cooldown check and both send the email.
const CAP_ALERT_COOLDOWN_MS = 30 * 24 * 60 * 60 * 1000;
const AUTO_RECHARGE_FAILED_COOLDOWN_MS = 24 * 60 * 60 * 1000;

async function tryClaimRollingSlot(
  orgId: string,
  column: 'auto_recharge_cap_alert_sent_at',
  cooldownMs: number,
): Promise<boolean> {
  const now = new Date();
  const cutoffIso = new Date(now.getTime() - cooldownMs).toISOString();
  const { data, error } = await supabase
    .from('organization_billing')
    .update({ [column]: now.toISOString() })
    .eq('organization_id', orgId)
    .or(`${column}.is.null,${column}.lt.${cutoffIso}`)
    .select('organization_id');
  if (error) {
    console.error('[billing.alerts] tryClaimRollingSlot failed', { column, error });
    captureBillingError(error, 'rolling_slot_claim_failed', { orgId, extra: { column } });
    return false;
  }
  return (data?.length ?? 0) > 0;
}

async function releaseRollingSlot(
  orgId: string,
  column: 'auto_recharge_cap_alert_sent_at',
): Promise<void> {
  await supabase
    .from('organization_billing')
    .update({ [column]: null })
    .eq('organization_id', orgId);
}

export async function sendAutoRechargeCapReached(
  orgId: string,
  spentCents: number,
  capCents: number,
): Promise<AlertSendResult> {
  const claimed = await tryClaimRollingSlot(
    orgId,
    'auto_recharge_cap_alert_sent_at',
    CAP_ALERT_COOLDOWN_MS,
  );
  if (!claimed) return { sent: false, reason: 'already_sent' };

  const recipients = await resolveBillingRecipients(orgId);
  const name = await orgName(orgId);
  if (recipients.length === 0) {
    await releaseRollingSlot(orgId, 'auto_recharge_cap_alert_sent_at');
    return { sent: false, reason: 'no_recipients' };
  }

  const spentDollars = (spentCents / 100).toFixed(2);
  const capDollars = (capCents / 100).toFixed(2);
  const result = await sendEmail({
    to: recipients,
    subject: `Auto-recharge cap reached — ${name} (${nowStamp()})`,
    text:
      `Your account has reached its auto-recharge cap of $${capDollars} ` +
      `(spent $${spentDollars} in the last 30 days).\n\n` +
      `Auto-recharge is paused. Spending will resume as older charges roll off the 30-day window. ` +
      `To resume sooner, raise the cap in billing or top up manually.`,
  });

  if (!result.sent) {
    // Release on failure so the next attempt isn't permanently muted.
    await releaseRollingSlot(orgId, 'auto_recharge_cap_alert_sent_at');
    return { sent: false, reason: 'send_failed' };
  }
  return { sent: true };
}

// In-memory dedup for the auto-recharge-failed email — Stripe webhook + inline failure
// handler can both fire for the same incident, and we don't want to spam. A 24-hour
// cooldown per org is fine since the user has to take action either way.
const recentAutoRechargeFailedSends = new Map<string, number>();

export async function sendAutoRechargeFailed(orgId: string, reason: string): Promise<AlertSendResult> {
  const lastSent = recentAutoRechargeFailedSends.get(orgId);
  if (lastSent && Date.now() - lastSent < AUTO_RECHARGE_FAILED_COOLDOWN_MS) {
    return { sent: false, reason: 'already_sent' };
  }
  // Mark intent BEFORE send; if send fails we clear so the next attempt can retry.
  recentAutoRechargeFailedSends.set(orgId, Date.now());

  const recipients = await resolveBillingRecipients(orgId);
  const name = await orgName(orgId);
  if (recipients.length === 0) {
    recentAutoRechargeFailedSends.delete(orgId);
    return { sent: false, reason: 'no_recipients' };
  }

  const result = await sendEmail({
    to: recipients,
    subject: `Auto-recharge failed — ${name} (${nowStamp()})`,
    text: `Auto-recharge failed: ${reason}.\n\nAuto-recharge has been disabled. Please update your payment method in billing to re-enable it.`,
  });

  if (!result.sent) {
    recentAutoRechargeFailedSends.delete(orgId);
    return { sent: false, reason: 'send_failed' };
  }
  return { sent: true };
}

export async function checkAndDispatchBalanceAlerts(
  orgId: string,
  newBalanceCents: number,
): Promise<void> {
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('low_balance_alert_threshold_cents, auto_recharge_enabled, low_balance_alert_sent_at, zero_balance_alert_sent_at')
    .eq('organization_id', orgId)
    .single();
  if (!billing) return;

  if (newBalanceCents <= 0 && !billing.zero_balance_alert_sent_at) {
    await sendZeroBalanceAlert(orgId, billing.auto_recharge_enabled).catch((err) => {
      console.error('[billing.alerts] sendZeroBalanceAlert failed', err);
      captureBillingError(err, 'zero_balance_alert_failed', { orgId });
    });
    return;
  }

  if (
    newBalanceCents > 0 &&
    newBalanceCents <= billing.low_balance_alert_threshold_cents &&
    !billing.low_balance_alert_sent_at
  ) {
    await sendLowBalanceAlert(orgId, newBalanceCents).catch((err) => {
      console.error('[billing.alerts] sendLowBalanceAlert failed', err);
      captureBillingError(err, 'low_balance_alert_failed', { orgId });
    });
  }
}

export const __testing = { tryClaimAlertSlot, releaseAlertSlot };
export type { BillingAlertKind };
