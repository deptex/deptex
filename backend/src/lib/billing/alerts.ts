import { supabase } from '../supabase';
import { sendEmail } from '../email';

type BillingAlertKind =
  | 'low_balance'
  | 'zero_balance'
  | 'credit_added'
  | 'auto_recharge_failed';

interface OrgMemberRow {
  user_id: string;
  role: string;
}

export async function resolveBillingRecipients(orgId: string): Promise<string[]> {
  // Always send to every org member with manage_billing permission. No override
  // column — the billing_email_recipients column is kept in DB for future use
  // but no code reads it today.

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

async function tryClaimAlertSlot(orgId: string, column: 'low_balance_alert_sent_at' | 'zero_balance_alert_sent_at'): Promise<boolean> {
  const { error, count } = await supabase
    .from('organization_billing')
    .update({ [column]: new Date().toISOString() }, { count: 'exact' })
    .eq('organization_id', orgId)
    .is(column, null);
  if (error) {
    console.error('[billing.alerts] tryClaimAlertSlot failed', error);
    return false;
  }
  return (count ?? 0) > 0;
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
    subject: `Low balance ${name} — $${dollars} remaining`,
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
    subject: `Account out of credit — ${name}`,
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
    subject: `Receipt ${name} — $${dollars} added`,
    text: `Your account was ${verb} by $${dollars}.`,
  });

  return result.sent ? { sent: true } : { sent: false, reason: 'send_failed' };
}

export async function sendAutoRechargeFailed(orgId: string, reason: string): Promise<AlertSendResult> {
  const recipients = await resolveBillingRecipients(orgId);
  const name = await orgName(orgId);
  if (recipients.length === 0) return { sent: false, reason: 'no_recipients' };

  const result = await sendEmail({
    to: recipients,
    subject: `Auto-recharge failed — ${name}`,
    text: `Auto-recharge failed: ${reason}.\n\nAuto-recharge has been disabled. Please update your payment method in billing to re-enable it.`,
  });

  return result.sent ? { sent: true } : { sent: false, reason: 'send_failed' };
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
    });
  }
}

export const __testing = { tryClaimAlertSlot, releaseAlertSlot };
export type { BillingAlertKind };
