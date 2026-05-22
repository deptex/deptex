import { supabase } from '../supabase';
import { sendEmail } from '../email';

const APP_BASE_URL = process.env.APP_BASE_URL || 'https://app.deptex.dev';

type BillingAlertKind =
  | 'low_balance'
  | 'zero_balance'
  | 'credit_added'
  | 'auto_recharge_failed';

interface OrgMemberRow {
  user_id: string;
  role: string;
  user_profiles?: { email: string } | null;
}

export async function resolveBillingRecipients(orgId: string): Promise<string[]> {
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('billing_email_override')
    .eq('organization_id', orgId)
    .single();

  if (billing?.billing_email_override) {
    return [billing.billing_email_override];
  }

  const { data: members } = await supabase
    .from('organization_members')
    .select('user_id, role, user_profiles!inner(email)')
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

  const recipients: string[] = [];
  for (const m of members as unknown as OrgMemberRow[]) {
    if (!billingRoleNames.has(m.role)) continue;
    const email = m.user_profiles?.email;
    if (email) recipients.push(email);
  }
  return recipients;
}

async function orgName(orgId: string): Promise<string> {
  const { data } = await supabase.from('organizations').select('name').eq('id', orgId).single();
  return data?.name ?? 'Your organization';
}

function billingPageUrl(orgId: string): string {
  return `${APP_BASE_URL}/organizations/${orgId}/settings/plan`;
}

function emailShell(orgName: string, body: string, ctaLabel: string, ctaUrl: string): string {
  return `<!doctype html>
<html><body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111">
  <p style="font-size:14px;color:#555">${orgName} — Deptex billing</p>
  ${body}
  <p style="margin:32px 0">
    <a href="${ctaUrl}" style="background:#047857;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:500">${ctaLabel}</a>
  </p>
  <p style="font-size:12px;color:#888;margin-top:32px">You're receiving this because you manage billing for ${orgName}. Reply to set a single billing email override in settings.</p>
</body></html>`;
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

  const [recipients, name] = await Promise.all([resolveBillingRecipients(orgId), orgName(orgId)]);
  if (recipients.length === 0) {
    await releaseAlertSlot(orgId, 'low_balance_alert_sent_at');
    return { sent: false, reason: 'no_recipients' };
  }

  const dollars = (balanceCents / 100).toFixed(2);
  const html = emailShell(
    name,
    `<h2 style="margin:0 0 12px">Your balance is low</h2>
     <p>Your current balance is <strong>$${dollars}</strong>. Top up to avoid an interruption.</p>`,
    'Top up now',
    billingPageUrl(orgId),
  );

  const result = await sendEmail({
    to: recipients,
    subject: `[${name}] Low balance — $${dollars} remaining`,
    html,
    text: `Your Deptex balance is low: $${dollars}. Top up: ${billingPageUrl(orgId)}`,
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

  const [recipients, name] = await Promise.all([resolveBillingRecipients(orgId), orgName(orgId)]);
  if (recipients.length === 0) {
    await releaseAlertSlot(orgId, 'zero_balance_alert_sent_at');
    return { sent: false, reason: 'no_recipients' };
  }

  const tail = autoRechargeEnabled
    ? `<p>Auto-recharge appears to have failed. Check your payment method.</p>`
    : `<p>Top up to resume Aegis chats and scans.</p>`;

  const html = emailShell(
    name,
    `<h2 style="margin:0 0 12px">Your balance is at $0</h2>
     <p>Aegis chats and metered scans are paused until you top up.</p>
     ${tail}`,
    'Top up now',
    billingPageUrl(orgId),
  );

  const result = await sendEmail({
    to: recipients,
    subject: `[${name}] Account out of credit`,
    html,
    text: `Your Deptex balance is $0. Top up: ${billingPageUrl(orgId)}`,
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
  const [recipients, name] = await Promise.all([resolveBillingRecipients(orgId), orgName(orgId)]);
  if (recipients.length === 0) return { sent: false, reason: 'no_recipients' };

  const dollars = (amountCents / 100).toFixed(2);
  const verb = source === 'auto_recharge_topup' ? 'auto-recharged' : 'topped up';
  const html = emailShell(
    name,
    `<h2 style="margin:0 0 12px">Receipt: $${dollars} ${verb}</h2>
     <p>Your account was ${verb} by <strong>$${dollars}</strong>.</p>`,
    'View activity',
    billingPageUrl(orgId),
  );

  const result = await sendEmail({
    to: recipients,
    subject: `[${name}] Receipt — $${dollars} added`,
    html,
    text: `$${dollars} was added to your Deptex balance.`,
  });

  return result.sent ? { sent: true } : { sent: false, reason: 'send_failed' };
}

export async function sendAutoRechargeFailed(orgId: string, reason: string): Promise<AlertSendResult> {
  const [recipients, name] = await Promise.all([resolveBillingRecipients(orgId), orgName(orgId)]);
  if (recipients.length === 0) return { sent: false, reason: 'no_recipients' };

  const html = emailShell(
    name,
    `<h2 style="margin:0 0 12px">Auto-recharge failed</h2>
     <p>We couldn't auto-recharge your account: <em>${reason}</em>.</p>
     <p>Auto-recharge has been disabled until you update your payment method.</p>`,
    'Update payment method',
    billingPageUrl(orgId),
  );

  const result = await sendEmail({
    to: recipients,
    subject: `[${name}] Auto-recharge failed`,
    html,
    text: `Auto-recharge failed: ${reason}. Disabled until payment method updated.`,
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
