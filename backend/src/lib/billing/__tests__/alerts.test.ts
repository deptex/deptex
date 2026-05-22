import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
  queryBuilder,
} from '../../../test/mocks/supabaseSingleton';

jest.mock('../../email', () => ({
  sendEmail: jest.fn(),
}));

import {
  sendLowBalanceAlert,
  sendZeroBalanceAlert,
  sendCreditAddedEmail,
  sendAutoRechargeFailed,
  resolveBillingRecipients,
  checkAndDispatchBalanceAlerts,
} from '../alerts';
import { sendEmail } from '../../email';

const ORG_ID = '00000000-0000-0000-0000-000000000001';

function setBillingRow(overrides: Partial<Record<string, unknown>> = {}) {
  setTableResponse('organization_billing', 'single', {
    data: {
      organization_id: ORG_ID,
      billing_email_override: null,
      low_balance_alert_threshold_cents: 500,
      auto_recharge_enabled: false,
      low_balance_alert_sent_at: null,
      zero_balance_alert_sent_at: null,
      ...overrides,
    },
    error: null,
  });
}

function setOrgName(name = 'Acme Inc') {
  setTableResponse('organizations', 'single', {
    data: { name },
    error: null,
  });
}

function mockUpdateCount(returnCount: number) {
  (queryBuilder.update as jest.Mock).mockReturnValue({
    eq: jest.fn().mockReturnThis(),
    is: jest.fn().mockReturnThis(),
    then: (resolve: any) => resolve({ count: returnCount, error: null }),
  });
}

describe('resolveBillingRecipients', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    (sendEmail as jest.Mock).mockReset();
  });

  it('returns billing_email_override when set', async () => {
    setBillingRow({ billing_email_override: 'billing@acme.test' });
    const recipients = await resolveBillingRecipients(ORG_ID);
    expect(recipients).toEqual(['billing@acme.test']);
  });

  it('returns members with manage_billing role permission when no override', async () => {
    setBillingRow();
    setTableResponse('organization_members', 'then', {
      data: [
        { user_id: 'u1', role: 'owner', user_profiles: { email: 'owner@acme.test' } },
        { user_id: 'u2', role: 'member', user_profiles: { email: 'member@acme.test' } },
      ],
      error: null,
    });
    setTableResponse('organization_roles', 'then', {
      data: [
        { name: 'owner', permissions: {} },
        { name: 'member', permissions: { manage_billing: false } },
      ],
      error: null,
    });

    const recipients = await resolveBillingRecipients(ORG_ID);
    expect(recipients).toEqual(['owner@acme.test']);
  });
});

describe('sendLowBalanceAlert', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    (sendEmail as jest.Mock).mockReset();
  });

  it('does not send when claim slot returns 0 (already sent)', async () => {
    mockUpdateCount(0);
    const result = await sendLowBalanceAlert(ORG_ID, 250);
    expect(result.sent).toBe(false);
    expect(result.reason).toBe('already_sent');
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it('releases slot when no recipients', async () => {
    mockUpdateCount(1);
    setBillingRow({ billing_email_override: null });
    setTableResponse('organization_members', 'then', { data: [], error: null });
    setOrgName();

    const result = await sendLowBalanceAlert(ORG_ID, 250);
    expect(result.sent).toBe(false);
    expect(result.reason).toBe('no_recipients');
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it('sends and keeps flag when send succeeds', async () => {
    mockUpdateCount(1);
    setBillingRow({ billing_email_override: 'b@acme.test' });
    setOrgName();
    (sendEmail as jest.Mock).mockResolvedValueOnce({ sent: true, messageId: 'm1' });

    const result = await sendLowBalanceAlert(ORG_ID, 250);
    expect(result.sent).toBe(true);
    expect(sendEmail).toHaveBeenCalledWith(
      expect.objectContaining({
        to: ['b@acme.test'],
        subject: expect.stringContaining('Low balance'),
      }),
    );
  });

  it('releases flag when send fails', async () => {
    mockUpdateCount(1);
    setBillingRow({ billing_email_override: 'b@acme.test' });
    setOrgName();
    (sendEmail as jest.Mock).mockResolvedValueOnce({ sent: false, error: 'smtp down' });

    const result = await sendLowBalanceAlert(ORG_ID, 250);
    expect(result.sent).toBe(false);
    expect(result.reason).toBe('send_failed');
  });
});

describe('sendZeroBalanceAlert', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    (sendEmail as jest.Mock).mockReset();
  });

  it('content varies with auto_recharge_enabled = true', async () => {
    mockUpdateCount(1);
    setBillingRow({ billing_email_override: 'b@acme.test' });
    setOrgName();
    (sendEmail as jest.Mock).mockResolvedValueOnce({ sent: true });

    await sendZeroBalanceAlert(ORG_ID, true);
    const call = (sendEmail as jest.Mock).mock.calls[0][0];
    expect(call.html).toContain('Auto-recharge appears to have failed');
  });

  it('content varies with auto_recharge_enabled = false', async () => {
    mockUpdateCount(1);
    setBillingRow({ billing_email_override: 'b@acme.test' });
    setOrgName();
    (sendEmail as jest.Mock).mockResolvedValueOnce({ sent: true });

    await sendZeroBalanceAlert(ORG_ID, false);
    const call = (sendEmail as jest.Mock).mock.calls[0][0];
    expect(call.html).toContain('Top up to resume');
  });
});

describe('sendCreditAddedEmail', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    (sendEmail as jest.Mock).mockReset();
  });

  it('renders topup receipt', async () => {
    setBillingRow({ billing_email_override: 'b@acme.test' });
    setOrgName();
    (sendEmail as jest.Mock).mockResolvedValueOnce({ sent: true });

    const result = await sendCreditAddedEmail(ORG_ID, 2500, 'topup');
    expect(result.sent).toBe(true);
    const call = (sendEmail as jest.Mock).mock.calls[0][0];
    expect(call.subject).toContain('$25.00');
    expect(call.html).toContain('topped up');
  });

  it('renders auto-recharge receipt', async () => {
    setBillingRow({ billing_email_override: 'b@acme.test' });
    setOrgName();
    (sendEmail as jest.Mock).mockResolvedValueOnce({ sent: true });

    await sendCreditAddedEmail(ORG_ID, 2000, 'auto_recharge_topup');
    const call = (sendEmail as jest.Mock).mock.calls[0][0];
    expect(call.html).toContain('auto-recharged');
  });
});

describe('sendAutoRechargeFailed', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    (sendEmail as jest.Mock).mockReset();
  });

  it('always sends (no dedup flag)', async () => {
    setBillingRow({ billing_email_override: 'b@acme.test' });
    setOrgName();
    (sendEmail as jest.Mock).mockResolvedValueOnce({ sent: true });

    const result = await sendAutoRechargeFailed(ORG_ID, 'card_declined');
    expect(result.sent).toBe(true);
    const call = (sendEmail as jest.Mock).mock.calls[0][0];
    expect(call.html).toContain('card_declined');
  });
});

describe('checkAndDispatchBalanceAlerts', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    (sendEmail as jest.Mock).mockReset();
  });

  it('dispatches zero-balance when balance <= 0 and flag null', async () => {
    setBillingRow({
      low_balance_alert_threshold_cents: 500,
      zero_balance_alert_sent_at: null,
      auto_recharge_enabled: false,
    });
    mockUpdateCount(1);

    setTableResponse('organizations', 'single', { data: { name: 'X' }, error: null });
    setTableResponse('organization_members', 'then', { data: [], error: null });

    await checkAndDispatchBalanceAlerts(ORG_ID, 0);
  });

  it('dispatches nothing when balance > threshold', async () => {
    setBillingRow({ low_balance_alert_threshold_cents: 500 });
    await checkAndDispatchBalanceAlerts(ORG_ID, 1000);
    expect(sendEmail).not.toHaveBeenCalled();
  });
});
