import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/utils';
import { MessageBubble } from '../MessageBubble';

// The cost_cap error bubble is the in-chat paywall. These pin: (a) billing
// managers get a "Top up" button wired to openTopUp('insufficient_credit');
// (b) everyone else falls back to a link that points at /settings/billing
// (NOT the stale /settings/ai), and the bubble never throws without onTopUp.

function costCapMessage() {
  return {
    id: 'm1',
    role: 'assistant',
    parts: [],
    error: { type: 'cost_cap', statusCode: null, message: 'Your prepaid balance is too low.' },
  } as any;
}

describe('MessageBubble — cost_cap CTA', () => {
  it('renders a "Top up" button that calls onTopUp("insufficient_credit") for billing managers', () => {
    const onTopUp = vi.fn();
    render(
      <MessageBubble message={costCapMessage()} organizationId="org1" onTopUp={onTopUp} canManageBilling />,
    );
    const btn = screen.getByRole('button', { name: /Top up/i });
    fireEvent.click(btn);
    expect(onTopUp).toHaveBeenCalledTimes(1);
    expect(onTopUp).toHaveBeenCalledWith('insufficient_credit');
  });

  it('falls back to a /settings/billing link (not /settings/ai) and does not throw without onTopUp', () => {
    render(<MessageBubble message={costCapMessage()} organizationId="org1" />);
    expect(screen.queryByRole('button', { name: /Top up/i })).toBeNull();
    const link = screen.getByRole('link', { name: /Billing settings/i });
    expect(link).toHaveAttribute('href', '/organizations/org1/settings/billing');
  });

  it('shows the billing link, not a Top up button, when the member cannot manage billing', () => {
    const onTopUp = vi.fn();
    render(
      <MessageBubble
        message={costCapMessage()}
        organizationId="org1"
        onTopUp={onTopUp}
        canManageBilling={false}
      />,
    );
    expect(screen.queryByRole('button', { name: /Top up/i })).toBeNull();
    expect(screen.getByRole('link', { name: /Billing settings/i })).toBeInTheDocument();
  });
});
