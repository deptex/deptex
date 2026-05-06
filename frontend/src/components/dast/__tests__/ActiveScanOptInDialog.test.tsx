import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/utils';
import { ActiveScanOptInDialog } from '../ActiveScanOptInDialog';

// Boundary regression gates for the active-scan attestation dialog. The
// strict trim-equality between confirmText and targetUrl is the only runtime
// guard authorizing a destructive scan; the v2.1a critical review flagged
// this surface as P0 because no test pinned (a) empty-input → button
// disabled, (b) prefix-substring → does NOT match, (c) trailing whitespace
// is forgiven, (d) onConfirm fires only when matches=true.

const TARGET = 'https://app.example.com';

describe('ActiveScanOptInDialog — confirm-text gate', () => {
  beforeEach(() => {
    // Each test gets a clean slate; component reads localStorage in helpers
    // not asserted here.
    window.localStorage.clear();
  });

  it('confirm button is disabled on initial open (empty input)', () => {
    render(
      <ActiveScanOptInDialog
        open={true}
        onOpenChange={() => {}}
        targetUrl={TARGET}
        onConfirm={vi.fn()}
      />,
    );
    const btn = screen.getByRole('button', { name: /Run active scan/i });
    expect(btn).toBeDisabled();
  });

  it('button stays disabled on a prefix substring of the URL', () => {
    render(
      <ActiveScanOptInDialog
        open={true}
        onOpenChange={() => {}}
        targetUrl={TARGET}
        onConfirm={vi.fn()}
      />,
    );
    const input = screen.getByPlaceholderText(TARGET);
    fireEvent.change(input, { target: { value: 'https://app.example' } });
    const btn = screen.getByRole('button', { name: /Run active scan/i });
    expect(btn).toBeDisabled();
  });

  it('button enables on exact match', () => {
    render(
      <ActiveScanOptInDialog
        open={true}
        onOpenChange={() => {}}
        targetUrl={TARGET}
        onConfirm={vi.fn()}
      />,
    );
    const input = screen.getByPlaceholderText(TARGET);
    fireEvent.change(input, { target: { value: TARGET } });
    const btn = screen.getByRole('button', { name: /Run active scan/i });
    expect(btn).toBeEnabled();
  });

  it('trim-tolerance: trailing newline still matches (operator copy-paste)', () => {
    render(
      <ActiveScanOptInDialog
        open={true}
        onOpenChange={() => {}}
        targetUrl={TARGET}
        onConfirm={vi.fn()}
      />,
    );
    const input = screen.getByPlaceholderText(TARGET);
    fireEvent.change(input, { target: { value: `${TARGET}\n` } });
    const btn = screen.getByRole('button', { name: /Run active scan/i });
    expect(btn).toBeEnabled();
  });

  it('onConfirm fires ONLY when input matches targetUrl', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    render(
      <ActiveScanOptInDialog
        open={true}
        onOpenChange={() => {}}
        targetUrl={TARGET}
        onConfirm={onConfirm}
      />,
    );
    const input = screen.getByPlaceholderText(TARGET);
    const btn = screen.getByRole('button', { name: /Run active scan/i });

    // Mismatched value — clicking the (disabled) button must NOT fire.
    fireEvent.change(input, { target: { value: 'wrong' } });
    fireEvent.click(btn);
    expect(onConfirm).not.toHaveBeenCalled();

    // Exact match — fires once.
    fireEvent.change(input, { target: { value: TARGET } });
    fireEvent.click(btn);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('Cancel button never invokes onConfirm', () => {
    const onConfirm = vi.fn();
    render(
      <ActiveScanOptInDialog
        open={true}
        onOpenChange={() => {}}
        targetUrl={TARGET}
        onConfirm={onConfirm}
      />,
    );
    const cancel = screen.getByRole('button', { name: /Cancel/i });
    fireEvent.click(cancel);
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
