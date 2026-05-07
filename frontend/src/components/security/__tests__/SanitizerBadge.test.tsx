/**
 * Phase 6.5 hardening — SanitizerBadge confidence-ladder rendering.
 *
 * The badge MUST hide entirely below the HIDE_BELOW threshold (so depscore
 * doesn't disagree with what the user sees), render an "AI uncertain" amber
 * pill in the middle band, and only render the "Sanitized" / "Unsanitized"
 * verdict + sanitizer line citation in the high-confidence band.
 */
import { describe, it, expect } from 'vitest';
import { render, screen } from '../../../test/utils';
import { SanitizerBadge } from '../SanitizerBadge';
import { HIDE_BELOW, UNCERTAIN_UPPER } from '../../../lib/security/confidence-thresholds';

describe('SanitizerBadge', () => {
  it('hides entirely (returns null) when confidence is below HIDE_BELOW', () => {
    const { container } = render(
      <SanitizerBadge isSanitized={true} confidence={HIDE_BELOW - 0.01} sanitizerLine={42} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders the amber "AI uncertain" pill in the middle band', () => {
    const mid = (HIDE_BELOW + UNCERTAIN_UPPER) / 2;
    render(<SanitizerBadge isSanitized={true} confidence={mid} sanitizerLine={42} />);
    expect(screen.getByText(/AI uncertain/i)).toBeInTheDocument();
    // The sanitizerLine citation MUST NOT render in the uncertain band, even
    // when the server returned one.
    expect(screen.queryByText(/:42/)).toBeNull();
  });

  it('renders "Sanitized" + sanitizer line citation in the confident band', () => {
    render(
      <SanitizerBadge
        isSanitized={true}
        confidence={UNCERTAIN_UPPER + 0.05}
        sanitizerLine={42}
      />,
    );
    expect(screen.getByText('Sanitized')).toBeInTheDocument();
    expect(screen.getByText(/:42/)).toBeInTheDocument();
  });

  it('renders "Unsanitized" leak label in the confident band when isSanitized=false', () => {
    render(<SanitizerBadge isSanitized={false} confidence={0.95} sanitizerLine={null} />);
    expect(screen.getByText('Unsanitized')).toBeInTheDocument();
  });

  it('renders "AI couldn\'t verify" amber pill when isSanitized is null', () => {
    render(<SanitizerBadge isSanitized={null} confidence={0.95} />);
    expect(screen.getByText(/couldn't verify/i)).toBeInTheDocument();
  });

  it('returns null when confidence is missing', () => {
    const { container } = render(<SanitizerBadge isSanitized={true} confidence={null} />);
    expect(container.firstChild).toBeNull();
  });
});
