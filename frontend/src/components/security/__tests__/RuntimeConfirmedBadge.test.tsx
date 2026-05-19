import { describe, it, expect } from 'vitest';
import { render, screen } from '../../../test/utils';
import { RuntimeConfirmedBadge } from '../RuntimeConfirmedBadge';

// The RuntimeConfirmedBadge marks an SCA finding whose reachability was
// flipped to 'confirmed' by a runtime DAST observation. priorLevel is
// optional — the badge must render cleanly with or without it.

describe('RuntimeConfirmedBadge', () => {
  it('renders the "Runtime Confirmed" label', () => {
    render(<RuntimeConfirmedBadge priorLevel="module" />);
    expect(screen.getByText('Runtime Confirmed')).toBeInTheDocument();
  });

  it('renders with a null priorLevel without crashing', () => {
    render(<RuntimeConfirmedBadge priorLevel={null} />);
    expect(screen.getByText('Runtime Confirmed')).toBeInTheDocument();
  });

  it('renders with priorLevel omitted entirely', () => {
    render(<RuntimeConfirmedBadge />);
    expect(screen.getByText('Runtime Confirmed')).toBeInTheDocument();
  });
});
