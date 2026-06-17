import { describe, it, expect } from 'vitest';
import { render, screen } from '../test/utils';
import { SeverityPills } from '../components/SeverityPills';

describe('SeverityPills', () => {
  it('renders the four band counts', () => {
    render(<SeverityPills critical={1} high={2} medium={3} low={4} />);
    expect(screen.getByText('1')).toBeTruthy();
    expect(screen.getByText('2')).toBeTruthy();
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.getByText('4')).toBeTruthy();
  });

  it('shows all four bands (zeros included) by default', () => {
    const { container } = render(<SeverityPills critical={0} high={0} medium={1} low={0} />);
    // 4 pill triggers regardless of zero counts, so columns stay aligned across rows.
    expect(container.querySelectorAll('span.rounded-full').length).toBe(4);
  });

  it('hideZeros drops empty bands', () => {
    const { container } = render(<SeverityPills critical={0} high={0} medium={1} low={2} hideZeros />);
    expect(container.querySelectorAll('span.rounded-full').length).toBe(2);
  });

  it('renders "No findings" when totals are zero and hideZeros is set', () => {
    render(<SeverityPills critical={0} high={0} medium={0} low={0} hideZeros />);
    expect(screen.getByText('No findings')).toBeTruthy();
  });

  it('treats omitted counts as zero', () => {
    const { container } = render(<SeverityPills hideZeros />);
    expect(screen.getByText('No findings')).toBeTruthy();
    expect(container.querySelectorAll('span.rounded-full').length).toBe(0);
  });
});
