import { describe, it, expect } from 'vitest';
import { render, screen } from '../../test/utils';
import { RoleBadge } from '../RoleBadge';

describe('RoleBadge', () => {
  it('renders the roleDisplayName when supplied', () => {
    render(<RoleBadge role="contributor" roleDisplayName="Lead Engineer" />);
    expect(screen.getByText('Lead Engineer')).toBeInTheDocument();
  });

  it('falls back to a capitalised role name when no displayName is set', () => {
    render(<RoleBadge role="contributor" />);
    expect(screen.getByText('Contributor')).toBeInTheDocument();
  });

  it('renders "Owner" capitalised for the owner role with no displayName', () => {
    render(<RoleBadge role="owner" />);
    expect(screen.getByText('Owner')).toBeInTheDocument();
  });

  it('applies an rgba background, color, and border from a 6-char hex color', () => {
    render(<RoleBadge role="admin" roleColor="#3b82f6" />);
    const span = screen.getByText('Admin');
    expect(span).toHaveStyle({
      backgroundColor: 'rgba(59, 130, 246, 0.1)',
      color: '#3b82f6',
      borderColor: 'rgba(59, 130, 246, 0.2)',
    });
  });

  it('expands a 3-char hex color correctly when computing rgba', () => {
    render(<RoleBadge role="admin" roleColor="#f00" />);
    const span = screen.getByText('Admin');
    expect(span).toHaveStyle({
      backgroundColor: 'rgba(255, 0, 0, 0.1)',
      color: '#f00',
      borderColor: 'rgba(255, 0, 0, 0.2)',
    });
  });

  it('uses the neutral foreground palette when no color is provided', () => {
    render(<RoleBadge role="member" />);
    const span = screen.getByText('Member');
    // No inline style overrides should be set in the no-color path.
    expect(span.getAttribute('style') ?? '').not.toMatch(/background-color/);
    expect(span.className).toMatch(/bg-foreground\/5/);
    expect(span.className).toMatch(/text-foreground-secondary/);
  });

  it('treats an empty-string color as no color', () => {
    render(<RoleBadge role="member" roleColor="" />);
    const span = screen.getByText('Member');
    expect(span.className).toMatch(/bg-foreground\/5/);
  });

  it('passes through additional className tokens', () => {
    render(<RoleBadge role="member" className="ml-4" />);
    const span = screen.getByText('Member');
    expect(span.className).toMatch(/ml-4/);
  });
});
