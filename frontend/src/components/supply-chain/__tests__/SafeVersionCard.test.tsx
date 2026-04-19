import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/utils';
import { SafeVersionCard } from '../SafeVersionCard';
import type { LatestSafeVersionResponse } from '../../../lib/api';

const baseSeverityChange = vi.fn();
const baseSimulate = vi.fn();
const baseBumpAll = vi.fn();

function renderCard(overrides: Record<string, any> = {}) {
  const defaultProps = {
    data: null as LatestSafeVersionResponse | null,
    loading: false,
    severity: 'high',
    onSeverityChange: baseSeverityChange,
    onSimulate: baseSimulate,
    ...overrides,
  };
  return render(<SafeVersionCard {...defaultProps} />);
}

describe('SafeVersionCard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ----- Loading / Empty -----

  it('renders skeleton when loading with no data', () => {
    const { container } = renderCard({ loading: true, data: null });
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument();
  });

  it('renders nothing when not loading and no data', () => {
    const { container } = renderCard({ loading: false, data: null });
    expect(container.firstChild).toBeNull();
  });

  // ----- State: Already on the safest version -----

  it('shows "Recommended" and version with green check when isCurrent is true', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: '2.0.1',
      safeVersionId: 'sv-1',
      isCurrent: true,
      severity: 'high',
      versionsChecked: 5,
      message: 'Current version is the latest safe version',
    };
    const { container } = renderCard({ data });
    expect(screen.getByText('Recommended')).toBeInTheDocument();
    expect(screen.getByText('2.0.1')).toBeInTheDocument();
    expect(screen.queryByText("You're on the safest version")).not.toBeInTheDocument();
    expect(container.querySelector('.text-success')).toBeInTheDocument();
  });

  it('does not show bump button when already on latest safe version (isCurrent)', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: '2.0.1',
      safeVersionId: 'sv-1',
      isCurrent: true,
      severity: 'high',
      versionsChecked: 5,
      message: null,
    };
    renderCard({ data, onBumpAll: baseBumpAll, bumpScope: 'org' });
    expect(screen.queryByText('Bump all projects')).not.toBeInTheDocument();
    expect(screen.queryByText('Bump this project')).not.toBeInTheDocument();
  });

  // ----- State: Found a different safe version -----

  it('shows simulate button when safe version is different from current', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: '3.0.0',
      safeVersionId: 'sv-2',
      isCurrent: false,
      severity: 'high',
      versionsChecked: 10,
      message: null,
    };
    renderCard({ data });
    expect(screen.getByText('Preview')).toBeInTheDocument();
  });

  it('does not show bump button when safe version exists but not viewing simulated version', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: '3.0.0',
      safeVersionId: 'sv-2',
      isCurrent: false,
      severity: 'high',
      versionsChecked: 10,
      message: null,
    };
    renderCard({ data, onBumpAll: baseBumpAll, bumpScope: 'org', isViewingSimulatedSafeVersion: false });
    expect(screen.getByText('Preview')).toBeInTheDocument();
    expect(screen.queryByText('Bump all projects')).not.toBeInTheDocument();
  });

  it('shows only bump button when viewing simulated safe version (not Simulate)', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: '3.0.0',
      safeVersionId: 'sv-2',
      isCurrent: false,
      severity: 'high',
      versionsChecked: 10,
      message: null,
    };
    renderCard({ data, onBumpAll: baseBumpAll, bumpScope: 'org', isViewingSimulatedSafeVersion: true });
    expect(screen.getByText('Bump all projects')).toBeInTheDocument();
    expect(screen.queryByText('Preview')).not.toBeInTheDocument();
  });

  it('calls onSimulate when simulate button is clicked', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: '3.0.0',
      safeVersionId: 'sv-2',
      isCurrent: false,
      severity: 'high',
      versionsChecked: 10,
      message: null,
    };
    renderCard({ data });
    fireEvent.click(screen.getByText('Preview'));
    expect(baseSimulate).toHaveBeenCalledWith('sv-2');
  });

  // ----- State: No safe version found -----

  it('shows "No safe version found" when safeVersion is null', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: null,
      safeVersionId: null,
      isCurrent: false,
      severity: 'high',
      versionsChecked: 25,
      message: 'No recent versions meet this criteria',
    };
    renderCard({ data });
    expect(screen.getByText('No safe version found')).toBeInTheDocument();
    expect(screen.getByText('No recent versions meet this criteria')).toBeInTheDocument();
  });

  it('shows default message when no safe version and no message', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: null,
      safeVersionId: null,
      isCurrent: false,
      severity: 'high',
      versionsChecked: 25,
      message: null,
    };
    renderCard({ data });
    expect(screen.getByText('No version meets the severity threshold.')).toBeInTheDocument();
  });

  // ----- Loading spinner on bump button -----

  it('shows spinner on bump button when bumpingAll and viewing simulated safe version', () => {
    const data: LatestSafeVersionResponse = {
      safeVersion: '3.0.0',
      safeVersionId: 'sv-2',
      isCurrent: false,
      severity: 'high',
      versionsChecked: 10,
      message: null,
    };
    const { container } = renderCard({
      data,
      onBumpAll: baseBumpAll,
      bumpingAll: true,
      bumpScope: 'org',
      isViewingSimulatedSafeVersion: true,
    });
    expect(screen.getByText('Bump all projects')).toBeInTheDocument();
    expect(container.querySelector('.animate-spin')).toBeInTheDocument();
  });
});
