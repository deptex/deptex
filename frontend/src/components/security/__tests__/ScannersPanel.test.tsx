/**
 * ScannersPanel — base-image recommendations loading / error / empty states.
 *
 * Phase 2 close-out: the recommendations fetch now has three visually
 * distinct states (skeleton, error+retry, empty=section-absent). Empty must
 * not look like a failure; a failure must not look like an empty result.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/utils';
import ScannersPanel from '../ScannersPanel';
import { api } from '../../../lib/api';

vi.mock('../../../lib/api', () => ({
  api: {
    getProjectScannerSummary: vi.fn(),
    getBaseImageRecommendations: vi.fn(),
  },
  frameworkLabel: (s: string) => s,
}));

const summaryFixture = {
  infra_types: [],
  iac: { critical: 0, high: 0, medium: 0, low: 0, ignored: 0 },
  container: { critical: 0, high: 0, medium: 0, low: 0, ignored: 0 },
  container_reachability: { module: 0, unreachable: 0, unclassified: 0 },
  last_scan_at: null,
};

const recFixture = {
  id: 'rec-1',
  dockerfile_path: 'Dockerfile',
  current_image: 'node:20-bullseye',
  current_image_digest: 'sha256:abc',
  current_image_cve_count: 40,
  recommended_image: 'cgr.dev/chainguard/node:20',
  recommended_image_cve_count: 0,
  cve_delta: 40,
  alternatives: [],
  shell_compat_verdict: 'no_shell_required' as const,
  shell_compat_evidence: { likely_safe: true },
  drop_in_score: 85,
  is_dismissed: false,
  created_at: '2026-05-18',
};

beforeEach(() => {
  vi.clearAllMocks();
  // Stable summary; tests only vary the recommendations fetch.
  (api.getProjectScannerSummary as any).mockResolvedValue(summaryFixture);
});

function renderPanel() {
  return render(
    <ScannersPanel
      organizationId="org-1"
      projectId="proj-1"
      canManage={true}
    />
  );
}

describe('ScannersPanel — recommendations state machine', () => {
  it('shows a loading skeleton while recommendations are pending', async () => {
    // Pending — never resolves during this test.
    (api.getBaseImageRecommendations as any).mockImplementation(
      () => new Promise(() => { /* never resolves */ })
    );

    renderPanel();

    const skeleton = await screen.findByLabelText('Loading base-image recommendations');
    expect(skeleton).toBeInTheDocument();
    expect(skeleton.getAttribute('aria-busy')).toBe('true');
  });

  it('shows an error message + Retry button when the fetch rejects, distinct from the empty state', async () => {
    (api.getBaseImageRecommendations as any).mockRejectedValueOnce(
      new Error('Network error fetching recommendations')
    );

    renderPanel();

    expect(
      await screen.findByText('Network error fetching recommendations')
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    // Section header is visible — error state shares the panel chrome, unlike
    // the empty state which omits the section entirely.
    expect(screen.getByText('Base-image recommendations')).toBeInTheDocument();
  });

  it('Retry re-issues the fetch — second call wins, error clears, cards render', async () => {
    const getRecs = api.getBaseImageRecommendations as any;
    getRecs
      .mockRejectedValueOnce(new Error('flaky network'))
      .mockResolvedValueOnce({ recommendations: [recFixture] });

    renderPanel();

    const retry = await screen.findByRole('button', { name: /retry/i });
    fireEvent.click(retry);

    await waitFor(() => {
      expect(screen.getByText('node:20-bullseye')).toBeInTheDocument();
    });
    expect(getRecs).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('flaky network')).not.toBeInTheDocument();
  });

  it('omits the recommendations section entirely on the empty result', async () => {
    (api.getBaseImageRecommendations as any).mockResolvedValueOnce({ recommendations: [] });

    renderPanel();

    // Wait for the summary card so we know the panel is mounted and the
    // recommendations fetch has settled.
    await screen.findByText('IaC + Container Scanners');
    await waitFor(() => {
      expect(
        screen.queryByLabelText('Loading base-image recommendations')
      ).not.toBeInTheDocument();
    });

    expect(screen.queryByText('Base-image recommendations')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
  });

  it('renders the recommendation cards on a successful non-empty fetch', async () => {
    (api.getBaseImageRecommendations as any).mockResolvedValueOnce({
      recommendations: [recFixture],
    });

    renderPanel();

    expect(await screen.findByText('node:20-bullseye')).toBeInTheDocument();
    expect(screen.getByText('cgr.dev/chainguard/node:20')).toBeInTheDocument();
    expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
  });
});
