import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/utils';
import BaseImageRecommendationCard from '../BaseImageRecommendationCard';
import type { BaseImageRecommendation } from '../../../lib/api';
import { api } from '../../../lib/api';

vi.mock('../../../lib/api', () => ({
  api: {
    dismissBaseImageRecommendation: vi.fn(),
    suggestBaseImage: vi.fn(),
  },
}));

function makeRec(overrides: Partial<BaseImageRecommendation> = {}): BaseImageRecommendation {
  return {
    id: 'rec-1',
    dockerfile_path: 'Dockerfile',
    current_image: 'node:20-bullseye',
    current_image_digest: 'sha256:abc',
    current_image_cve_count: 40,
    recommended_image: 'cgr.dev/chainguard/node:20',
    recommended_image_cve_count: 0,
    cve_delta: 40,
    alternatives: [
      { image: 'gcr.io/distroless/nodejs20-debian12', provider: 'distroless', cve_count: 2, drop_in_score: 80 },
    ],
    shell_compat_verdict: 'no_shell_required',
    shell_compat_evidence: { likely_safe: true },
    drop_in_score: 85,
    is_dismissed: false,
    created_at: '2026-05-18',
    ...overrides,
  };
}

function renderCard(rec: BaseImageRecommendation, canManage = true, onDismissed = vi.fn()) {
  return render(
    <BaseImageRecommendationCard
      organizationId="org-1"
      projectId="proj-1"
      recommendation={rec}
      canManage={canManage}
      onDismissed={onDismissed}
    />
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('BaseImageRecommendationCard — real recommendation', () => {
  it('renders the current and recommended images', () => {
    renderCard(makeRec());
    expect(screen.getByText('node:20-bullseye')).toBeInTheDocument();
    expect(screen.getByText('cgr.dev/chainguard/node:20')).toBeInTheDocument();
  });

  it('shows the dockerfile path', () => {
    renderCard(makeRec({ dockerfile_path: 'services/api/Dockerfile' }));
    expect(screen.getByText('services/api/Dockerfile')).toBeInTheDocument();
  });

  it('shows a positive CVE delta badge', () => {
    renderCard(makeRec({ cve_delta: 40 }));
    expect(screen.getByText('−40 CVEs')).toBeInTheDocument();
  });

  it('shows "No CVE reduction" when the delta is not positive', () => {
    renderCard(makeRec({ cve_delta: 0 }));
    expect(screen.getByText('No CVE reduction')).toBeInTheDocument();
  });

  it('shows the likely-safe verdict when evidence says so', () => {
    renderCard(makeRec({ shell_compat_verdict: 'no_shell_required', shell_compat_evidence: { likely_safe: true } }));
    expect(screen.getByText('Likely safe drop-in')).toBeInTheDocument();
  });

  it('shows the needs-a-shell verdict for a shell-required Dockerfile', () => {
    renderCard(
      makeRec({ shell_compat_verdict: 'shell_required', shell_compat_evidence: { likely_safe: false } })
    );
    expect(screen.getByText('Needs a shell — verify')).toBeInTheDocument();
  });

  it('shows the unknown verdict when compatibility could not be determined', () => {
    renderCard(makeRec({ shell_compat_verdict: 'unknown', shell_compat_evidence: {} }));
    expect(screen.getByText('Compatibility unknown')).toBeInTheDocument();
  });

  it('toggles the alternatives list', () => {
    renderCard(makeRec());
    expect(screen.queryByText('gcr.io/distroless/nodejs20-debian12')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText(/See 1 other option/i));
    expect(screen.getByText('gcr.io/distroless/nodejs20-debian12')).toBeInTheDocument();
  });

  it('dismisses the recommendation and notifies the parent', async () => {
    (api.dismissBaseImageRecommendation as any).mockResolvedValue({ ok: true });
    const onDismissed = vi.fn();
    renderCard(makeRec(), true, onDismissed);
    fireEvent.click(screen.getByRole('button', { name: /Dismiss/i }));
    await waitFor(() => expect(onDismissed).toHaveBeenCalledWith('rec-1'));
    expect(api.dismissBaseImageRecommendation).toHaveBeenCalledWith('org-1', 'proj-1', 'rec-1');
  });

  it('surfaces a dismiss failure without notifying the parent', async () => {
    (api.dismissBaseImageRecommendation as any).mockRejectedValue(new Error('nope'));
    const onDismissed = vi.fn();
    renderCard(makeRec(), true, onDismissed);
    fireEvent.click(screen.getByRole('button', { name: /Dismiss/i }));
    await waitFor(() =>
      expect(screen.getByText(/Could not dismiss/i)).toBeInTheDocument()
    );
    expect(onDismissed).not.toHaveBeenCalled();
  });

  it('hides the Dismiss button when the caller cannot manage', () => {
    renderCard(makeRec(), false);
    expect(screen.queryByRole('button', { name: /Dismiss/i })).not.toBeInTheDocument();
  });
});

describe('BaseImageRecommendationCard — empty state', () => {
  function emptyRec(): BaseImageRecommendation {
    return makeRec({
      recommended_image: null,
      recommended_image_cve_count: null,
      cve_delta: null,
      alternatives: [],
      current_image: 'acme/internal:1.0',
    });
  }

  it('renders the no-alternative message', () => {
    renderCard(emptyRec());
    expect(screen.getByText(/No hardened alternative/i)).toBeInTheDocument();
    expect(screen.getByText('acme/internal:1.0')).toBeInTheDocument();
  });

  it('logs a suggestion and confirms it was sent', async () => {
    (api.suggestBaseImage as any).mockResolvedValue({ ok: true });
    renderCard(emptyRec());
    fireEvent.click(screen.getByRole('button', { name: /Suggest this image family/i }));
    await waitFor(() => expect(screen.getByText('Suggestion sent')).toBeInTheDocument());
    expect(api.suggestBaseImage).toHaveBeenCalledWith('org-1', 'proj-1', 'acme/internal:1.0');
  });

  it('hides the suggest CTA when the caller cannot manage', () => {
    renderCard(emptyRec(), false);
    expect(
      screen.queryByRole('button', { name: /Suggest this image family/i })
    ).not.toBeInTheDocument();
  });
});

describe('BaseImageRecommendationCard — snapshots', () => {
  it('matches the real-recommendation snapshot', () => {
    const { container } = renderCard(makeRec());
    expect(container).toMatchSnapshot();
  });

  it('matches the shell-required snapshot', () => {
    const { container } = renderCard(
      makeRec({ shell_compat_verdict: 'shell_required', shell_compat_evidence: { likely_safe: false } })
    );
    expect(container).toMatchSnapshot();
  });

  it('matches the empty-state snapshot', () => {
    const { container } = renderCard(
      makeRec({ recommended_image: null, cve_delta: null, alternatives: [] })
    );
    expect(container).toMatchSnapshot();
  });
});
