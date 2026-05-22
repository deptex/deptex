import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import AISection from '../AISection';
import type { AIModelMetadata, AIModelsResponse } from '../../../lib/api';

const mockGetAIModels = vi.fn();
const mockUpdateAIModels = vi.fn();
const mockToast = vi.fn();

vi.mock('../../../lib/api', () => ({
  api: {
    getAIModels: (...args: unknown[]) => mockGetAIModels(...args),
    updateAIModels: (...args: unknown[]) => mockUpdateAIModels(...args),
  },
}));

vi.mock('../../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast, toasts: [] }),
}));

const opus: AIModelMetadata = {
  id: 'claude-opus-4-7',
  provider: 'anthropic',
  label: 'Claude Opus 4.7',
  description: 'Most capable Anthropic model',
  contextWindow: 1_000_000,
  inputPricePer1M: 15,
  outputPricePer1M: 75,
  sweBenchVerified: 72.5,
  releasedAt: '2026-01-10',
};
const sonnet: AIModelMetadata = {
  id: 'claude-sonnet-4-6',
  provider: 'anthropic',
  label: 'Claude Sonnet 4.6',
  description: 'Faster, cheaper Anthropic model',
  contextWindow: 200_000,
  inputPricePer1M: 3,
  outputPricePer1M: 15,
  sweBenchVerified: 60.0,
  releasedAt: '2025-11-01',
};

const modelsResp: AIModelsResponse = {
  models: [opus, sonnet],
  enabledModels: ['claude-opus-4-7', 'claude-sonnet-4-6'],
  defaultModel: 'claude-opus-4-7',
  defaultProvider: 'anthropic',
};

describe('AISection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetAIModels.mockResolvedValue(modelsResp);
    mockUpdateAIModels.mockImplementation(async (_orgId: string, patch: any) => ({ ...modelsResp, ...patch }));
  });

  it('shows the AI Models skeleton while loading, then the real table', async () => {
    let resolve!: (v: AIModelsResponse) => void;
    mockGetAIModels.mockReturnValue(new Promise<AIModelsResponse>((r) => { resolve = r; }));
    render(<AISection organizationId="org-1" canManageSettings={true} />);
    expect(await screen.findByTestId('ai-models-skeleton')).toBeInTheDocument();
    resolve(modelsResp);
    await waitFor(() => {
      expect(screen.queryByTestId('ai-models-skeleton')).not.toBeInTheDocument();
    });
    expect(screen.getByRole('heading', { name: 'AI Models' })).toBeInTheDocument();
  });

  it('renders the AI Models table with provider rows + Default badge', async () => {
    render(<AISection organizationId="org-1" canManageSettings={true} />);
    await waitFor(() => {
      expect(screen.getByText('Claude Opus 4.7')).toBeInTheDocument();
    });
    expect(screen.getByText('Claude Sonnet 4.6')).toBeInTheDocument();
    const opusRow = screen.getByText('Claude Opus 4.7').closest('tr') as HTMLElement;
    expect(within(opusRow).getByText(/Default/i)).toBeInTheDocument();
  });

  it('toggling a non-default enabled model off calls updateAIModels with the new enabled list', async () => {
    render(<AISection organizationId="org-1" canManageSettings={true} />);
    await waitFor(() => {
      expect(screen.getByText('Claude Sonnet 4.6')).toBeInTheDocument();
    });
    const sonnetRow = screen.getByText('Claude Sonnet 4.6').closest('tr') as HTMLElement;
    const sonnetToggle = within(sonnetRow).getByRole('button', { name: /Enabled/i });
    await userEvent.click(sonnetToggle);
    await waitFor(() => {
      expect(mockUpdateAIModels).toHaveBeenCalledWith('org-1', expect.objectContaining({
        enabledModels: ['claude-opus-4-7'],
      }));
    });
  });

  it('clicking Set as default on a non-default enabled row sets it as default', async () => {
    render(<AISection organizationId="org-1" canManageSettings={true} />);
    await waitFor(() => {
      expect(screen.getByText('Claude Sonnet 4.6')).toBeInTheDocument();
    });
    const sonnetRow = screen.getByText('Claude Sonnet 4.6').closest('tr') as HTMLElement;
    await userEvent.click(within(sonnetRow).getByRole('button', { name: /Set as default/i }));
    await waitFor(() => {
      expect(mockUpdateAIModels).toHaveBeenCalledWith('org-1', expect.objectContaining({
        defaultModel: 'claude-sonnet-4-6',
      }));
    });
  });

  it('rejects toggling off the last enabled model', async () => {
    mockGetAIModels.mockResolvedValue({
      ...modelsResp,
      enabledModels: ['claude-opus-4-7'],
    });
    render(<AISection organizationId="org-1" canManageSettings={true} />);
    await waitFor(() => {
      expect(screen.getByText('Claude Opus 4.7')).toBeInTheDocument();
    });
    const opusRow = screen.getByText('Claude Opus 4.7').closest('tr') as HTMLElement;
    const opusToggle = within(opusRow).getByRole('button', { name: /Enabled/i });
    await userEvent.click(opusToggle);
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
        title: expect.stringMatching(/At least one model must remain enabled/i),
      }));
    });
    expect(mockUpdateAIModels).not.toHaveBeenCalled();
  });

  it('Enabled toggle is disabled when the user lacks manage permission', async () => {
    render(<AISection organizationId="org-1" canManageSettings={false} />);
    await waitFor(() => {
      expect(screen.getByText('Claude Opus 4.7')).toBeInTheDocument();
    });
    const opusRow = screen.getByText('Claude Opus 4.7').closest('tr') as HTMLElement;
    expect(within(opusRow).getByRole('button', { name: /Enabled/i })).toBeDisabled();
  });
});
