import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import AISpendingSection from '../AISpendingSection';
import type {
  AIUsageSummary,
  AegisToolBreakdownResponse,
  DailyUsageResponse,
} from '../../../lib/api';

const mockGetAIUsage = vi.fn();
const mockGetAIUsageDaily = vi.fn();
const mockGetAegisToolBreakdown = vi.fn();

vi.mock('../../../lib/api', () => ({
  api: {
    getAIUsage: (...args: unknown[]) => mockGetAIUsage(...args),
    getAIUsageDaily: (...args: unknown[]) => mockGetAIUsageDaily(...args),
    getAegisToolBreakdown: (...args: unknown[]) => mockGetAegisToolBreakdown(...args),
  },
}));

// Recharts ResponsiveContainer needs ResizeObserver — passthrough children directly.
vi.mock('recharts', async (importOriginal) => {
  const mod = await importOriginal<typeof import('recharts')>();
  return {
    ...mod,
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
      <div style={{ width: 800, height: 400 }}>{children}</div>
    ),
  };
});

const summary: AIUsageSummary = {
  totalInputTokens: 200_000,
  totalOutputTokens: 50_000,
  totalEstimatedCost: 4.25,
  monthlyCostCap: 50,
  byFeature: {
    'aegis.chat': { tokens: 180_000, cost: 3.5, count: 42 },
    'docs.assistant': { tokens: 70_000, cost: 0.75, count: 11 },
  },
  byUser: [],
};

const daily: DailyUsageResponse = {
  days: 30,
  points: [
    { date: '2026-05-01', tokens: 1000, cost_cents: 25 },
    { date: '2026-05-02', tokens: 2000, cost_cents: 50 },
  ],
};

const tools: AegisToolBreakdownResponse = {
  days: 30,
  limit: 10,
  tools: [
    { tool_name: 'read_file', executions: 120, total_tokens: 15000, total_cost_cents: 30 },
    { tool_name: 'list_findings', executions: 80, total_tokens: 9000, total_cost_cents: 18 },
  ],
};

describe('AISpendingSection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetAIUsage.mockResolvedValue(summary);
    mockGetAIUsageDaily.mockResolvedValue(daily);
    mockGetAegisToolBreakdown.mockResolvedValue(tools);
  });

  it('renders nothing when canViewSpending is false', () => {
    const { container } = render(
      <AISpendingSection organizationId="org-1" canViewSpending={false} />,
    );
    expect(container.firstChild).toBeNull();
    expect(mockGetAIUsage).not.toHaveBeenCalled();
  });

  it('renders the spending section with headline stats', async () => {
    render(<AISpendingSection organizationId="org-1" canViewSpending={true} />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'AI spending' })).toBeInTheDocument();
    });
    const section = screen.getByTestId('ai-spending-section');
    // Headline stat labels are uppercased — getAllByText handles the duplicate with By-feature header.
    expect(within(section).getByText('Estimated cost')).toBeInTheDocument();
    expect(within(section).getByText('Monthly cap')).toBeInTheDocument();
  });

  it('renders the By feature table with friendly labels', async () => {
    render(<AISpendingSection organizationId="org-1" canViewSpending={true} />);
    const byFeatureHeader = await screen.findByRole('heading', { name: 'By feature' });
    const byFeatureSection = byFeatureHeader.closest('div')?.parentElement as HTMLElement;
    await waitFor(() => {
      expect(within(byFeatureSection).getByText('Aegis Chat')).toBeInTheDocument();
    });
    expect(within(byFeatureSection).getByText('Docs Assistant')).toBeInTheDocument();
    expect(screen.queryByText('aegis.chat')).not.toBeInTheDocument();
  });

  it('changing the timeframe to 7 days re-fetches with the new window', async () => {
    render(<AISpendingSection organizationId="org-1" canViewSpending={true} />);
    await waitFor(() => {
      expect(mockGetAIUsage).toHaveBeenCalledWith('org-1', '30d');
    });
    await userEvent.click(screen.getByRole('button', { name: /Last 30 days/i }));
    await userEvent.click(await screen.findByRole('menuitem', { name: /Last 7 days/i }));
    await waitFor(() => {
      expect(mockGetAIUsage).toHaveBeenCalledWith('org-1', '7d');
      expect(mockGetAIUsageDaily).toHaveBeenCalledWith('org-1', 7);
      expect(mockGetAegisToolBreakdown).toHaveBeenCalledWith('org-1', 7, 10);
    });
  });
});
