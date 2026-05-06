/**
 * Phase 6.5 hardening — EntryPointBadge STATUS_HINT exhaustiveness.
 *
 * The Phase 6.5 backend can return any of the EpdStatus values listed in
 * `lib/api.ts` — including 4 new gated-Anthropic-fallback states. If a
 * frontend regression drops one of those keys from the STATUS_HINT lookup,
 * the badge will silently render a confusing tooltip ("undefined") instead
 * of a real explanation. This test pins exhaustiveness by rendering every
 * status with a known classification and asserting the rendered tooltip
 * text is non-empty for each.
 */
import { describe, it, expect } from 'vitest';
import { render, screen } from '../../../test/utils';
import { EntryPointBadge } from '../EntryPointBadge';
import type { EpdStatus } from '../../../lib/api';

const ALL_STATUSES: EpdStatus[] = [
  'ai_verified',
  'byok_missing',
  'fallback_no_ai',
  'ai_error_fallback',
  'budget_exceeded',
  'pending',
  'flow_aggregated',
  'no_flows_evaluated',
  'all_flows_suppressed',
  'ai_truncated',
  'ai_verified_anthropic_fallback',
  'ai_verified_anthropic_fallback_failed',
  'ai_verified_anthropic_fallback_skipped_cost_cap',
  'ai_verified_anthropic_fallback_skipped_burn_breaker',
];

describe('EntryPointBadge', () => {
  it('returns null when classification is null', () => {
    const { container } = render(
      <EntryPointBadge classification={null} status="ai_verified" />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('returns null when classification is UNKNOWN', () => {
    const { container } = render(
      <EntryPointBadge classification="UNKNOWN" status="ai_verified" />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders "Public" label for PUBLIC_UNAUTH', () => {
    render(<EntryPointBadge classification="PUBLIC_UNAUTH" status="ai_verified" />);
    expect(screen.getByText('Public')).toBeInTheDocument();
  });

  it.each(ALL_STATUSES)('produces a non-empty aria-label for status=%s', (status) => {
    const { getByRole } = render(
      <EntryPointBadge classification="PUBLIC_UNAUTH" status={status} />,
    );
    const button = getByRole('button');
    const ariaLabel = button.getAttribute('aria-label');
    expect(ariaLabel).toBeTruthy();
    // STATUS_HINT must produce more than just the bare classification label.
    // If a key were missing, ariaLabel would just be "Entry point: Public.".
    expect(ariaLabel!.length).toBeGreaterThan('Entry point: Public.'.length + 5);
    // And the hint text MUST NOT contain literal 'undefined' (which is what
    // missing-key lookups render as when forced into a template string).
    expect(ariaLabel).not.toMatch(/undefined/);
  });
});
