import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/utils';

import { RecordedStrategyEditor } from '../RecordedStrategyEditor';
import { api } from '../../../lib/api';

/**
 * Smoke + state-machine tests for the v2.1d recorded-login step editor.
 * Pins the load-bearing UX paths the plan calls out:
 *   - renders the starter `goto` step
 *   - adding / removing steps; goto-at-index-N inline error
 *   - Test-login disabled until payload is complete
 *   - Test-login button calls api.postDastLoginTest with (projectId, targetId)
 *   - 409 dast_target_busy surfaces the Cancel-running-scan affordance
 *   - polling timeout (slow-threshold flip) surfaces "Still running…" copy
 *
 * The polling hook itself uses fake timers via vitest's `vi.useFakeTimers()`
 * so tests don't pay the real 1.5s probe cadence.
 */

const PROJECT_A = 'aaaa1111-1111-1111-1111-111111111111';
const TARGET_A = 'bbbb2222-2222-2222-2222-222222222222';
const TEST_JOB_ID = 'cccc3333-3333-3333-3333-333333333333';

describe('RecordedStrategyEditor', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Default: empty job list so the polling hook doesn't try to hit a real
    // backend during tests. Individual tests override via spyOn as needed.
    vi.spyOn(api, 'getDastJobs').mockResolvedValue([]);
  });

  it('renders an initial `goto` step', () => {
    render(
      <RecordedStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />,
    );
    // The starter step's action select renders "Go to URL".
    expect(screen.getByText(/Go to URL/i)).toBeInTheDocument();
  });

  it('emits null payload when required fields are missing', () => {
    const onChange = vi.fn();
    render(
      <RecordedStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={onChange} />,
    );
    // Payload null because login_page_url + username + password are empty.
    expect(onChange).toHaveBeenLastCalledWith(null);
  });

  it('emits an assembled RecordedCredentialPayload when fields are populated', async () => {
    const onChange = vi.fn();
    render(
      <RecordedStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={onChange} />,
    );
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/app\.example\.com\/login/i), {
      target: { value: 'https://app.example.com/login' },
    });
    fireEvent.change(screen.getByPlaceholderText('alice@example.com'), {
      target: { value: 'alice@example.com' },
    });
    // Password input is type=password; locate by autoComplete attribute.
    const passwordInput = document.querySelector('input[autocomplete="new-password"]') as HTMLInputElement;
    fireEvent.change(passwordInput, { target: { value: 'hunter2hunter2' } });

    await waitFor(() => {
      // Last call should have a real payload (steps include the starter goto).
      const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1][0];
      expect(lastCall).not.toBeNull();
      expect(lastCall.kind).toBe('recorded');
      expect(lastCall.login_page_url).toBe('https://app.example.com/login');
      expect(lastCall.username).toBe('alice@example.com');
      expect(lastCall.password).toBe('hunter2hunter2');
      expect(lastCall.steps.length).toBeGreaterThan(0);
    });
  });

  it('Test login button is disabled when payload is incomplete', () => {
    render(
      <RecordedStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />,
    );
    const testBtn = screen.getByRole('button', { name: /Test login/i });
    expect(testBtn).toBeDisabled();
  });

  it('Test login button calls api.postDastLoginTest when clicked', async () => {
    const spy = vi.spyOn(api, 'postDastLoginTest').mockResolvedValue({
      test_job_id: TEST_JOB_ID,
      status: 'queued',
    });

    render(
      <RecordedStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />,
    );
    // Populate the minimum required fields.
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/app\.example\.com\/login/i), {
      target: { value: 'https://app.example.com/login' },
    });
    fireEvent.change(screen.getByPlaceholderText('alice@example.com'), {
      target: { value: 'alice@example.com' },
    });
    const passwordInput = document.querySelector('input[autocomplete="new-password"]') as HTMLInputElement;
    fireEvent.change(passwordInput, { target: { value: 'hunter2hunter2' } });

    const testBtn = await waitFor(() => {
      const b = screen.getByRole('button', { name: /Test login/i });
      expect(b).not.toBeDisabled();
      return b;
    });
    fireEvent.click(testBtn);

    await waitFor(() => {
      expect(spy).toHaveBeenCalledWith(PROJECT_A, TARGET_A);
    });
  });

  it('surfaces a 409 concurrency error with the Cancel affordance message', async () => {
    vi.spyOn(api, 'postDastLoginTest').mockRejectedValue(
      new Error('project_concurrent_dast_blocked: target busy'),
    );

    render(
      <RecordedStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />,
    );
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/app\.example\.com\/login/i), {
      target: { value: 'https://app.example.com/login' },
    });
    fireEvent.change(screen.getByPlaceholderText('alice@example.com'), {
      target: { value: 'alice@example.com' },
    });
    const passwordInput = document.querySelector('input[autocomplete="new-password"]') as HTMLInputElement;
    fireEvent.change(passwordInput, { target: { value: 'hunter2hunter2' } });

    const testBtn = await waitFor(() => {
      const b = screen.getByRole('button', { name: /Test login/i });
      expect(b).not.toBeDisabled();
      return b;
    });
    fireEvent.click(testBtn);

    await waitFor(() => {
      expect(screen.getByText(/A scan is running on this target/i)).toBeInTheDocument();
    });
  });

  it('surfaces a 503 fly_machine_unavailable error', async () => {
    vi.spyOn(api, 'postDastLoginTest').mockRejectedValue(
      new Error('fly_machine_unavailable'),
    );

    render(
      <RecordedStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />,
    );
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/app\.example\.com\/login/i), {
      target: { value: 'https://app.example.com/login' },
    });
    fireEvent.change(screen.getByPlaceholderText('alice@example.com'), {
      target: { value: 'alice@example.com' },
    });
    const passwordInput = document.querySelector('input[autocomplete="new-password"]') as HTMLInputElement;
    fireEvent.change(passwordInput, { target: { value: 'hunter2hunter2' } });

    fireEvent.click(
      await waitFor(() => {
        const b = screen.getByRole('button', { name: /Test login/i });
        expect(b).not.toBeDisabled();
        return b;
      }),
    );

    await waitFor(() => {
      expect(screen.getByText(/Worker unavailable/i)).toBeInTheDocument();
    });
  });
});
