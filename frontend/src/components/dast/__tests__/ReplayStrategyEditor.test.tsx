// Phase 36 (v1.1) — smoke + state-machine tests for ReplayStrategyEditor.
// Pins the load-bearing UX paths the plan calls out (M4 step 7):
//   - renders the upload dropzone in the empty state
//   - rejects non-.har files client-side (no api call)
//   - rejects > 1.5MB files client-side (no api call)
//   - parses a synthetic HAR via api.parseDastHar and renders the summary
//   - Test-replay button is disabled until payload is complete
//   - Test-replay calls api.postDastLoginTest with (projectId, targetId)
//   - 409 concurrency error surfaces the Cancel-running-scan affordance
//
// useJobResult is faked out by stubbing api.getDastJobs so the polling
// hook doesn't try to reach a real backend during tests.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/utils';

import { ReplayStrategyEditor } from '../ReplayStrategyEditor';
import { api } from '../../../lib/api';

const PROJECT_A = 'aaaa1111-1111-1111-1111-111111111111';
const TARGET_A = 'bbbb2222-2222-2222-2222-222222222222';
const TEST_JOB_ID = 'cccc3333-3333-3333-3333-333333333333';

function syntheticHar(): unknown {
  return {
    log: {
      entries: [
        {
          request: {
            method: 'POST',
            url: 'https://app.example.com/login',
            headers: [
              { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
            ],
            postData: {
              mimeType: 'application/x-www-form-urlencoded',
              text: 'username=alice&password=wonderland',
            },
          },
          response: { status: 302, headers: [{ name: 'Set-Cookie', value: 'session=abc' }] },
        },
      ],
    },
  };
}

function previewResponse() {
  return {
    requests: [
      {
        index: 0,
        method: 'POST',
        url_scrubbed: 'https://app.example.com/login',
        response_status: 302,
        has_auth_header: false,
        has_cookie_header: false,
        has_password_body: true,
        body_size: 32,
        flag_chips: ['password_body' as const, 'set_cookie' as const],
      },
    ],
    summary: {
      request_count: 1,
      origins: ['app.example.com'],
      cookies_set: 1,
      auth_headers_observed: 0,
      dropped_header_count: 0,
      dropped_bytes: 0,
      kept_header_count: 1,
    },
    totp_detected: null,
    non_replayable_warnings: [],
  };
}

function makeFile(content: string, name: string): File {
  const f = new File([content], name, { type: 'application/json' });
  // jsdom's File.text() returns a Promise of the blob bytes via FileReader;
  // some test setups don't have a backing implementation. Patch it so the
  // editor's `await file.text()` resolves deterministically.
  Object.defineProperty(f, 'text', {
    value: async () => content,
    configurable: true,
  });
  Object.defineProperty(f, 'size', {
    value: content.length,
    configurable: true,
  });
  return f;
}

describe('ReplayStrategyEditor', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, 'getDastJobs').mockResolvedValue([]);
  });

  it('renders the upload dropzone in the empty state', () => {
    render(<ReplayStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />);
    expect(screen.getByText(/Drag a/i)).toBeInTheDocument();
    expect(screen.getByText(/\.har/i)).toBeInTheDocument();
  });

  it('rejects non-.har files without calling the API', async () => {
    const spy = vi.spyOn(api, 'parseDastHar').mockResolvedValue(previewResponse());
    render(<ReplayStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />);
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(input, { target: { files: [makeFile('not har', 'creds.txt')] } });
    await waitFor(() => {
      expect(screen.getByText(/Only \.har files/i)).toBeInTheDocument();
    });
    expect(spy).not.toHaveBeenCalled();
  });

  it('rejects > 1.5MB files without calling the API', async () => {
    const spy = vi.spyOn(api, 'parseDastHar').mockResolvedValue(previewResponse());
    render(<ReplayStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />);
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    const big = makeFile('a'.repeat(2_000_000), 'big.har');
    fireEvent.change(input, { target: { files: [big] } });
    await waitFor(() => {
      expect(screen.getByText(/exceeds the 1\.5 MB cap/i)).toBeInTheDocument();
    });
    expect(spy).not.toHaveBeenCalled();
  });

  it('parses a synthetic HAR and renders the summary', async () => {
    const spy = vi.spyOn(api, 'parseDastHar').mockResolvedValue(previewResponse());
    const onChange = vi.fn();
    render(<ReplayStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={onChange} />);
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(input, {
      target: { files: [makeFile(JSON.stringify(syntheticHar()), 'login.har')] },
    });

    await waitFor(() => {
      expect(spy).toHaveBeenCalledWith(PROJECT_A, TARGET_A, expect.any(Object));
      // Summary header rendered.
      expect(screen.getByText(/requests/i)).toBeInTheDocument();
      expect(screen.getByText(/app\.example\.com/)).toBeInTheDocument();
    });

    // onChange emitted an assembled replay payload.
    await waitFor(() => {
      const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1][0];
      expect(lastCall).not.toBeNull();
      expect(lastCall.kind).toBe('replay');
      expect(lastCall.requests.length).toBe(1);
      expect(lastCall.origins_observed).toEqual(['app.example.com']);
    });
  });

  it('Test replay button is disabled before a HAR is parsed', () => {
    render(<ReplayStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />);
    // Pre-parse: the button isn't even rendered yet (the preview card renders it).
    expect(screen.queryByRole('button', { name: /Test replay/i })).toBeNull();
  });

  it('Test replay button calls api.postDastLoginTest after parsing', async () => {
    vi.spyOn(api, 'parseDastHar').mockResolvedValue(previewResponse());
    const postSpy = vi.spyOn(api, 'postDastLoginTest').mockResolvedValue({
      test_job_id: TEST_JOB_ID,
      status: 'queued',
    });
    render(<ReplayStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />);

    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(input, {
      target: { files: [makeFile(JSON.stringify(syntheticHar()), 'login.har')] },
    });

    const btn = await waitFor(() => {
      const b = screen.getByRole('button', { name: /Test replay/i });
      expect(b).not.toBeDisabled();
      return b;
    });
    fireEvent.click(btn);

    await waitFor(() => {
      expect(postSpy).toHaveBeenCalledWith(PROJECT_A, TARGET_A);
    });
  });

  it('surfaces a 409 project_concurrent_dast_blocked with the Cancel affordance copy', async () => {
    vi.spyOn(api, 'parseDastHar').mockResolvedValue(previewResponse());
    vi.spyOn(api, 'postDastLoginTest').mockRejectedValue(
      new Error('project_concurrent_dast_blocked: target busy'),
    );
    render(<ReplayStrategyEditor projectId={PROJECT_A} targetId={TARGET_A} onChange={() => {}} />);

    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(input, {
      target: { files: [makeFile(JSON.stringify(syntheticHar()), 'login.har')] },
    });

    const btn = await waitFor(() => {
      const b = screen.getByRole('button', { name: /Test replay/i });
      expect(b).not.toBeDisabled();
      return b;
    });
    fireEvent.click(btn);

    await waitFor(() => {
      expect(screen.getByText(/A scan is running on this target/i)).toBeInTheDocument();
    });
  });
});
